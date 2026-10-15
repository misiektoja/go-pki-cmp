package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// POPMethod is how a certificate request proves possession of its private key.
type POPMethod int

const (
	// POPSignature covers the direct methods: a signature in popo, a PKCS #10
	// self-signature or, with [WithSignatureProtectionPOP], the message protection.
	POPSignature POPMethod = iota
	// POPEncryptedCertificate is the encrypted certificate method of RFC 9810
	// §5.2.8.3.2, enabled by [WithEncryptedCertificatePOP]. Possession is only
	// proven once a certConf with the hash of the certificate arrives.
	POPEncryptedCertificate
	// POPChallengeResponse is the challenge-response method of RFC 9810
	// §5.2.8.3.3, enabled by [WithChallengeResponsePOP]. Possession is proven
	// before the request reaches the [Handler].
	POPChallengeResponse
)

// String returns a short name for the method.
func (m POPMethod) String() string {
	switch m {
	case POPSignature:
		return "signature"
	case POPEncryptedCertificate:
		return "encrypted certificate"
	case POPChallengeResponse:
		return "challenge-response"
	default:
		return "unknown"
	}
}

// popMethodKey is the context key that carries the proof-of-possession method of a request.
type popMethodKey struct{}

// contextWithPOPMethod records the proof-of-possession method of the request ctx serves.
func contextWithPOPMethod(ctx context.Context, m POPMethod) context.Context {
	return context.WithValue(ctx, popMethodKey{}, m)
}

// POPMethodFromContext returns how the certificate request behind a call proves
// possession of its private key. The server sets it for [Handler.HandleCMP],
// [CA.IssueCertificate], [PendingChecker.CheckPending] and
// [CertificateConfirmer.ConfirmCertificate]. Without it the result is [POPSignature].
func POPMethodFromContext(ctx context.Context) POPMethod {
	m, _ := ctx.Value(popMethodKey{}).(POPMethod)
	return m
}

// requestPOPMethod returns the proof-of-possession method the certificate request in msg chose.
func requestPOPMethod(msg *pkicmp.PKIMessage) POPMethod {
	if msg.Body.Type == pkicmp.BodyTypeP10CR {
		return POPSignature
	}
	msgs, err := msg.Body.CertReqMessages()
	if err != nil || len(*msgs) == 0 || (*msgs)[0].Popo == nil {
		return POPSignature
	}
	switch v, ok := (*msgs)[0].Popo.SubsequentMessage(); {
	case ok && v == pkicmp.SubsequentMessageEncrCert:
		return POPEncryptedCertificate
	case ok && v == pkicmp.SubsequentMessageChallengeResp:
		return POPChallengeResponse
	default:
		return POPSignature
	}
}

// checkIndirectPOP accepts a keyEncipherment or keyAgreement proof when the
// server allows its subsequentMessage method for the requested key.
//
// Either choice is accepted for every supported key, because the server
// encrypts for the key whichever the client names.
func checkIndirectPOP(ctx context.Context, crmf *parsedCRMF) error {
	cfg := policyConfigFrom(ctx)
	if crmf.subsequentMessage == nil {
		// thisMessage, dhMAC, agreeMAC and encryptedKey are not supported.
		return rejection(pkicmp.FailBadPOP, "proof of possession by signature required")
	}
	switch *crmf.subsequentMessage {
	case pkicmp.SubsequentMessageEncrCert:
		if !cfg.encryptedCertPOP {
			return rejection(pkicmp.FailBadPOP, "encrypted certificate proof of possession is not accepted")
		}
	case pkicmp.SubsequentMessageChallengeResp:
		if !cfg.challengeResponsePOP {
			return rejection(pkicmp.FailBadPOP, "challenge-response proof of possession is not accepted")
		}
	default:
		return rejection(pkicmp.FailBadPOP, "unknown subsequentMessage")
	}
	if !encryptableKey(crmf.publicKey) {
		return rejection(pkicmp.FailBadAlg, "the server cannot encrypt for the requested key")
	}
	// RFC 9483 §4.1.1: an end entity MUST use a signature proof when its key can sign.
	if !pkicmp.IsKEMKey(crmf.publicKey) && !cfg.indirectPOPForSigningKeys {
		return rejection(pkicmp.FailBadPOP, "a key that can sign must prove possession by signature")
	}
	return nil
}

// encryptableKey reports whether the cms package can encrypt for pub.
func encryptableKey(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey, *mlkem.EncapsulationKey768, *mlkem.EncapsulationKey1024:
		return true
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	default:
		return false
	}
}

// encryptCertificate returns cert encrypted for the holder of its private key
// (RFC 9810 §5.2.8.3.2), answering a message of version pvno.
//
// EnvelopedData, with the recipient named by issuer and serial number, is
// cmp2021 syntax and raises the response to pvno 3. A pvno 2 request for an
// RSA key gets the EncryptedValue of CMP version 2 instead, which RFC 9810
// §5.2.2 keeps for backward compatibility, so that a version 2 client can read
// the response, unless envelopedOnly is set. Other keys have no EncryptedValue
// form.
func encryptCertificate(cert *x509.Certificate, pvno int, envelopedOnly bool) (pkicmp.CertOrEncCert, error) {
	pub := certificatePublicKey(cert)
	if pub == nil {
		return pkicmp.CertOrEncCert{}, errors.New("cannot parse the public key of the issued certificate")
	}
	if rsaKey, ok := pub.(*rsa.PublicKey); ok && pvno == pkicmp.PVNO2 && !envelopedOnly {
		value, err := cms.NewEncryptedValue(cert.Raw, rsaKey)
		return pkicmp.NewEncryptedValueCertificate(value), err
	}
	envelope, err := cms.Encrypt(cert.Raw, pub, cms.IssuerAndSerial(cert))
	return pkicmp.NewEncryptedCertificate(envelope), err
}

var (
	// nullDN is an empty Name, the issuer in the recipient identifier of a challenge (RFC 9810 §5.2.8.3.3).
	nullDN = []byte{0x30, 0x00}
	// oidSHA256 is the one-way function that computes the challenge witness.
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// challengeSize is the size in bytes of the random number a challenge encrypts.
const challengeSize = 32

// newChallenge returns a popdecc challenge encrypted for pub and the number the
// client must return, as challengeSize big-endian bytes.
//
// RFC 9810 §5.2.8.3.3 identifies the recipient by a NULL-DN issuer and the
// certReqId as serial number, and Rand names the sender of the popdecc.
func newChallenge(pub crypto.PublicKey, certReqID int64, sender pkicmp.GeneralName) (pkicmp.Challenge, []byte, error) {
	answer := make([]byte, challengeSize)
	rand.Read(answer)
	n := new(big.Int).SetBytes(answer)
	content, err := (&pkicmp.Rand{Int: n, Sender: sender}).MarshalBinary()
	if err != nil {
		return pkicmp.Challenge{}, nil, err
	}
	envelope, err := cms.Encrypt(content, pub, cms.RecipientID{Issuer: nullDN, SerialNumber: big.NewInt(certReqID)})
	if err != nil {
		return pkicmp.Challenge{}, nil, err
	}
	return pkicmp.Challenge{
		OWF:           &pkicmp.AlgorithmIdentifier{Algorithm: oidSHA256},
		Witness:       pkicmp.ChallengeWitness(crypto.SHA256, n),
		EncryptedRand: envelope,
	}, answer, nil
}

// answerMatches reports in constant time whether n is the number whose big-endian bytes are answer.
func answerMatches(n *big.Int, answer []byte) bool {
	if n == nil || n.Sign() < 0 || n.BitLen() > 8*len(answer) {
		return false
	}
	return subtle.ConstantTimeCompare(n.FillBytes(make([]byte, len(answer))), answer) == 1
}

// challengePossession answers a request that chose challenge-response proof of
// possession with a popdecc and keeps the request until the popdecr. The
// handler does not see the request before the client proves possession.
func (s *Server) challengePossession(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, req certRequestInfo) *pkicmp.PKIMessage {
	reject := func(status pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
		return s.buildCertRep(msg, sender, certRep{certReqID: req.certReqID, status: status, reqType: req.reqType})
	}
	if err := enforceProofOfPossession(ctx, msg, sender); err != nil {
		return reject(errorToStatusInfo(err))
	}
	failure := pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure}
	crmf, err := parseCRMFMsg(msg)
	if err != nil {
		return reject(errorToStatusInfo(err))
	}
	der, err := msg.MarshalBinary()
	if err != nil {
		return reject(failure)
	}
	challenge, answer, err := newChallenge(crmf.publicKey, req.certReqID, s.responseSender())
	if err != nil {
		return reject(failure)
	}
	respMsg := s.buildResponse(msg, pkicmp.NewPopDecCBody(&pkicmp.POPODecKeyChallContent{challenge}), sender)
	if !s.setChallenged(credID, msg.Header.TransactionID, challengeState{
		reqType:         req.reqType,
		certReqID:       req.certReqID,
		implicitConfirm: req.implicit,
		request:         der,
		answer:          answer,
		senderNonce:     respMsg.Header.SenderNonce,
	}) {
		return s.buildErrorResponse(msg, sender, failure)
	}
	return respMsg
}

// handlePopDecR checks the answer to a popdecc (RFC 9810 §5.2.8.3.3). A right
// answer continues the challenged request, and the response to the popdecr is
// its ip, cp or kup. A wrong one ends the transaction with badPOP.
func (s *Server) handlePopDecR(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	answers, err := msg.Body.PopDecR()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID
	entry, ok := s.getChallenged(credID, txnID)
	if !ok {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"no pending challenge"},
		})
	}
	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	if len(msg.Header.RecipNonce) == 0 || subtle.ConstantTimeCompare(msg.Header.RecipNonce, entry.senderNonce) != 1 {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce does not match the popdecc"},
		})
	}
	req := certRequestInfo{
		certReqID: *entry.certReqID,
		reqType:   entry.reqType,
		implicit:  entry.implicitConfirm,
		method:    POPChallengeResponse,
	}
	if len(*answers) != 1 || !answerMatches((*answers)[0], entry.challengeAnswer) {
		s.setCompleted(credID, txnID)
		return s.buildCertRep(msg, sender, certRep{
			certReqID: req.certReqID,
			status: pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadPOP,
				StatusString: pkicmp.PKIFreeText{"wrong answer to the proof-of-possession challenge"},
			},
			reqType: req.reqType,
		})
	}
	original, err := pkicmp.ParsePKIMessage(entry.challengeRequest)
	if err != nil {
		s.setCompleted(credID, txnID)
		return s.buildCertRep(msg, sender, certRep{
			certReqID: req.certReqID,
			status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure},
			reqType:   req.reqType,
		})
	}
	return s.issue(contextWithPOPMethod(ctx, POPChallengeResponse), original, msg, sender, credID, req)
}
