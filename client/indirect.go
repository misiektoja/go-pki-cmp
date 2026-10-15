package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// IndirectPOP selects how a key that cannot sign proves possession of its
// private key (RFC 9810 §5.2.8.3).
type IndirectPOP int

const (
	// EncryptedCertificate asks the CA to return the certificate encrypted for
	// the requested key. The client decrypts it and confirms its hash in
	// certConf, which is the proof. The CA revokes the certificate when that
	// confirmation does not arrive.
	EncryptedCertificate IndirectPOP = iota + 1
	// ChallengeResponse asks the CA for a popdecc challenge encrypted for the
	// requested key. The client answers with the decrypted number in popdecr
	// before the CA issues the certificate.
	ChallengeResponse
)

// String returns the RFC 9810 name of the method.
func (p IndirectPOP) String() string {
	switch p {
	case EncryptedCertificate:
		return "encrCert"
	case ChallengeResponse:
		return "challengeResp"
	default:
		return fmt.Sprintf("IndirectPOP(%d)", int(p))
	}
}

// subsequentMessage returns the popoPrivKey subsequentMessage value of the method.
func (p IndirectPOP) subsequentMessage() (int64, error) {
	switch p {
	case EncryptedCertificate:
		return pkicmp.SubsequentMessageEncrCert, nil
	case ChallengeResponse:
		return pkicmp.SubsequentMessageChallengeResp, nil
	default:
		return 0, fmt.Errorf("unknown indirect proof of possession %d", int(p))
	}
}

// decryptionProof is the private key that answers an indirect proof of possession.
type decryptionProof struct {
	key    any
	method IndirectPOP
}

// SendIRWithIndirectPOP performs an Initialization Request (RFC 9810 §5.3.1)
// for a key that cannot sign, which proves possession by decryption with
// method. See [Client.SendCRWithIndirectPOP] for the accepted keys.
func (c *Client) SendIRWithIndirectPOP(ctx context.Context, key any, method IndirectPOP, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendIndirectCRMF(ctx, key, method, creds, pkicmp.BodyTypeIP, opts)
}

// SendCRWithIndirectPOP performs a Certification Request (RFC 9810 §5.3.3) for
// a key that cannot sign, which proves possession by decryption with method.
//
// key is the private key of the requested certificate:
//
//   - an ML-KEM-768 or ML-KEM-1024 key, as *mlkem.DecapsulationKey768,
//     *mlkem.DecapsulationKey1024 or another crypto.Decapsulator for them,
//   - an RSA key, as *rsa.PrivateKey or another crypto.Decrypter that
//     implements RSA-OAEP,
//   - an elliptic curve key on P-256, P-384 or P-521, as *ecdsa.PrivateKey,
//     *ecdh.PrivateKey or another ecdh.KeyExchanger, requested with the
//     keyAgreement proof.
//
// The CA must support the method. RFC 9483 §4.1.1 lets a CA refuse it for a
// key that can sign, such as RSA or an elliptic curve key.
func (c *Client) SendCRWithIndirectPOP(ctx context.Context, key any, method IndirectPOP, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendIndirectCRMF(ctx, key, method, creds, pkicmp.BodyTypeCP, opts)
}

// SendKURWithIndirectPOP performs a Key Update Request (RFC 9810 §5.3.5) for a
// new key that cannot sign, which proves possession by decryption with method.
// See [Client.SendCRWithIndirectPOP] for the accepted keys.
func (c *Client) SendKURWithIndirectPOP(ctx context.Context, newKey any, method IndirectPOP, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendIndirectCRMF(ctx, newKey, method, creds, pkicmp.BodyTypeKUP, opts)
}

// sendIndirectCRMF requests a certificate for key with a keyEncipherment or keyAgreement proof of possession.
func (c *Client) sendIndirectCRMF(ctx context.Context, key any, method IndirectPOP, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	subsequent, err := method.subsequentMessage()
	if err != nil {
		return nil, &Error{Op: "indirect proof of possession", Err: err}
	}
	pub, agreement, err := decryptionPublicKey(key)
	if err != nil {
		return nil, &Error{Op: "indirect proof of possession", Err: err}
	}
	pop := func(m *pkicmp.CertReqMsg) error {
		if agreement {
			m.Popo = pkicmp.NewKeyAgreementPOP(&subsequent)
		} else {
			m.Popo = pkicmp.NewKeyEnciphermentPOP(&subsequent)
		}
		return nil
	}
	return c.sendCertRequest(ctx, pub, pop, &decryptionProof{key: key, method: method}, creds, expectedRepType, opts)
}

// decryptionPublicKey returns the public key of a private key that the cms
// package can decrypt with, in the form pkicmp.ParsePublicKey returns, and
// whether it proves possession by key agreement.
func decryptionPublicKey(key any) (crypto.PublicKey, bool, error) {
	var pub crypto.PublicKey
	agreement := false
	switch k := key.(type) {
	case *mlkem.DecapsulationKey768:
		pub = k.EncapsulationKey()
	case *mlkem.DecapsulationKey1024:
		pub = k.EncapsulationKey()
	case crypto.Decapsulator:
		pub = k.Encapsulator()
	case *ecdsa.PrivateKey:
		pub, agreement = &k.PublicKey, true
	case ecdh.KeyExchanger:
		pub, agreement = k.PublicKey(), true
	case crypto.Decrypter:
		if _, ok := k.Public().(*rsa.PublicKey); !ok {
			return nil, false, fmt.Errorf("a crypto.Decrypter must hold an RSA key, not %T", k.Public())
		}
		pub = k.Public()
	default:
		return nil, false, fmt.Errorf("unsupported key type %T", key)
	}
	der, err := pkicmp.MarshalPublicKey(pub)
	if err != nil {
		return nil, false, err
	}
	parsed, err := pkicmp.ParsePublicKey(der)
	if err != nil {
		return nil, false, err
	}
	switch p := parsed.(type) {
	case *mlkem.EncapsulationKey768, *mlkem.EncapsulationKey1024, *rsa.PublicKey:
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() && p.Curve != elliptic.P384() && p.Curve != elliptic.P521() {
			return nil, false, errors.New("only P-256, P-384 and P-521 keys can prove possession by key agreement")
		}
	default:
		return nil, false, fmt.Errorf("unsupported public key type %T", parsed)
	}
	return parsed, agreement, nil
}

// decryptCertificate returns the certificate of an encrypted certificate response, decrypted with proof.
func decryptCertificate(envelope []byte, proof *decryptionProof) (*x509.Certificate, error) {
	if proof == nil {
		return nil, &Error{Op: "the CA sent an encrypted certificate for a key that signs"}
	}
	der, err := cms.Decrypt(envelope, proof.key)
	if err != nil {
		return nil, &Error{Op: "decrypt certificate", Err: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &Error{Op: "parse decrypted certificate", Err: err}
	}
	return cert, nil
}

// answerChallenge proves possession of proof.key by answering the popdecc
// challenge with a popdecr (RFC 9810 §5.2.8.3.3). It returns the popdecr and
// the verified response to it, which carries the certificate.
func (c *Client) answerChallenge(ctx context.Context, req, challenge *pkicmp.PKIMessage, creds pkicmp.Credentials, proof *decryptionProof, knownSigner *x509.Certificate) (*pkicmp.PKIMessage, *cmpHTTPResponse, *pkicmp.VerifyResult, error) {
	if proof == nil || proof.method != ChallengeResponse {
		return nil, nil, nil, &Error{Op: "the CA sent a popdecc challenge the request did not ask for"}
	}
	content, err := challenge.Body.PopDecC()
	if err != nil {
		return nil, nil, nil, &Error{Op: "parse popdecc", Err: err}
	}
	if len(*content) != 1 {
		return nil, nil, nil, &Error{Op: fmt.Sprintf("popdecc carries %d challenges for one request", len(*content))}
	}
	ch := (*content)[0]
	if len(ch.EncryptedRand) == 0 {
		return nil, nil, nil, &Error{Op: "popdecc challenge has no encryptedRand"}
	}
	plain, err := cms.Decrypt(ch.EncryptedRand, proof.key)
	if err != nil {
		return nil, nil, nil, &Error{Op: "decrypt popdecc challenge", Err: err}
	}
	rnd, err := pkicmp.ParseRand(plain)
	if err != nil {
		return nil, nil, nil, &Error{Op: "parse popdecc challenge", Err: err}
	}
	if err := ch.VerifyWitness(rnd.Int); err != nil {
		return nil, nil, nil, &Error{Op: "verify popdecc witness", Err: err}
	}
	// Rand names the sender of the popdecc, so a challenge relayed from
	// another transaction or CA is not answered. Both names are encoded the
	// same way before they are compared.
	got, err := rnd.MarshalBinary()
	if err != nil {
		return nil, nil, nil, &Error{Op: "encode popdecc challenge", Err: err}
	}
	want, err := (&pkicmp.Rand{Int: rnd.Int, Sender: challenge.Header.Sender}).MarshalBinary()
	if err != nil || !bytes.Equal(got, want) {
		return nil, nil, nil, &Error{Op: "popdecc challenge names another sender"}
	}

	answer := pkicmp.POPODecKeyRespContent{rnd.Int}
	msg := pkicmp.NewPKIMessage(pkicmp.NewPopDecRBody(&answer), pkicmp.MessageOptions{
		Sender:     req.Header.Sender,
		Recipient:  req.Header.Recipient,
		RecipNonce: challenge.Header.SenderNonce,
	})
	msg.Header.TransactionID = req.Header.TransactionID
	msg.Header.SenderKID = req.Header.SenderKID
	if err := creds.Protect(msg); err != nil {
		return nil, nil, nil, &Error{Op: "protect popdecr", Err: err}
	}
	der, err := msg.MarshalBinary()
	if err != nil {
		return nil, nil, nil, &Error{Op: "marshal popdecr", Err: err}
	}
	httpResp, err := c.sendHTTP(ctx, der)
	if err != nil {
		return nil, nil, nil, err
	}
	cmpResp, err := httpResp.parse("parse response to popdecr")
	if err != nil {
		return nil, nil, nil, err
	}
	resp := cmpResp.message
	vr, err := c.verifyResponse(msg, resp, creds, c.trustedCAs, knownSigner)
	if err != nil {
		err = withUnverifiedStatus(resp, &Error{Op: "verify response to popdecr", Err: err})
		return nil, nil, nil, cmpResp.wrapError(err)
	}
	if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
		return nil, nil, nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)})
	}
	return msg, cmpResp, vr, nil
}
