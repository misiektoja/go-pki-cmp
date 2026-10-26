package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// PendingEnrollment is the state of an ir, cr, kur or p10cr that the CA
// answered with status waiting (RFC 9810 §5.3.22). [Client.ResumeEnrollment]
// continues the transaction from it, also in another process, so it encodes
// to JSON with its field tags. It holds no key or secret, but together with
// the credentials of the request it lets anyone collect the certificate.
type PendingEnrollment struct {
	// RequestType is the body type of the request: [pkicmp.BodyTypeIR],
	// [pkicmp.BodyTypeCR], [pkicmp.BodyTypeKUR] or [pkicmp.BodyTypeP10CR].
	RequestType pkicmp.BodyType `json:"requestType"`
	// PVNO is the protocol version of the transaction, 2 or 3.
	PVNO int `json:"pvno"`
	// TransactionID identifies the transaction to the CA.
	TransactionID []byte `json:"transactionId"`
	// Sender and Recipient are the DER-encoded GeneralNames of the request
	// header, which every later message repeats.
	Sender    []byte `json:"sender"`
	Recipient []byte `json:"recipient"`
	// SenderKID is the senderKID of the request, such as the reference of a
	// shared secret.
	SenderKID []byte `json:"senderKid,omitempty"`
	// RequestNonce is the senderNonce of the delayed request, which the final
	// response may repeat instead of the one of the last pollReq (RFC 9483 §4.4).
	RequestNonce []byte `json:"requestNonce"`
	// ResponseNonce is the senderNonce of the last response, which the next
	// pollReq repeats in recipNonce.
	ResponseNonce []byte `json:"responseNonce"`
	// CertReqID is the certReqId of the waiting CertResponse, which the
	// pollReq names.
	CertReqID int64 `json:"certReqId"`
	// PublicKey is the DER SubjectPublicKeyInfo of the requested key, which
	// the issued certificate must certify. It is empty for central key generation.
	PublicKey []byte `json:"publicKey"`
	// CentralKeyGeneration reports that the request asked the CA to generate
	// the key pair, which the final response carries.
	CentralKeyGeneration bool `json:"centralKeyGeneration,omitempty"`
	// IndirectPOP is the proof of possession by decryption the request asked
	// for. It is zero for a signature proof and for a p10cr.
	IndirectPOP IndirectPOP `json:"indirectPop,omitempty"`
	// ServerCertificate is the DER protection certificate of the last signed
	// response. It is a candidate signer for a later response that leaves its
	// certificate out, which must still chain to the trusted CAs.
	ServerCertificate []byte `json:"serverCertificate,omitempty"`
	// NextPoll is when the CA asked for the next pollReq. It is zero when the
	// CA named no time.
	NextPoll time.Time `json:"nextPoll,omitzero"`
}

// opResume names a failure to resume an enrollment in an [Error].
const opResume = "resume enrollment"

// ResumeEnrollment continues an enrollment from the state in
// [EnrollResult.Pending] or [PendingError]. It polls until the CA decides,
// checks the issued certificate as the Send* methods do and confirms it,
// unless the CA grants implicit confirmation.
//
// creds must be the credentials of the request, because the CA finds the
// transaction by them, and the client needs the trust settings of the one that
// sent the request, such as [WithTrustedCAs]. The header fields that later
// messages repeat come from pending, so request options other than
// [WithDeferredPolling] are ignored. For a request with central key
// generation, creds also decrypt the generated private key, which
// [EnrollResult.GeneratedKey] then holds.
//
// The first pollReq waits for [PendingEnrollment.NextPoll], at most the
// maximum of [WithCheckAfterLimits]. A context deadline and [WithMaxPolls]
// bound the call as they bound a Send* method. Polling that stops while the CA
// still waits returns a [PendingError] with the updated state. pending itself
// is not changed.
//
// A request that proves possession with [EncryptedCertificate] needs its
// private key to decrypt the certificate, so it is resumed with
// [Client.ResumeEnrollmentWithIndirectPOP].
func (c *Client) ResumeEnrollment(ctx context.Context, pending *PendingEnrollment, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	if pending != nil && pending.IndirectPOP == EncryptedCertificate {
		return nil, &Error{Op: opResume, Err: errors.New(
			"the request proves possession with an encrypted certificate, so resume it with ResumeEnrollmentWithIndirectPOP")}
	}
	return c.resumeEnrollment(ctx, pending, nil, creds, opts)
}

// ResumeEnrollmentWithIndirectPOP continues an enrollment that proves
// possession by decryption, as [Client.ResumeEnrollment] does. key is the
// private key of the request, which decrypts an encrypted certificate. See
// [Client.SendCRWithIndirectPOP] for the accepted keys.
func (c *Client) ResumeEnrollmentWithIndirectPOP(ctx context.Context, pending *PendingEnrollment, key any, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	var proof *decryptionProof
	if pending != nil {
		if pending.IndirectPOP == 0 {
			return nil, &Error{Op: opResume, Err: errors.New(
				"the request proves possession by signature, so resume it with ResumeEnrollment")}
		}
		proof = &decryptionProof{key: key, method: pending.IndirectPOP}
	}
	return c.resumeEnrollment(ctx, pending, proof, creds, opts)
}

// resumeEnrollment polls for the final response of pending and finishes the
// enrollment. proof is the key of a request that proves possession by
// decryption.
func (c *Client) resumeEnrollment(ctx context.Context, pending *PendingEnrollment, proof *decryptionProof, creds pkicmp.Credentials, opts []RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}
	txn, state, err := pending.restore(creds, proof)
	if err != nil {
		return nil, &Error{Op: opResume, Err: err}
	}
	return c.pollEnrollment(ctx, txn, state, ropts.deferredPolling)
}

// pending returns the state that resumes txn where state stands.
func (txn *enrollment) pending(state *pollState) (*PendingEnrollment, error) {
	sender, err := generalNameDER(txn.header.Sender)
	if err != nil {
		return nil, &Error{Op: "encode the sender of a pending enrollment", Err: err}
	}
	recipient, err := generalNameDER(txn.header.Recipient)
	if err != nil {
		return nil, &Error{Op: "encode the recipient of a pending enrollment", Err: err}
	}
	var publicKey []byte
	if !txn.central {
		publicKey, err = pkicmp.MarshalPublicKey(txn.requestedKey)
		if err != nil {
			return nil, &Error{Op: "encode the public key of a pending enrollment", Err: err}
		}
	}
	p := &PendingEnrollment{
		RequestType:          txn.requestType,
		PVNO:                 txn.header.PVNO,
		TransactionID:        bytes.Clone(txn.header.TransactionID),
		Sender:               sender,
		Recipient:            recipient,
		SenderKID:            bytes.Clone(txn.header.SenderKID),
		RequestNonce:         bytes.Clone(state.delayed.SenderNonce),
		ResponseNonce:        bytes.Clone(state.recipNonce),
		CertReqID:            state.certReqID,
		PublicKey:            publicKey,
		CentralKeyGeneration: txn.central,
		NextPoll:             state.nextPoll,
	}
	if txn.proof != nil {
		p.IndirectPOP = txn.proof.method
	}
	if state.knownSigner != nil {
		p.ServerCertificate = bytes.Clone(state.knownSigner.Raw)
	}
	return p, nil
}

// checkFields reports a field of p that contradicts its request type or that
// a later message of the transaction needs and p lacks.
func (p *PendingEnrollment) checkFields() error {
	p10cr := p.RequestType == pkicmp.BodyTypeP10CR
	switch {
	case p10cr && p.CertReqID != -1 && p.CertReqID != 0:
		return fmt.Errorf("certReqId %d cannot answer a p10cr", p.CertReqID)
	case p10cr && p.IndirectPOP != 0:
		return errors.New("a p10cr cannot prove possession by decryption")
	case p.CentralKeyGeneration && (p10cr || p.IndirectPOP != 0 || len(p.PublicKey) > 0):
		return errors.New("a request for central key generation has no public key and no proof of possession")
	case !p10cr && p.CertReqID < 0:
		return fmt.Errorf("certReqId %d is negative", p.CertReqID)
	case p.PVNO != pkicmp.PVNO2 && p.PVNO != pkicmp.PVNO3:
		return fmt.Errorf("unsupported protocol version: %d", p.PVNO)
	case len(p.TransactionID) == 0:
		return errors.New("no transaction ID")
	case len(p.RequestNonce) == 0 || len(p.ResponseNonce) == 0:
		return errors.New("no request or response nonce")
	}
	return nil
}

// restore checks p and returns the enrollment and the polling state it
// describes. proof is the key of a request that proves possession by
// decryption, which must match the requested key.
func (p *PendingEnrollment) restore(creds pkicmp.Credentials, proof *decryptionProof) (*enrollment, *pollState, error) {
	if p == nil {
		return nil, nil, errors.New("no pending enrollment")
	}
	if creds == nil {
		return nil, nil, errors.New("no credentials provided")
	}
	txn := &enrollment{
		requestType: p.RequestType,
		certReqIDs:  []int64{p.CertReqID},
		proof:       proof,
		central:     p.CentralKeyGeneration,
		creds:       creds,
	}
	switch p.RequestType {
	case pkicmp.BodyTypeIR:
		txn.expectedRepType = pkicmp.BodyTypeIP
	case pkicmp.BodyTypeCR, pkicmp.BodyTypeP10CR:
		txn.expectedRepType = pkicmp.BodyTypeCP
	case pkicmp.BodyTypeKUR:
		txn.expectedRepType = pkicmp.BodyTypeKUP
	default:
		return nil, nil, fmt.Errorf("request type %s is not ir, cr, kur or p10cr", p.RequestType)
	}
	if err := p.checkFields(); err != nil {
		return nil, nil, err
	}
	if p.RequestType == pkicmp.BodyTypeP10CR {
		// A p10cr carries no certReqId, and the CA may answer with -1 or 0.
		txn.certReqIDs = []int64{-1, 0}
	}
	if p.IndirectPOP != 0 {
		if _, err := p.IndirectPOP.subsequentMessage(); err != nil {
			return nil, nil, err
		}
	}

	sender, err := parseGeneralName(p.Sender)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: %w", err)
	}
	recipient, err := parseGeneralName(p.Recipient)
	if err != nil {
		return nil, nil, fmt.Errorf("recipient: %w", err)
	}
	if !p.CentralKeyGeneration {
		txn.requestedKey, err = pkicmp.ParsePublicKey(p.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("public key: %w", err)
		}
	}
	if proof != nil {
		pub, _, err := decryptionPublicKey(proof.key)
		if err != nil {
			return nil, nil, err
		}
		if !pkicmp.PublicKeysEqual(pub, txn.requestedKey) {
			return nil, nil, errors.New("the key does not match the public key of the request")
		}
	}
	var knownSigner *x509.Certificate
	if len(p.ServerCertificate) > 0 {
		knownSigner, err = (&pkicmp.CMPCertificate{Raw: p.ServerCertificate}).Parse()
		if err != nil {
			return nil, nil, fmt.Errorf("server certificate: %w", err)
		}
	}

	txn.header = pkicmp.PKIHeader{
		PVNO:          p.PVNO,
		Sender:        sender,
		Recipient:     recipient,
		TransactionID: bytes.Clone(p.TransactionID),
		SenderKID:     bytes.Clone(p.SenderKID),
	}
	state := &pollState{
		delayed:     txn.header,
		recipNonce:  bytes.Clone(p.ResponseNonce),
		certReqID:   p.CertReqID,
		knownSigner: knownSigner,
		nextPoll:    p.NextPoll,
	}
	state.delayed.SenderNonce = bytes.Clone(p.RequestNonce)
	return txn, state, nil
}

// generalNameDER encodes a name the client put in a request header, which is
// always a directoryName. A name the client took encoded is kept verbatim.
func generalNameDER(name pkicmp.GeneralName) ([]byte, error) {
	if len(name.Raw) > 0 {
		return bytes.Clone(name.Raw), nil
	}
	if name.RFC822Name != "" {
		return nil, errors.New("an rfc822Name in the request header is not supported")
	}
	// pkicmp encodes a directoryName with encoding/asn1 as well, so the bytes
	// are those the request carried.
	rdn, err := asn1.Marshal(name.DirectoryName)
	if err != nil {
		return nil, err
	}
	return pkicmp.NewDirectoryNameFromRawDER(rdn).Raw, nil
}

// parseGeneralName checks that der is one GeneralName element and returns it
// for a header, which writes it back verbatim.
func parseGeneralName(der []byte) (pkicmp.GeneralName, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	switch {
	case err != nil:
		return pkicmp.GeneralName{}, err
	case len(rest) > 0:
		return pkicmp.GeneralName{}, errors.New("trailing data after the GeneralName")
	case raw.Class != asn1.ClassContextSpecific || raw.Tag > 8:
		return pkicmp.GeneralName{}, errors.New("not a GeneralName")
	}
	return pkicmp.GeneralName{Raw: bytes.Clone(der)}, nil
}
