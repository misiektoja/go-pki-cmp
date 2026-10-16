package pkicmp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidRegCtrlOldCertID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 5}

// CertReqMessages per RFC 4211 §3.
//
//	CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
type CertReqMessages []CertReqMsg

func (m *CertReqMessages) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, req := range *m {
			req.marshal(mctx, b)
		}
	})
}

func (m *CertReqMessages) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertReqMessages sequence"}
	}
	for !seq.Empty() {
		var req CertReqMsg
		if err := req.unmarshal(&seq); err != nil {
			return err
		}
		*m = append(*m, req)
	}
	return nil
}

// CertReqMsg per RFC 4211 §3.
//
//	CertReqMsg ::= SEQUENCE {
//	    certReq   CertRequest,
//	    popo      proofOfPossession  OPTIONAL,
//	    regInfo   SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue OPTIONAL
//	}
type CertReqMsg struct {
	// CertReq holds the requested certificate contents.
	CertReq CertRequest
	// Popo proves the requester controls the referenced private key.
	Popo *proofOfPossession
}

func (m *CertReqMsg) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		m.CertReq.marshal(mctx, b)
		if m.Popo != nil {
			m.Popo.marshal(mctx, b)
		}
	})
}

// GeneratePOP generates a Signature proofOfPossession using the provided private key
// over the DER-encoded CertRequest and assigns it to m.Popo.
func (m *CertReqMsg) GeneratePOP(key crypto.Signer) error {
	mctx := &marshalContext{MinRequiredPVNO: PVNO2}

	var b cryptobyte.Builder
	m.CertReq.marshal(mctx, &b)
	certReqDER, err := b.Bytes()
	if err != nil {
		return &ParseError{Detail: "marshal CertRequest for POP", Err: err}
	}

	sigAlgOID, hashFunc, err := signatureAlgorithmFromKey(key)
	if err != nil {
		return err
	}

	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(certReqDER)
		digest = h.Sum(nil)
	} else {
		digest = certReqDER
	}

	sig, err := key.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return &ParseError{Detail: "sign POP", Err: err}
	}

	m.Popo = &proofOfPossession{
		Signature: &popoSigningKey{
			Algorithm: AlgorithmIdentifier{Algorithm: sigAlgOID},
			Signature: sig,
		},
	}

	return nil
}

// NewRAVerifiedPOP creates a proofOfPossession where the RA has already
// verified the requester's key possession (raVerified variant).
func NewRAVerifiedPOP() *proofOfPossession {
	return &proofOfPossession{RAVerified: true}
}

// NewKeyEnciphermentPOP creates a proofOfPossession for an encryption key
// where possession is demonstrated via subsequentMessage (keyEncipherment variant).
func NewKeyEnciphermentPOP(subsequent *int64) *proofOfPossession {
	return &proofOfPossession{KeyEncipherment: &popoPrivKey{SubsequentMessage: subsequent}}
}

// NewEncryptedKeyPOP creates a proofOfPossession carrying an envelopedData
// encrypted key (keyEncipherment / encryptedKey variant).
func NewEncryptedKeyPOP(raw []byte) *proofOfPossession {
	return &proofOfPossession{KeyEncipherment: &popoPrivKey{encryptedKey: &envelopedData{Raw: raw}}}
}

func (m *CertReqMsg) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertReqMsg sequence"}
	}
	if err := m.CertReq.unmarshal(&seq); err != nil {
		return err
	}

	if !seq.Empty() && !seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		// proofOfPossession is a CHOICE, so it has context tags [0], [1], [2], [3]
		m.Popo = &proofOfPossession{}
		if err := m.Popo.unmarshal(&seq); err != nil {
			return err
		}
	}

	// Ignore RegInfo for now if present (it's a SEQUENCE)
	return nil
}

// Subject returns the requested certificate subject from the CertTemplate.
func (m *CertReqMsg) Subject() pkix.Name {
	var name pkix.Name
	if len(m.CertReq.CertTemplate.Subject.DirectoryName) > 0 {
		name.FillFromRDNSequence(&m.CertReq.CertTemplate.Subject.DirectoryName)
	}
	return name
}

// PublicKey parses and returns the public key from the CertTemplate. A
// composite ML-DSA key is returned as *compositemldsa.PublicKey.
func (m *CertReqMsg) PublicKey() (any, error) {
	if len(m.CertReq.CertTemplate.PublicKey) == 0 {
		return nil, nil
	}
	return ParsePublicKey(m.CertReq.CertTemplate.PublicKey)
}

// Extensions parses and returns the extensions from the CertTemplate.
func (m *CertReqMsg) Extensions() ([]pkix.Extension, error) {
	if len(m.CertReq.CertTemplate.Extensions) == 0 {
		return nil, nil
	}
	var exts []pkix.Extension
	if _, err := asn1.Unmarshal(m.CertReq.CertTemplate.Extensions, &exts); err != nil {
		return nil, err
	}
	return exts, nil
}

// CertRequest per RFC 4211 §3.
//
//	CertRequest ::= SEQUENCE {
//	    certReqId     INTEGER,
//	    certTemplate  CertTemplate,
//	    controls      Controls OPTIONAL
//	}
type CertRequest struct {
	// CertReqID links this request to its corresponding response item.
	CertReqID int64
	// CertTemplate describes subject, key, and extension preferences.
	CertTemplate CertTemplate
	// Controls contains registration controls that affect certificate issuance.
	Controls []AttributeTypeAndValue
	// Raw contains the DER encoding of this CertRequest, preserved during parsing
	// for use in POP verification. Set automatically by unmarshal; ignored during marshal.
	Raw []byte
}

func (r *CertRequest) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(r.CertReqID)
		r.CertTemplate.marshal(mctx, b)
		if len(r.Controls) > 0 {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for i := range r.Controls {
					r.Controls[i].marshal(mctx, b)
				}
			})
		}
	})
}

func (r *CertRequest) unmarshal(s *cryptobyte.String) error {
	// Capture the raw DER of the entire CertRequest SEQUENCE for POP verification.
	var raw cryptobyte.String
	if !s.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertRequest sequence"}
	}
	r.Raw = []byte(raw)

	var seq cryptobyte.String
	inner := cryptobyte.String(r.Raw)
	if !inner.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertRequest sequence"}
	}
	if !seq.ReadASN1Integer(&r.CertReqID) {
		return &ParseError{Detail: detailInvalidCertReqID}
	}
	if err := r.CertTemplate.unmarshal(&seq); err != nil {
		return err
	}
	if seq.Empty() {
		return nil
	}

	var controls cryptobyte.String
	if !seq.ReadASN1(&controls, cbasn1.SEQUENCE) || controls.Empty() {
		return &ParseError{Detail: "invalid Controls sequence"}
	}
	for !controls.Empty() {
		var control AttributeTypeAndValue
		if err := control.unmarshal(&controls); err != nil {
			return err
		}
		r.Controls = append(r.Controls, control)
	}
	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in CertRequest"}
	}
	return nil
}

// AttributeTypeAndValue carries one typed CRMF registration control value.
type AttributeTypeAndValue struct {
	// Type selects how Value should be interpreted.
	Type asn1.ObjectIdentifier
	// Value contains the complete DER encoding of the required control value.
	Value []byte
}

// NewOldCertIDControl identifies the certificate being updated by issuer and serial number.
func NewOldCertIDControl(certificate *x509.Certificate) (AttributeTypeAndValue, error) {
	if certificate == nil {
		return AttributeTypeAndValue{}, fmt.Errorf("pkicmp: oldCertID certificate is nil")
	}
	if certificate.SerialNumber == nil {
		return AttributeTypeAndValue{}, fmt.Errorf("pkicmp: oldCertID certificate serial number is nil")
	}

	issuer := NewDirectoryName(certificate.Issuer)
	if len(certificate.RawIssuer) > 0 {
		issuer = NewDirectoryNameFromRawDER(certificate.RawIssuer)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		issuer.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
		b.AddASN1BigInt(certificate.SerialNumber)
	})
	value, err := b.Bytes()
	if err != nil {
		return AttributeTypeAndValue{}, fmt.Errorf("pkicmp: encode oldCertID: %w", err)
	}
	return AttributeTypeAndValue{Type: oidRegCtrlOldCertID, Value: value}, nil
}

// directoryNameDER returns the DER Name inside a directoryName [4] GeneralName element.
func directoryNameDER(raw []byte) ([]byte, bool) {
	s := cryptobyte.String(raw)
	var inner cryptobyte.String
	if !s.ReadASN1(&inner, cbasn1.Tag(tagDirectoryName).ContextSpecific().Constructed()) || !s.Empty() {
		return nil, false
	}
	rest := inner
	if !rest.SkipASN1(cbasn1.SEQUENCE) || !rest.Empty() {
		return nil, false
	}
	return inner, true
}

// OldCertID returns the certificate the request names in an oldCertID control
// (RFC 4211 §6.5). It returns nil when the request carries none.
//
// The requester chooses the value. RFC 9483 §4.1.3 expects a key update to be
// signed with the certificate it names. Before acting on the value, a caller
// must check that with [CertID.Identifies] or authorize the signer in another
// way. A repeated or undecodable control is an error.
func (r *CertRequest) OldCertID() (*CertID, error) {
	var found *CertID
	for i := range r.Controls {
		if !r.Controls[i].Type.Equal(oidRegCtrlOldCertID) {
			continue
		}
		if found != nil {
			return nil, &ParseError{Detail: "more than one oldCertID control"}
		}
		value := cryptobyte.String(r.Controls[i].Value)
		var id CertID
		if err := id.unmarshal(&value); err != nil {
			return nil, err
		}
		if !value.Empty() {
			return nil, &ParseError{Detail: "trailing data in oldCertID"}
		}
		found = &id
	}
	return found, nil
}

// marshal encodes one AttributeTypeAndValue.
func (a *AttributeTypeAndValue) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(a.Type)
		if len(a.Value) == 0 {
			b.SetError(fmt.Errorf("pkicmp: attribute type and value is empty"))
			return
		}
		b.AddBytes(a.Value)
	})
}

// unmarshal decodes one AttributeTypeAndValue.
func (a *AttributeTypeAndValue) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid AttributeTypeAndValue sequence"}
	}
	if !seq.ReadASN1ObjectIdentifier(&a.Type) {
		return &ParseError{Detail: "invalid AttributeTypeAndValue OID"}
	}
	var value cryptobyte.String
	var tag cbasn1.Tag
	if !seq.ReadAnyASN1Element(&value, &tag) || !seq.Empty() {
		return &ParseError{Detail: "invalid AttributeTypeAndValue value"}
	}
	a.Value = value
	return nil
}

// CertTemplate per RFC 4211 §2.
//
// Only serialNumber [1], issuer [3], subject [5], publicKey [6] and extensions [9]
// are supported. Other fields (version, signingAlg, validity, issuerUID,
// subjectUID) are silently skipped during parsing.
type CertTemplate struct {
	// SerialNumber identifies an existing certificate, as in a revocation request.
	SerialNumber *big.Int
	Issuer       []byte // Raw DER Name, such as x509.Certificate.RawIssuer
	// Subject is the requested certificate subject DN.
	Subject GeneralName
	// RawSubject is the DER Name of the subject exactly as received, which keeps
	// the attribute order and string types that Subject loses when re-encoded.
	// Parsing sets it. Marshalling ignores it and encodes Subject.
	RawSubject []byte
	PublicKey  []byte // Raw DER SubjectPublicKeyInfo
	Extensions []byte // Raw DER Extensions
}

func (t *CertTemplate) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if t.SerialNumber != nil {
			// serialNumber [1] INTEGER OPTIONAL (IMPLICIT)
			b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(marshalImplicitBigInt(t.SerialNumber))
			})
		}
		if len(t.Issuer) > 0 {
			// issuer [3] Name OPTIONAL
			// Name is a CHOICE, so the tag is EXPLICIT and wraps the SEQUENCE.
			if !isSingleElement(t.Issuer, cbasn1.SEQUENCE) {
				b.SetError(fmt.Errorf("pkicmp: invalid issuer DER"))
				return
			}
			b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(t.Issuer)
			})
		}
		switch {
		case len(t.Subject.DirectoryName) > 0:
			// subject [5] Name OPTIONAL
			// Name is CHOICE { rdnSequence RDNSequence }
			// Tagging a CHOICE is always EXPLICIT, so we keep it as is.
			b.AddASN1(cbasn1.Tag(5).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				marshalRDNSequence(b, t.Subject.DirectoryName)
			})
		case len(t.Subject.Raw) > 0:
			// A subject from NewDirectoryNameFromRawDER keeps its Name encoding.
			name, ok := directoryNameDER(t.Subject.Raw)
			if !ok {
				b.SetError(fmt.Errorf("pkicmp: certificate template subject is not a directoryName"))
				return
			}
			b.AddASN1(cbasn1.Tag(5).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(name)
			})
		}
		if len(t.PublicKey) > 0 {
			// publicKey [6] SubjectPublicKeyInfo OPTIONAL
			// SubjectPublicKeyInfo is a SEQUENCE.
			// IMPLICIT tagging means [6] replaces the SEQUENCE tag.
			content, err := stripSequence(t.PublicKey)
			if err != nil {
				b.SetError(fmt.Errorf("pkicmp: invalid publicKey DER: %w", err))
				return
			}
			b.AddASN1(cbasn1.Tag(6).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(content)
			})
		}
		if len(t.Extensions) > 0 {
			// extensions [9] Extensions OPTIONAL
			// Extensions is a SEQUENCE.
			// IMPLICIT tagging means [9] replaces the SEQUENCE tag.
			content, err := stripSequence(t.Extensions)
			if err != nil {
				b.SetError(fmt.Errorf("pkicmp: invalid extensions DER: %w", err))
				return
			}
			b.AddASN1(cbasn1.Tag(9).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(content)
			})
		}
	})
}

func (t *CertTemplate) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertTemplate sequence"}
	}

	for !seq.Empty() {
		var sub cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&sub, &tag) {
			return &ParseError{Detail: "invalid CertTemplate element"}
		}

		switch tag {
		case cbasn1.Tag(1).ContextSpecific():
			var content cryptobyte.String
			if !sub.ReadASN1(&content, tag) {
				return &ParseError{Detail: "invalid serialNumber tag"}
			}
			serial, err := unmarshalImplicitBigInt(content)
			if err != nil {
				return err
			}
			t.SerialNumber = serial
		case cbasn1.Tag(3).ContextSpecific().Constructed():
			var content, name cryptobyte.String
			if !sub.ReadASN1(&content, tag) {
				return &ParseError{Detail: "invalid issuer tag"}
			}
			if !content.ReadASN1Element(&name, cbasn1.SEQUENCE) || !content.Empty() {
				return &ParseError{Detail: "invalid issuer name"}
			}
			t.Issuer = name
		case cbasn1.Tag(5).ContextSpecific().Constructed():
			var content cryptobyte.String
			if !sub.ReadASN1(&content, tag) {
				return &ParseError{Detail: "invalid subject tag"}
			}
			raw := content
			if err := parseRDNSequence(&content, &t.Subject.DirectoryName); err != nil {
				return err
			}
			t.RawSubject = raw[:len(raw)-len(content)]
		case cbasn1.Tag(6).ContextSpecific().Constructed():
			var content cryptobyte.String
			if !sub.ReadASN1(&content, tag) {
				return &ParseError{Detail: "invalid publicKey tag"}
			}
			t.PublicKey = wrapSequence(content)
		case cbasn1.Tag(9).ContextSpecific().Constructed():
			var content cryptobyte.String
			if !sub.ReadASN1(&content, tag) {
				return &ParseError{Detail: "invalid extensions tag"}
			}
			t.Extensions = wrapSequence(content)
		default:
			// Skip unknown optional fields for now
		}
	}
	return nil
}

// proofOfPossession per RFC 4211 §4.

//	proofOfPossession ::= CHOICE {
//	    raVerified        [0] NULL,
//	    signature         [1] popoSigningKey,
//	    keyEncipherment   [2] popoPrivKey,
//	    keyAgreement      [3] popoPrivKey
//	}
type proofOfPossession struct {
	// RAVerified means the RA has already verified key possession.
	RAVerified bool
	// Signature carries a signature-based POP proof.
	Signature *popoSigningKey
	// KeyEncipherment carries encryption-based POP material.
	KeyEncipherment *popoPrivKey
	// KeyAgreement carries agreement-based POP material.
	KeyAgreement *popoPrivKey
}

func (p *proofOfPossession) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	switch {
	case p.RAVerified:
		// raVerified [0] NULL (IMPLICIT)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {})
	case p.Signature != nil:
		// signature [1] popoSigningKey (IMPLICIT)
		// popoSigningKey is a SEQUENCE.
		b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.Signature.marshalInner(mctx, b)
		})
	case p.KeyEncipherment != nil:
		// keyEncipherment [2] popoPrivKey (EXPLICIT because popoPrivKey is a CHOICE)
		b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.KeyEncipherment.marshal(mctx, b)
		})
	case p.KeyAgreement != nil:
		// keyAgreement [3] popoPrivKey (EXPLICIT because popoPrivKey is a CHOICE)
		b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.KeyAgreement.marshal(mctx, b)
		})
	}
}

func (p *proofOfPossession) unmarshal(s *cryptobyte.String) error {
	var sub cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&sub, &tag) {
		return &ParseError{Detail: "missing proofOfPossession"}
	}

	switch tag {
	case cbasn1.Tag(0).ContextSpecific():
		p.RAVerified = true
	case cbasn1.Tag(1).ContextSpecific().Constructed():
		// signature [1] IMPLICIT popoSigningKey (SEQUENCE)
		p.Signature = &popoSigningKey{}
		return p.Signature.unmarshalInner(&sub)
	case cbasn1.Tag(2).ContextSpecific().Constructed():
		// keyEncipherment [2] EXPLICIT popoPrivKey (CHOICE)
		p.KeyEncipherment = &popoPrivKey{}
		return p.KeyEncipherment.unmarshal(&sub)
	case cbasn1.Tag(3).ContextSpecific().Constructed():
		// keyAgreement [3] EXPLICIT popoPrivKey (CHOICE)
		p.KeyAgreement = &popoPrivKey{}
		return p.KeyAgreement.unmarshal(&sub)
	default:
		return &ParseError{Detail: fmt.Sprintf("unsupported proofOfPossession variant: %d", tag)}
	}
	return nil
}

// popoPrivKey per RFC 9810 §5.2.8.
//
//	popoPrivKey ::= CHOICE {
//	    thisMessage       [0] BIT STRING,         -- deprecated
//	    subsequentMessage [1] SubsequentMessage,
//	    dhMAC             [2] BIT STRING,         -- deprecated
//	    agreeMAC          [3] PKMACValue,
//	    encryptedKey      [4] envelopedData
//	}
type popoPrivKey struct {
	// SubsequentMessage carries the subsequentMessage [1] value (RFC 9810 §5.2.8.3).
	SubsequentMessage *int64
	// encryptedKey carries the encryptedKey [4] value (RFC 9810 §5.2.8.3).
	encryptedKey *envelopedData
}

func (p *popoPrivKey) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	if p.SubsequentMessage != nil {
		// subsequentMessage [1] SubsequentMessage (IMPLICIT)
		// SubsequentMessage is an INTEGER.
		b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(marshalImplicitInt64(*p.SubsequentMessage))
		})
	} else if p.encryptedKey != nil {
		mctx.MinRequiredPVNO = PVNO3
		// encryptedKey [4] envelopedData (IMPLICIT)
		// envelopedData is a SEQUENCE.
		b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.encryptedKey.marshalInner(b)
		})
	}
}

func (p *popoPrivKey) unmarshal(s *cryptobyte.String) error {
	var sub cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&sub, &tag) {
		return &ParseError{Detail: "missing popoPrivKey"}
	}

	switch tag {
	case cbasn1.Tag(1).ContextSpecific():
		// subsequentMessage [1] IMPLICIT INTEGER
		val, err := unmarshalImplicitInt64(sub)
		if err != nil {
			return err
		}
		p.SubsequentMessage = &val
	case cbasn1.Tag(4).ContextSpecific().Constructed():
		// encryptedKey [4] IMPLICIT envelopedData (SEQUENCE)
		p.encryptedKey = &envelopedData{}
		return p.encryptedKey.unmarshalInner(&sub)
	default:
		return &ParseError{Detail: fmt.Sprintf("unsupported popoPrivKey variant: %d", tag)}
	}
	return nil
}

// popoSigningKey per RFC 4211 §4.1.
//
//	popoSigningKey ::= SEQUENCE {
//	    poposkInput           [0] popoSigningKeyInput OPTIONAL,
//	    algorithmIdentifier   AlgorithmIdentifier,
//	    signature             BIT STRING
//	}
type popoSigningKey struct {
	// PoposkInput carries optional sender-identity bound to the proof.
	PoposkInput *popoSigningKeyInput
	// Algorithm identifies how the POP signature was generated.
	Algorithm AlgorithmIdentifier
	// Signature is the POP signature output bytes.
	Signature []byte
}

func (p *popoSigningKey) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		p.marshalInner(mctx, b)
	})
}

func (p *popoSigningKey) marshalInner(mctx *marshalContext, b *cryptobyte.Builder) {
	if p.PoposkInput != nil {
		// poposkInput [0] popoSigningKeyInput (IMPLICIT)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.PoposkInput.marshalInner(mctx, b)
		})
	}
	p.Algorithm.marshal(mctx, b)
	b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
		b.AddUint8(0) // No unused bits
		b.AddBytes(p.Signature)
	})
}

func (p *popoSigningKey) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid popoSigningKey sequence"}
	}
	return p.unmarshalInner(&seq)
}

func (p *popoSigningKey) unmarshalInner(seq *cryptobyte.String) error {
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid poposkInput tag"}
		}
		p.PoposkInput = &popoSigningKeyInput{raw: append([]byte(nil), sub...)}
		if err := p.PoposkInput.unmarshalInner(&sub); err != nil {
			return err
		}
	}

	if err := p.Algorithm.unmarshal(seq); err != nil {
		return err
	}

	var bitString cryptobyte.String
	if !seq.ReadASN1(&bitString, cbasn1.BIT_STRING) {
		return &ParseError{Detail: "invalid signature BIT STRING"}
	}
	var unused uint8
	if !bitString.ReadUint8(&unused) {
		return &ParseError{Detail: "invalid signature unused bits"}
	}
	p.Signature = bitString
	return nil
}

// popoSigningKeyInput per RFC 4211 §4.1.
//
//	popoSigningKeyInput ::= SEQUENCE {
//	    authInfo            CHOICE {
//	        sender              [0] GeneralName,
//	        publicKeyMAC        PKMACValue },
//	    publicKey           SubjectPublicKeyInfo
//	}
type popoSigningKeyInput struct {
	// Sender is the authInfo for a requester with an authenticated name.
	Sender *GeneralName
	// PublicKeyMAC is the authInfo for a requester that holds only a shared secret.
	PublicKeyMAC *pkMACValue
	// PublicKey is the key material being proven.
	PublicKey []byte // Raw DER SubjectPublicKeyInfo

	// raw is the content of the received poposkInput element, which the POP
	// signature covers. It is nil for a value built locally.
	raw []byte
}

// pkMACValue per RFC 4211 §4.1.
//
//	PKMACValue ::= SEQUENCE {
//	    algId  AlgorithmIdentifier,
//	    value  BIT STRING
//	}
type pkMACValue struct {
	// Algorithm is PasswordBasedMac with its parameters.
	Algorithm AlgorithmIdentifier
	// Value is the MAC over the public key.
	Value []byte
}

// marshal writes the popoSigningKeyInput as a SEQUENCE.
func (p *popoSigningKeyInput) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		p.marshalInner(mctx, b)
	})
}

// marshalInner writes the authInfo choice followed by the public key.
func (p *popoSigningKeyInput) marshalInner(mctx *marshalContext, b *cryptobyte.Builder) {
	switch {
	case p.Sender != nil:
		// sender [0] GeneralName (EXPLICIT because GeneralName is a CHOICE)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			p.Sender.marshal(mctx, b)
		})
	case p.PublicKeyMAC != nil:
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			p.PublicKeyMAC.Algorithm.marshal(mctx, b)
			b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
				b.AddUint8(0) // No unused bits
				b.AddBytes(p.PublicKeyMAC.Value)
			})
		})
	}
	b.AddBytes(p.PublicKey)
}

// unmarshal reads a popoSigningKeyInput SEQUENCE.
func (p *popoSigningKeyInput) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid popoSigningKeyInput sequence"}
	}
	return p.unmarshalInner(&seq)
}

// unmarshalInner reads the required authInfo choice and the public key, and
// nothing after them.
func (p *popoSigningKeyInput) unmarshalInner(seq *cryptobyte.String) error {
	switch {
	case seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()):
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid sender tag"}
		}
		p.Sender = &GeneralName{}
		if err := p.Sender.unmarshal(&sub); err != nil {
			return err
		}
		if !sub.Empty() {
			return &ParseError{Detail: "trailing data in poposkInput sender"}
		}
	case seq.PeekASN1Tag(cbasn1.SEQUENCE):
		// Both alternatives after sender are SEQUENCEs, so the required
		// authInfo is a PKMACValue exactly when another SEQUENCE follows it.
		rest := *seq
		var first cryptobyte.String
		if !rest.SkipASN1(cbasn1.SEQUENCE) || !rest.PeekASN1Tag(cbasn1.SEQUENCE) {
			return &ParseError{Detail: detailPoposkInputAuthMissing}
		}
		if !seq.ReadASN1(&first, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid publicKeyMAC"}
		}
		p.PublicKeyMAC = &pkMACValue{}
		if err := p.PublicKeyMAC.Algorithm.unmarshal(&first); err != nil {
			return err
		}
		var bitString cryptobyte.String
		var unused uint8
		if !first.ReadASN1(&bitString, cbasn1.BIT_STRING) || !bitString.ReadUint8(&unused) || unused != 0 || !first.Empty() {
			return &ParseError{Detail: "invalid publicKeyMAC value"}
		}
		p.PublicKeyMAC.Value = bitString
	default:
		return &ParseError{Detail: detailPoposkInputAuthMissing}
	}

	var pub cryptobyte.String
	if !seq.ReadASN1Element(&pub, cbasn1.SEQUENCE) || !seq.Empty() {
		return &ParseError{Detail: "invalid poposkInput publicKey"}
	}
	p.PublicKey = pub
	return nil
}
