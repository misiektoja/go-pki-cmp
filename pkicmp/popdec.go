package pkicmp

import (
	"bytes"
	"crypto"
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SubsequentMessage values of popoPrivKey (RFC 9810 §5.2.8.3). An encryption or
// key agreement key that cannot sign proves possession with one of them.
const (
	// SubsequentMessageEncrCert asks for the certificate encrypted for the
	// requested key. Decrypting it and confirming its hash in certConf is the proof.
	SubsequentMessageEncrCert int64 = 0
	// SubsequentMessageChallengeResp asks for a popdecc challenge encrypted for
	// the requested key. Returning the decrypted number in popdecr is the proof.
	SubsequentMessageChallengeResp int64 = 1
)

// NewKeyAgreementPOP creates a proofOfPossession for a key agreement key that
// proves possession through subsequentMessage (keyAgreement variant).
func NewKeyAgreementPOP(subsequent *int64) *proofOfPossession {
	return &proofOfPossession{KeyAgreement: &popoPrivKey{SubsequentMessage: subsequent}}
}

// SubsequentMessage returns the subsequentMessage value of a keyEncipherment or
// keyAgreement proof. The second result is false for any other proof.
func (p *proofOfPossession) SubsequentMessage() (int64, bool) {
	priv := p.KeyEncipherment
	if priv == nil {
		priv = p.KeyAgreement
	}
	if priv == nil || priv.SubsequentMessage == nil {
		return 0, false
	}
	return *priv.SubsequentMessage, true
}

// Challenge per RFC 9810 §5.2.8.3.3.
//
//	Challenge ::= SEQUENCE {
//	    owf                 AlgorithmIdentifier OPTIONAL,
//	    witness             OCTET STRING,
//	    challenge           OCTET STRING,           -- deprecated
//	    encryptedRand   [0] EnvelopedData OPTIONAL
//	}
//
// The RFC 9810 module uses EXPLICIT TAGS, so encryptedRand wraps a complete
// EnvelopedData. A Challenge that tags the EnvelopedData implicitly is accepted
// as well. The deprecated challenge field is written empty, as RFC 9810
// requires for pvno 3.
type Challenge struct {
	// OWF is the one-way function that computed Witness. RFC 9810 requires it in the first challenge.
	OWF *AlgorithmIdentifier
	// Witness is the OWF hash of the DER INTEGER the challenge encrypts.
	Witness []byte
	// EncryptedRand is the DER EnvelopedData that encrypts a [Rand] for the requested key.
	EncryptedRand []byte
}

func (c *Challenge) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if c.OWF != nil {
			c.OWF.marshal(mctx, b)
		}
		b.AddASN1OctetString(c.Witness)
		b.AddASN1OctetString(nil)
		if c.EncryptedRand != nil {
			mctx.MinRequiredPVNO = PVNO3
			// encryptedRand [0] EXPLICIT EnvelopedData
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(c.EncryptedRand)
			})
		}
	})
}

func (c *Challenge) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid Challenge sequence"}
	}
	if seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		c.OWF = &AlgorithmIdentifier{}
		if err := c.OWF.unmarshal(&seq); err != nil {
			return err
		}
	}
	var witness, deprecated cryptobyte.String
	if !seq.ReadASN1(&witness, cbasn1.OCTET_STRING) {
		return &ParseError{Detail: "invalid Challenge witness"}
	}
	if !seq.ReadASN1(&deprecated, cbasn1.OCTET_STRING) {
		return &ParseError{Detail: "missing Challenge challenge field"}
	}
	c.Witness = witness
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub, envelope cryptobyte.String
		seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed())
		switch {
		case sub.PeekASN1Tag(cbasn1.SEQUENCE):
			if !sub.ReadASN1Element(&envelope, cbasn1.SEQUENCE) || !sub.Empty() {
				return &ParseError{Detail: "invalid Challenge encryptedRand"}
			}
			c.EncryptedRand = envelope
		default:
			// An implicitly tagged EnvelopedData starts with its version INTEGER.
			c.EncryptedRand = wrapSequence(sub)
		}
	}
	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in Challenge"}
	}
	return nil
}

// POPODecKeyChallContent is the popdecc body (RFC 9810 §5.2.8.3.3), one challenge per certificate request.
//
//	POPODecKeyChallContent ::= SEQUENCE OF Challenge
type POPODecKeyChallContent []Challenge

func (c *POPODecKeyChallContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := range *c {
			(*c)[i].marshal(mctx, b)
		}
	})
}

func (c *POPODecKeyChallContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid POPODecKeyChallContent sequence"}
	}
	for !seq.Empty() {
		var ch Challenge
		if err := ch.unmarshal(&seq); err != nil {
			return err
		}
		*c = append(*c, ch)
	}
	return nil
}

// POPODecKeyRespContent is the popdecr body (RFC 9810 §5.2.8.3.3), the decrypted
// number of each challenge in the order of the popdecc.
//
//	POPODecKeyRespContent ::= SEQUENCE OF INTEGER
type POPODecKeyRespContent []*big.Int

func (r *POPODecKeyRespContent) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, n := range *r {
			b.AddASN1BigInt(n)
		}
	})
}

func (r *POPODecKeyRespContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid POPODecKeyRespContent sequence"}
	}
	for !seq.Empty() {
		n := new(big.Int)
		if !seq.ReadASN1Integer(n) {
			return &ParseError{Detail: "invalid POPODecKeyRespContent integer"}
		}
		*r = append(*r, n)
	}
	return nil
}

// Rand is the content a popdecc challenge encrypts (RFC 9810 §5.2.8.3.3).
//
//	Rand ::= SEQUENCE {
//	    int      INTEGER,
//	    sender   GeneralName
//	}
type Rand struct {
	// Int is the number the client returns in popdecr.
	Int *big.Int
	// Sender is the sender of the popdecc message.
	Sender GeneralName
}

// MarshalBinary returns the DER encoding of the Rand.
func (r *Rand) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r.Int)
		r.Sender.marshal(&marshalContext{}, b)
	})
	return b.Bytes()
}

// ParseRand decodes a DER Rand.
func ParseRand(der []byte) (*Rand, error) {
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	r := &Rand{Int: new(big.Int)}
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() || !seq.ReadASN1Integer(r.Int) {
		return nil, &ParseError{Detail: "invalid Rand"}
	}
	if err := r.Sender.unmarshal(&seq); err != nil {
		return nil, err
	}
	if !seq.Empty() {
		return nil, &ParseError{Detail: "trailing data in Rand"}
	}
	return r, nil
}

// ChallengeWitness returns the witness of a challenge number: the hash of its DER
// INTEGER encoding, tag and length included, as Bouncy Castle computes it.
func ChallengeWitness(h crypto.Hash, n *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1BigInt(n)
	d := h.New()
	d.Write(b.BytesOrPanic())
	return d.Sum(nil)
}

// ErrWitnessMismatch is returned when a decrypted challenge does not match its witness.
var ErrWitnessMismatch = errors.New("pkicmp: challenge witness does not match the decrypted number")

// VerifyWitness checks that the witness of c is the OWF hash of n, the number
// decrypted from EncryptedRand. It fails when OWF is absent or names an
// unsupported hash, and returns [ErrWitnessMismatch] for another number.
func (c *Challenge) VerifyWitness(n *big.Int) error {
	if c.OWF == nil {
		return &ParseError{Detail: "challenge has no owf"}
	}
	h, err := hashFromOID(c.OWF.Algorithm)
	if err != nil {
		return err
	}
	if !bytes.Equal(ChallengeWitness(h, n), c.Witness) {
		return ErrWitnessMismatch
	}
	return nil
}

// NewEncryptedCertificate returns a CertOrEncCert holding the DER EnvelopedData of an encrypted certificate.
func NewEncryptedCertificate(envelope []byte) CertOrEncCert {
	return CertOrEncCert{EncryptedCert: &encryptedKey{envelopedData: &envelopedData{Raw: envelope}}}
}

// EncryptedCertificate returns the DER EnvelopedData of an encrypted certificate,
// or nil when the certificate is in plaintext or uses the deprecated EncryptedValue.
func (c *CertOrEncCert) EncryptedCertificate() []byte {
	if c.EncryptedCert == nil || c.EncryptedCert.envelopedData == nil {
		return nil
	}
	return c.EncryptedCert.envelopedData.Raw
}

// NewEncryptedValueCertificate returns a CertOrEncCert holding the DER
// EncryptedValue (RFC 4211 §2.1) of an encrypted certificate. RFC 9810 §5.2.2
// keeps this form for CMP version 2 peers only.
func NewEncryptedValueCertificate(value []byte) CertOrEncCert {
	return CertOrEncCert{EncryptedCert: &encryptedKey{encryptedValue: &encryptedValue{Raw: value}}}
}

// EncryptedValueCertificate returns the DER EncryptedValue of an encrypted
// certificate, or nil when the certificate is in plaintext or uses EnvelopedData.
func (c *CertOrEncCert) EncryptedValueCertificate() []byte {
	if c.EncryptedCert == nil || c.EncryptedCert.encryptedValue == nil {
		return nil
	}
	return c.EncryptedCert.encryptedValue.Raw
}
