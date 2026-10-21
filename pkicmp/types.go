package pkicmp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CMPCertificate per RFC 9810 §5.1.
//
// CMPCertificate ::= CHOICE { x509v3PKCert Certificate, ... }
type CMPCertificate struct {
	// Raw contains the DER-encoded certificate CHOICE value.
	Raw []byte
}

// Parse parses the Raw bytes into an x509.Certificate.
func (c *CMPCertificate) Parse() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Raw)
}

// PKIFreeText per RFC 9810 §5.1.1.
//
// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
type PKIFreeText []string

// InfoTypeAndValue per RFC 9810 §5.1.1.
//
//	InfoTypeAndValue ::= SEQUENCE {
//	    infoType    OBJECT IDENTIFIER,
//	    infoValue   ANY DEFINED BY infoType OPTIONAL }
type InfoTypeAndValue struct {
	// InfoType selects how InfoValue should be interpreted.
	InfoType  asn1.ObjectIdentifier
	InfoValue []byte // Raw DER of the value
}

// AlgorithmIdentifier per RFC 9810 §5.1.1.
//
//	AlgorithmIdentifier ::= SEQUENCE {
//	    algorithm   OBJECT IDENTIFIER,
//	    parameters  ANY DEFINED BY algorithm OPTIONAL }
type AlgorithmIdentifier struct {
	// Algorithm selects the cryptographic algorithm.
	Algorithm  asn1.ObjectIdentifier
	Parameters []byte // Raw DER of the parameters
}

// GeneralName per RFC 9810 §5.1.1 and RFC 5280 §4.2.1.6.
//
// Only directoryName [4] is supported. Other variants (rfc822Name, dNSName,
// URI, iPAddress, registeredID) will return [ErrUnsupportedGeneralName].
//
//	GeneralName ::= CHOICE {
//	    otherName                 [0]  OtherName,
//	    rfc822Name                [1]  IA5String,
//	    dNSName                   [2]  IA5String,
//	    x400Address               [3]  ORAddress,
//	    directoryName             [4]  Name,
//	    ediPartyName              [5]  EDIPartyName,
//	    uniformResourceIdentifier [6]  IA5String,
//	    iPAddress                 [7]  OCTET STRING,
//	    registeredID              [8]  OBJECT IDENTIFIER }
type GeneralName struct {
	// DirectoryName holds the parsed RDNSequence when the variant is directoryName [4].
	DirectoryName pkix.RDNSequence
	// RFC822Name holds the email address when the variant is rfc822Name [1].
	RFC822Name string
	// Raw holds the full DER-encoded GeneralName element (tag + length + value)
	// for round-tripping variants that are not parsed into dedicated fields.
	Raw []byte
}

var (
	ErrUnsupportedGeneralName = errors.New("pkicmp: unsupported GeneralName variant")
)

// GeneralName context-specific tag constants per RFC 5280 §4.2.1.6.
const (
	tagRFC822Name    = 1
	tagDirectoryName = 4
	tagURI           = 6
)

// NewDirectoryName creates a GeneralName of type directoryName from a pkix.Name.
//
// pkix.Name.ToRDNSequence only emits the attributes that have a typed field,
// so a name parsed from a certificate loses everything else, such as the UID
// and domainComponent attributes EJBCA puts in its CA subject. Those attributes
// survive parsing only in Names, and this reconstructs them the same way
// pkix.Name.String does, which keeps the encoded name and its string form in
// agreement. Use NewDirectoryNameFromRawDER when the original bytes must be
// preserved exactly, for example to echo a peer's own name back to it.
func NewDirectoryName(name pkix.Name) GeneralName {
	return GeneralName{DirectoryName: toFullRDNSequence(name)}
}

// toFullRDNSequence encodes a pkix.Name including the attributes ToRDNSequence drops.
func toFullRDNSequence(name pkix.Name) pkix.RDNSequence {
	var rdns pkix.RDNSequence
	// ExtraNames is the caller's explicit encoding instruction, and
	// ToRDNSequence already appends it, so Names is only consulted otherwise.
	if name.ExtraNames == nil {
		for _, atv := range name.Names {
			if isTypedNameAttribute(atv.Type) {
				continue
			}
			// Attributes are placed ahead of the typed ones so they read last
			// in the string form, matching pkix.Name.String.
			rdns = append(rdns, pkix.RelativeDistinguishedNameSET{atv})
		}
	}
	return append(rdns, name.ToRDNSequence()...)
}

// isTypedNameAttribute reports whether ToRDNSequence already emits the attribute from a typed pkix.Name field.
func isTypedNameAttribute(t asn1.ObjectIdentifier) bool {
	if len(t) != 4 || t[0] != 2 || t[1] != 5 || t[2] != 4 {
		return false
	}
	switch t[3] {
	// commonName, serialNumber, countryName, localityName, stateOrProvinceName,
	// organizationName, organizationalUnitName, streetAddress, postalCode.
	case 3, 5, 6, 7, 8, 9, 10, 11, 17:
		return true
	default:
		return false
	}
}

// NewDirectoryNameFromRawDER creates a GeneralName of type directoryName from
// pre-encoded DER bytes (e.g., x509.Certificate.RawSubject). This preserves
// the original encoding (PrintableString vs UTF8String) without re-encoding.
func NewDirectoryNameFromRawDER(rawName []byte) GeneralName {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(tagDirectoryName).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddBytes(rawName)
	})
	raw, _ := b.Bytes()
	return GeneralName{Raw: raw}
}

// Internal cryptobyte helpers

func (a *AlgorithmIdentifier) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		a.marshalInner(b)
	})
}

func (a *AlgorithmIdentifier) marshalInner(b *cryptobyte.Builder) {
	b.AddASN1ObjectIdentifier(a.Algorithm)
	if len(a.Parameters) > 0 {
		b.AddBytes(a.Parameters)
	}
}

func (a *AlgorithmIdentifier) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid AlgorithmIdentifier sequence"}
	}
	return a.unmarshalInner(&seq)
}

func (a *AlgorithmIdentifier) unmarshalInner(seq *cryptobyte.String) error {
	if !seq.ReadASN1ObjectIdentifier(&a.Algorithm) {
		return &ParseError{Detail: "invalid AlgorithmIdentifier OID"}
	}
	if !seq.Empty() {
		// We need to capture the next full ASN.1 element if it's there
		// or the rest of the string if it's already a single element.
		// For parameters, it's usually a single element.
		var params cryptobyte.String
		var tag cbasn1.Tag
		if seq.ReadAnyASN1Element(&params, &tag) {
			a.Parameters = params
		} else {
			a.Parameters = *seq
			*seq = nil
		}
	}
	return nil
}

func (itv *InfoTypeAndValue) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(itv.InfoType)
		if len(itv.InfoValue) > 0 {
			b.AddBytes(itv.InfoValue)
		}
	})
}

func (itv *InfoTypeAndValue) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid InfoTypeAndValue sequence"}
	}
	if !seq.ReadASN1ObjectIdentifier(&itv.InfoType) {
		return &ParseError{Detail: "invalid InfoTypeAndValue OID"}
	}
	// infoValue is ANY DEFINED BY infoType OPTIONAL, so it is one DER element or absent.
	if !seq.Empty() {
		var value cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&value, &tag) {
			return &ParseError{Detail: "invalid InfoTypeAndValue infoValue"}
		}
		if !seq.Empty() {
			return &ParseError{Detail: "trailing data after InfoTypeAndValue infoValue"}
		}
		itv.InfoValue = value
	}
	return nil
}

func (ft *PKIFreeText) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	if len(*ft) == 0 {
		return
	}
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, s := range *ft {
			b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(s))
			})
		}
	})
}

func (ft *PKIFreeText) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PKIFreeText sequence"}
	}
	for !seq.Empty() {
		var utf8 cryptobyte.String
		if !seq.ReadASN1(&utf8, cbasn1.UTF8String) {
			return &ParseError{Detail: "invalid PKIFreeText element"}
		}
		*ft = append(*ft, string(utf8))
	}
	return nil
}

func (gn *GeneralName) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	// If parsed from wire (Raw is set), write back verbatim to preserve encoding.
	if len(gn.Raw) > 0 {
		b.AddBytes(gn.Raw)
		return
	}
	// rfc822Name [1] IMPLICIT IA5String — RFC 5280 §4.2.1.6.
	if gn.RFC822Name != "" {
		b.AddASN1(cbasn1.Tag(tagRFC822Name).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(gn.RFC822Name))
		})
		return
	}
	// directoryName [4] EXPLICIT Name — the [4] tag is explicit because Name is
	// a CHOICE (ASN.1 rule: implicit tagging of a CHOICE becomes explicit).
	// RFC 5280 §4.2.1.6.
	b.AddASN1(cbasn1.Tag(tagDirectoryName).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		marshalRDNSequence(b, gn.DirectoryName)
	})
}

func (gn *GeneralName) unmarshal(s *cryptobyte.String) error {
	// Capture the full element (tag+length+value) for round-tripping.
	var raw cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&raw, &tag) {
		return &ParseError{Detail: "missing GeneralName"}
	}
	gn.Raw = raw

	switch {
	case tag == cbasn1.Tag(tagDirectoryName).ContextSpecific().Constructed():
		// directoryName [4] EXPLICIT Name — parse the RDNSequence.
		inner := cryptobyte.String(gn.Raw)
		var content cryptobyte.String
		if !inner.ReadAnyASN1(&content, &tag) {
			return &ParseError{Detail: "invalid directoryName"}
		}
		return parseRDNSequence(&content, &gn.DirectoryName)

	case tag == cbasn1.Tag(tagRFC822Name).ContextSpecific():
		// rfc822Name [1] IMPLICIT IA5String — read the content bytes as string.
		inner := cryptobyte.String(gn.Raw)
		var content cryptobyte.String
		if !inner.ReadAnyASN1(&content, &tag) {
			return &ParseError{Detail: "invalid rfc822Name"}
		}
		gn.RFC822Name = string(content)
		return nil

	default:
		// Other GeneralName variants are preserved in Raw for round-tripping.
		return nil
	}
}

// marshalRDNSequence encodes a Name as encoding/asn1 does, so a name built from pkix.Name
// values gets the same string types as a certificate crypto/x509 creates from that name.
func marshalRDNSequence(b *cryptobyte.Builder, rdn pkix.RDNSequence) {
	der, err := asn1.Marshal(rdn)
	if err != nil {
		b.SetError(fmt.Errorf("pkicmp: encode directoryName: %w", err))
		return
	}
	b.AddBytes(der)
}

// parseRDNSequence parses a Name (CHOICE rdnSequence RDNSequence).
func parseRDNSequence(s *cryptobyte.String, rdn *pkix.RDNSequence) error {
	// Name ::= CHOICE { rdnSequence RDNSequence }
	// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	var der cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&der, &tag) {
		return &ParseError{Detail: "invalid Name element"}
	}
	_, err := asn1.Unmarshal(der, rdn)
	return err
}

func (c *CMPCertificate) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	// CMPCertificate ::= CHOICE { x509v3PKCert Certificate, ... }
	// x509v3PKCert is Certificate (SEQUENCE).
	b.AddBytes(c.Raw)
}

func (c *CMPCertificate) unmarshal(s *cryptobyte.String) error {
	// CMPCertificate ::= CHOICE { x509v3PKCert Certificate, ... }
	var der cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&der, &tag) {
		return &ParseError{Detail: "invalid CMPCertificate element"}
	}
	c.Raw = der
	return nil
}

// envelopedData per RFC 5652 §6.
type envelopedData struct {
	// Raw contains the DER-encoded envelopedData value (RFC 5652 §6.1).
	Raw []byte
}

func (e *envelopedData) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		e.marshalInner(b)
	})
}

func (e *envelopedData) marshalInner(b *cryptobyte.Builder) {
	// Raw contains the full SEQUENCE, so we need to strip it if we want the inner content.
	content, err := stripSequence(e.Raw)
	if err != nil {
		// If it's not a sequence, assume it's already the inner content.
		b.AddBytes(e.Raw)
		return
	}
	b.AddBytes(content)
}

func (e *envelopedData) unmarshal(s *cryptobyte.String) error {
	var der cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&der, &tag) {
		return &ParseError{Detail: "invalid envelopedData element"}
	}
	e.Raw = der
	return nil
}

func (e *envelopedData) unmarshalInner(s *cryptobyte.String) error {
	// s is the content. We wrap it in a SEQUENCE tag to get valid DER.
	e.Raw = wrapSequence(*s)
	*s = nil
	return nil
}

// encryptedValue per RFC 4211 §2.1.
//
// Deprecated: use envelopedData instead.
type encryptedValue struct {
	// Raw contains the DER-encoded encryptedValue CHOICE value.
	Raw []byte
}

func (e *encryptedValue) marshal(_ *marshalContext, b *cryptobyte.Builder) {
	b.AddBytes(e.Raw)
}

func (e *encryptedValue) unmarshal(s *cryptobyte.String) error {
	var der cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&der, &tag) {
		return &ParseError{Detail: "invalid encryptedValue element"}
	}
	e.Raw = der
	return nil
}

// encryptedKey per RFC 9810 §5.2.2.
//
//	encryptedKey ::= CHOICE {
//	    encryptedValue       encryptedValue,
//	    envelopedData    [0] envelopedData }
type encryptedKey struct {
	// encryptedValue is the legacy CRMF-style encrypted container.
	encryptedValue *encryptedValue
	// envelopedData is the CMS envelopedData-based container.
	envelopedData *envelopedData
}

func (k *encryptedKey) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	if k.envelopedData != nil {
		mctx.MinRequiredPVNO = PVNO3
		// envelopedData [0] envelopedData (IMPLICIT)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			k.envelopedData.marshalInner(b)
		})
	} else if k.encryptedValue != nil {
		k.encryptedValue.marshal(mctx, b)
	}
}

func (k *encryptedKey) unmarshal(s *cryptobyte.String) error {
	if s.Empty() {
		return &ParseError{Detail: "missing encryptedKey"}
	}
	tag := cbasn1.Tag((*s)[0])
	if tag == cbasn1.Tag(0).ContextSpecific().Constructed() {
		var sub cryptobyte.String
		if !s.ReadASN1(&sub, tag) {
			return &ParseError{Detail: "invalid envelopedData tag"}
		}
		k.envelopedData = &envelopedData{}
		return k.envelopedData.unmarshalInner(&sub)
	}
	k.encryptedValue = &encryptedValue{}
	return k.encryptedValue.unmarshal(s)
}

// Helper to strip SEQUENCE tag and length
func stripSequence(der []byte) ([]byte, error) {
	s := cryptobyte.String(der)
	var content cryptobyte.String
	if !s.ReadASN1(&content, cbasn1.SEQUENCE) {
		return nil, &ParseError{Detail: "not a sequence"}
	}
	return content, nil
}

// Helper to wrap content in SEQUENCE tag
func wrapSequence(content []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(content)
	})
	return b.BytesOrPanic()
}

func marshalImplicitInt64(val int64) []byte {
	var b cryptobyte.Builder
	b.AddASN1Int64(val)
	der, _ := b.Bytes()
	// Strip tag 0x02 and length
	s := cryptobyte.String(der)
	var content cryptobyte.String
	s.ReadASN1(&content, cbasn1.INTEGER)
	return content
}

// marshalImplicitBigInt returns the content octets of an INTEGER for use under an implicit tag.
func marshalImplicitBigInt(n *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1BigInt(n)
	der := b.BytesOrPanic()
	s := cryptobyte.String(der)
	var content cryptobyte.String
	s.ReadASN1(&content, cbasn1.INTEGER)
	return content
}

// unmarshalImplicitBigInt decodes the content octets of an implicitly tagged INTEGER, rejecting non-minimal encodings.
func unmarshalImplicitBigInt(content []byte) (*big.Int, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
		b.AddBytes(content)
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	s := cryptobyte.String(der)
	n := new(big.Int)
	if !s.ReadASN1Integer(n) {
		return nil, &ParseError{Detail: "invalid integer"}
	}
	return n, nil
}

func unmarshalImplicitInt64(content []byte) (int64, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
		b.AddBytes(content)
	})
	der, err := b.Bytes()
	if err != nil {
		return 0, err
	}
	s := cryptobyte.String(der)
	var val int64
	if !s.ReadASN1Integer(&val) {
		return 0, &ParseError{Detail: "invalid integer"}
	}
	return val, nil
}
