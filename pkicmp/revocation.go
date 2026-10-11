package pkicmp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// oidCRLReason identifies the RFC 5280 §5.3.1 reasonCode CRL entry extension.
var oidCRLReason = asn1.ObjectIdentifier{2, 5, 29, 21}

// CRLReason is the RFC 5280 §5.3.1 reason code requested for a revocation.
type CRLReason int

// CRL reason codes per RFC 5280 §5.3.1. Value 7 is not assigned.
const (
	CRLReasonUnspecified          CRLReason = 0
	CRLReasonKeyCompromise        CRLReason = 1
	CRLReasonCACompromise         CRLReason = 2
	CRLReasonAffiliationChanged   CRLReason = 3
	CRLReasonSuperseded           CRLReason = 4
	CRLReasonCessationOfOperation CRLReason = 5
	CRLReasonCertificateHold      CRLReason = 6
	// CRLReasonRemoveFromCRL asks the CA to release a certificate from hold.
	CRLReasonRemoveFromCRL      CRLReason = 8
	CRLReasonPrivilegeWithdrawn CRLReason = 9
	CRLReasonAACompromise       CRLReason = 10
)

// String returns the RFC 5280 name of the reason code.
func (r CRLReason) String() string {
	switch r {
	case CRLReasonUnspecified:
		return "unspecified"
	case CRLReasonKeyCompromise:
		return "keyCompromise"
	case CRLReasonCACompromise:
		return "cACompromise"
	case CRLReasonAffiliationChanged:
		return "affiliationChanged"
	case CRLReasonSuperseded:
		return "superseded"
	case CRLReasonCessationOfOperation:
		return "cessationOfOperation"
	case CRLReasonCertificateHold:
		return "certificateHold"
	case CRLReasonRemoveFromCRL:
		return "removeFromCRL"
	case CRLReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case CRLReasonAACompromise:
		return "aACompromise"
	default:
		return fmt.Sprintf("CRLReason(%d)", int(r))
	}
}

// Valid reports whether r is a reason code defined by RFC 5280.
func (r CRLReason) Valid() bool {
	return r >= CRLReasonUnspecified && r <= CRLReasonAACompromise && r != 7
}

// RevReqContent per RFC 9810 §5.3.9.
//
//	RevReqContent ::= SEQUENCE OF RevDetails
type RevReqContent []RevDetails

// marshal encodes the revocation request list.
func (c *RevReqContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := range *c {
			(*c)[i].marshal(mctx, b)
		}
	})
}

// unmarshal decodes the revocation request list.
func (c *RevReqContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid RevReqContent sequence"}
	}
	for !seq.Empty() {
		var details RevDetails
		if err := details.unmarshal(&seq); err != nil {
			return err
		}
		*c = append(*c, details)
	}
	return nil
}

// RevDetails per RFC 9810 §5.3.9.
//
//	RevDetails ::= SEQUENCE {
//	    certDetails         CertTemplate,
//	    crlEntryDetails     Extensions       OPTIONAL }
type RevDetails struct {
	// CertDetails identifies the certificate to revoke. RFC 9483 §4.2 requires
	// its SerialNumber and Issuer.
	CertDetails     CertTemplate
	CRLEntryDetails []byte // Raw DER Extensions requested for the CRL entry
}

// NewRevDetails identifies a certificate by issuer and serial number and
// requests the given reason code, as RFC 9483 §4.2 requires.
func NewRevDetails(cert *x509.Certificate, reason CRLReason) (RevDetails, error) {
	if cert == nil {
		return RevDetails{}, fmt.Errorf("pkicmp: revocation certificate is nil")
	}
	if cert.SerialNumber == nil {
		return RevDetails{}, fmt.Errorf("pkicmp: revocation certificate serial number is nil")
	}
	if !reason.Valid() {
		return RevDetails{}, fmt.Errorf("pkicmp: invalid CRL reason %d", int(reason))
	}

	// The issuer is sent as the certificate encoded it, since a CA may locate
	// the certificate by comparing the name bytes.
	issuer := cert.RawIssuer
	if len(issuer) == 0 {
		var err error
		if issuer, err = asn1.Marshal(toFullRDNSequence(cert.Issuer)); err != nil {
			return RevDetails{}, fmt.Errorf("pkicmp: encode revocation issuer: %w", err)
		}
	}

	reasonValue, err := asn1.Marshal(asn1.Enumerated(reason))
	if err != nil {
		return RevDetails{}, fmt.Errorf("pkicmp: encode CRL reason: %w", err)
	}
	crlEntryDetails, err := asn1.Marshal([]pkix.Extension{{Id: oidCRLReason, Value: reasonValue}})
	if err != nil {
		return RevDetails{}, fmt.Errorf("pkicmp: encode crlEntryDetails: %w", err)
	}

	return RevDetails{
		CertDetails: CertTemplate{
			SerialNumber: new(big.Int).Set(cert.SerialNumber),
			Issuer:       issuer,
		},
		CRLEntryDetails: crlEntryDetails,
	}, nil
}

// CRLEntryExtensions parses the extensions requested for the CRL entry.
func (d *RevDetails) CRLEntryExtensions() ([]pkix.Extension, error) {
	if len(d.CRLEntryDetails) == 0 {
		return nil, nil
	}
	var exts []pkix.Extension
	rest, err := asn1.Unmarshal(d.CRLEntryDetails, &exts)
	if err != nil {
		return nil, &ParseError{Detail: "invalid crlEntryDetails", Err: err}
	}
	if len(rest) > 0 {
		return nil, &ParseError{Detail: "trailing data in crlEntryDetails"}
	}
	return exts, nil
}

// marshal encodes one RevDetails.
func (d *RevDetails) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		d.CertDetails.marshal(mctx, b)
		if len(d.CRLEntryDetails) > 0 {
			if !isSingleElement(d.CRLEntryDetails, cbasn1.SEQUENCE) {
				b.SetError(fmt.Errorf("pkicmp: invalid crlEntryDetails DER"))
				return
			}
			b.AddBytes(d.CRLEntryDetails)
		}
	})
}

// unmarshal decodes one RevDetails.
func (d *RevDetails) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid RevDetails sequence"}
	}
	if err := d.CertDetails.unmarshal(&seq); err != nil {
		return err
	}
	if !seq.Empty() {
		var exts cryptobyte.String
		if !seq.ReadASN1Element(&exts, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid crlEntryDetails sequence"}
		}
		d.CRLEntryDetails = exts
	}
	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in RevDetails"}
	}
	return nil
}

// RevRepContent per RFC 9810 §5.3.10.
//
//	RevRepContent ::= SEQUENCE {
//	    status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
//	    revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
//	    crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL }
type RevRepContent struct {
	// Status holds one result per requested revocation, in request order.
	Status []PKIStatusInfo
	// RevCerts optionally identifies the certificates, in the same order as Status.
	RevCerts []CertID
	// CRLs holds optional DER CertificateList values resulting from the revocation.
	CRLs [][]byte
}

// marshal encodes the revocation response.
func (c *RevRepContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for i := range c.Status {
				c.Status[i].marshal(mctx, b)
			}
		})
		if len(c.RevCerts) > 0 {
			// revCerts [0] is EXPLICIT because the CMP module uses explicit tagging.
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for i := range c.RevCerts {
						c.RevCerts[i].marshal(mctx, b)
					}
				})
			})
		}
		if len(c.CRLs) > 0 {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, crl := range c.CRLs {
						if !isSingleElement(crl, cbasn1.SEQUENCE) {
							b.SetError(fmt.Errorf("pkicmp: invalid CertificateList DER"))
							return
						}
						b.AddBytes(crl)
					}
				})
			})
		}
	})
}

// unmarshal decodes the revocation response.
func (c *RevRepContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid RevRepContent sequence"}
	}

	var statusSeq cryptobyte.String
	if !seq.ReadASN1(&statusSeq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid RevRepContent status sequence"}
	}
	for !statusSeq.Empty() {
		var si PKIStatusInfo
		if err := si.unmarshal(&statusSeq); err != nil {
			return err
		}
		c.Status = append(c.Status, si)
	}

	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var tagged, certIDs cryptobyte.String
		if !seq.ReadASN1(&tagged, cbasn1.Tag(0).ContextSpecific().Constructed()) ||
			!tagged.ReadASN1(&certIDs, cbasn1.SEQUENCE) || !tagged.Empty() {
			return &ParseError{Detail: "invalid revCerts"}
		}
		for !certIDs.Empty() {
			var id CertID
			if err := id.unmarshal(&certIDs); err != nil {
				return err
			}
			c.RevCerts = append(c.RevCerts, id)
		}
	}

	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var tagged, crls cryptobyte.String
		if !seq.ReadASN1(&tagged, cbasn1.Tag(1).ContextSpecific().Constructed()) ||
			!tagged.ReadASN1(&crls, cbasn1.SEQUENCE) || !tagged.Empty() {
			return &ParseError{Detail: "invalid crls"}
		}
		for !crls.Empty() {
			var crl cryptobyte.String
			if !crls.ReadASN1Element(&crl, cbasn1.SEQUENCE) {
				return &ParseError{Detail: "invalid CertificateList"}
			}
			c.CRLs = append(c.CRLs, crl)
		}
	}

	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in RevRepContent"}
	}
	return nil
}

// CertID per RFC 4211 §6.5.
//
//	CertId ::= SEQUENCE {
//	    issuer           GeneralName,
//	    serialNumber     INTEGER }
type CertID struct {
	// Issuer names the CA that issued the certificate.
	Issuer GeneralName
	// SerialNumber identifies the certificate within Issuer.
	SerialNumber *big.Int
}

// marshal encodes one CertID.
func (id *CertID) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if id.SerialNumber == nil {
			b.SetError(fmt.Errorf("pkicmp: CertId serial number is nil"))
			return
		}
		id.Issuer.marshal(mctx, b)
		b.AddASN1BigInt(id.SerialNumber)
	})
}

// Identifies reports whether id names cert by serial number and issuer. The
// issuer must be a directoryName. Names are compared by their decoded
// attributes, so string types may differ, as in the sender check of
// [PKIMessage.Verify].
func (id *CertID) Identifies(cert *x509.Certificate) bool {
	if id == nil || cert == nil || id.SerialNumber == nil || cert.SerialNumber == nil ||
		id.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}
	issuer := id.Issuer
	// A directoryName built with NewDirectoryNameFromRawDER holds only Raw.
	if len(issuer.DirectoryName) == 0 && len(issuer.Raw) > 0 {
		raw := cryptobyte.String(issuer.Raw)
		if err := issuer.unmarshal(&raw); err != nil || !raw.Empty() {
			return false
		}
	}
	if len(issuer.DirectoryName) == 0 {
		return false
	}
	var certIssuer pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawIssuer, &certIssuer); err != nil || len(rest) > 0 {
		return false
	}
	return issuer.DirectoryName.String() == certIssuer.String()
}

// unmarshal decodes one CertID.
func (id *CertID) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertId sequence"}
	}
	if err := id.Issuer.unmarshal(&seq); err != nil {
		return err
	}
	id.SerialNumber = new(big.Int)
	if !seq.ReadASN1Integer(id.SerialNumber) {
		return &ParseError{Detail: "invalid CertId serialNumber"}
	}
	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in CertId"}
	}
	return nil
}

// isSingleElement reports whether der is exactly one complete ASN.1 element with the given tag.
func isSingleElement(der []byte, tag cbasn1.Tag) bool {
	s := cryptobyte.String(der)
	var element cryptobyte.String
	return s.ReadASN1Element(&element, tag) && s.Empty()
}
