package pkicmp

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
)

// Info types of the general messages in RFC 9810 §5.3.19 and RFC 9483 §4.3.
// Compare them with [asn1.ObjectIdentifier.Equal] and do not modify them.
var (
	// InfoTypeCurrentCRL asks for the latest CRL (RFC 9810 §5.3.19.6).
	InfoTypeCurrentCRL = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 6}
	// InfoTypeUnsupportedOIDs lists the requested info types a server does not support (RFC 9810 §5.3.19.7).
	InfoTypeUnsupportedOIDs = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 7}
	// InfoTypeCACerts asks for CA certificates (RFC 9483 §4.3.1).
	InfoTypeCACerts = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 17}
	// InfoTypeRootCAKeyUpdate answers a root CA certificate update request (RFC 9483 §4.3.2).
	InfoTypeRootCAKeyUpdate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 18}
	// InfoTypeCertReqTemplate asks for a certificate request template (RFC 9483 §4.3.3).
	InfoTypeCertReqTemplate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 19}
	// InfoTypeRootCACert asks for an update of a root CA certificate (RFC 9483 §4.3.2).
	InfoTypeRootCACert = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 20}
	// InfoTypeCRLStatusList asks for CRLs newer than the ones the client holds (RFC 9483 §4.3.4).
	InfoTypeCRLStatusList = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 22}
	// InfoTypeCRLs answers a CRL update request (RFC 9483 §4.3.4).
	InfoTypeCRLs = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 23}
)

// GenMsgContent per RFC 9810 §5.3.19.
//
//	GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
type GenMsgContent []InfoTypeAndValue

// GenRepContent per RFC 9810 §5.3.20.
//
//	GenRepContent ::= SEQUENCE OF InfoTypeAndValue
type GenRepContent []InfoTypeAndValue

// marshal encodes the general message items.
func (c *GenMsgContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	marshalInfoSequence(mctx, b, *c)
}

// unmarshal decodes the general message items.
func (c *GenMsgContent) unmarshal(s *cryptobyte.String) error {
	items, err := unmarshalInfoSequence(s, "GenMsgContent")
	*c = items
	return err
}

// marshal encodes the general response items.
func (c *GenRepContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	marshalInfoSequence(mctx, b, *c)
}

// unmarshal decodes the general response items.
func (c *GenRepContent) unmarshal(s *cryptobyte.String) error {
	items, err := unmarshalInfoSequence(s, "GenRepContent")
	*c = items
	return err
}

// marshalInfoSequence encodes a SEQUENCE OF InfoTypeAndValue.
func marshalInfoSequence(mctx *marshalContext, b *cryptobyte.Builder, items []InfoTypeAndValue) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := range items {
			items[i].marshal(mctx, b)
		}
	})
}

// unmarshalInfoSequence decodes a SEQUENCE OF InfoTypeAndValue that must fill s.
func unmarshalInfoSequence(s *cryptobyte.String, name string) ([]InfoTypeAndValue, error) {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, &ParseError{Detail: "invalid " + name}
	}
	items := []InfoTypeAndValue{}
	for !seq.Empty() {
		var item InfoTypeAndValue
		if err := item.unmarshal(&seq); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// checkInfoType reports an error when itav does not carry the expected info type.
func checkInfoType(itav InfoTypeAndValue, want asn1.ObjectIdentifier) error {
	if !itav.InfoType.Equal(want) {
		return &ParseError{Detail: fmt.Sprintf("info type %s, want %s", itav.InfoType, want)}
	}
	return nil
}

// infoValueSequence returns the content of an infoValue that must be one SEQUENCE.
func infoValueSequence(itav InfoTypeAndValue, name string) (cryptobyte.String, error) {
	s := cryptobyte.String(itav.InfoValue)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, &ParseError{Detail: "invalid " + name}
	}
	return seq, nil
}

// NewCACertsInfo answers a CA certificates request (RFC 9483 §4.3.1). Without
// certificates the infoValue is absent, which tells the client none are available.
func NewCACertsInfo(certs []*x509.Certificate) InfoTypeAndValue {
	itav := InfoTypeAndValue{InfoType: InfoTypeCACerts}
	if len(certs) == 0 {
		return itav
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, cert := range certs {
			b.AddBytes(cert.Raw)
		}
	})
	itav.InfoValue = b.BytesOrPanic()
	return itav
}

// ParseCACertsInfo returns the certificates of a CA certificates response. An
// absent infoValue yields no certificates and no error.
func ParseCACertsInfo(itav InfoTypeAndValue) ([]*x509.Certificate, error) {
	if err := checkInfoType(itav, InfoTypeCACerts); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	seq, err := infoValueSequence(itav, "CA certificates")
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificateSequence(seq)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, &ParseError{Detail: "CA certificates value is empty"}
	}
	return certs, nil
}

// parseCertificateSequence parses every certificate element in seq.
func parseCertificateSequence(seq cryptobyte.String) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for !seq.Empty() {
		var elem cryptobyte.String
		if !seq.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
			return nil, &ParseError{Detail: "invalid certificate element"}
		}
		cert, err := x509.ParseCertificate(elem)
		if err != nil {
			return nil, &ParseError{Detail: "invalid certificate", Err: err}
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// NewRootCACertInfo requests an update of oldRoot (RFC 9483 §4.3.2). A nil
// oldRoot leaves the infoValue absent, which RFC 9810 §5.3.19.15 permits when
// the server can tell which root the client means.
func NewRootCACertInfo(oldRoot *x509.Certificate) InfoTypeAndValue {
	itav := InfoTypeAndValue{InfoType: InfoTypeRootCACert}
	if oldRoot != nil {
		itav.InfoValue = bytes.Clone(oldRoot.Raw)
	}
	return itav
}

// ParseRootCACertInfo returns the root CA certificate a client asks to update,
// or nil when the request does not name one.
func ParseRootCACertInfo(itav InfoTypeAndValue) (*x509.Certificate, error) {
	if err := checkInfoType(itav, InfoTypeRootCACert); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(itav.InfoValue)
	if err != nil {
		return nil, &ParseError{Detail: "invalid root CA certificate", Err: err}
	}
	return cert, nil
}

// RootCAKeyUpdate per RFC 9810 §5.3.19.15.
//
//	RootCaKeyUpdateContent ::= SEQUENCE {
//	    newWithNew       CMPCertificate,
//	    newWithOld   [0] CMPCertificate OPTIONAL,
//	    oldWithNew   [1] CMPCertificate OPTIONAL }
type RootCAKeyUpdate struct {
	// NewWithNew is the new self-signed root CA certificate.
	NewWithNew *x509.Certificate
	// NewWithOld certifies the new root key under the old one, which lets a
	// client that trusts the old root accept the new one. RFC 9483 §4.3.2
	// requires it in a response.
	NewWithOld *x509.Certificate
	// OldWithNew certifies the old root key under the new one, for entities
	// that trust only the new root.
	OldWithNew *x509.Certificate
}

// NewRootCAKeyUpdateInfo answers a root CA certificate update request (RFC
// 9483 §4.3.2). A nil update leaves the infoValue absent, which tells the
// client that no update is available.
func NewRootCAKeyUpdateInfo(update *RootCAKeyUpdate) (InfoTypeAndValue, error) {
	itav := InfoTypeAndValue{InfoType: InfoTypeRootCAKeyUpdate}
	if update == nil {
		return itav, nil
	}
	if update.NewWithNew == nil {
		return InfoTypeAndValue{}, errors.New("pkicmp: root CA key update requires newWithNew")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(update.NewWithNew.Raw)
		// The CMP module uses explicit tags, so each context tag wraps a whole certificate.
		if update.NewWithOld != nil {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(update.NewWithOld.Raw)
			})
		}
		if update.OldWithNew != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(update.OldWithNew.Raw)
			})
		}
	})
	value, err := b.Bytes()
	if err != nil {
		return InfoTypeAndValue{}, err
	}
	itav.InfoValue = value
	return itav, nil
}

// ParseRootCAKeyUpdateInfo returns the content of a root CA key update
// response, or nil when the server has no update. Call
// [RootCAKeyUpdate.Verify] before trusting the new root.
func ParseRootCAKeyUpdateInfo(itav InfoTypeAndValue) (*RootCAKeyUpdate, error) {
	if err := checkInfoType(itav, InfoTypeRootCAKeyUpdate); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	seq, err := infoValueSequence(itav, "RootCaKeyUpdateContent")
	if err != nil {
		return nil, err
	}
	var newWithNew cryptobyte.String
	if !seq.ReadASN1Element(&newWithNew, cbasn1.SEQUENCE) {
		return nil, &ParseError{Detail: "invalid newWithNew"}
	}
	update := &RootCAKeyUpdate{}
	if update.NewWithNew, err = x509.ParseCertificate(newWithNew); err != nil {
		return nil, &ParseError{Detail: "invalid newWithNew", Err: err}
	}
	if update.NewWithOld, err = parseTaggedCertificate(&seq, 0, "newWithOld"); err != nil {
		return nil, err
	}
	if update.OldWithNew, err = parseTaggedCertificate(&seq, 1, "oldWithNew"); err != nil {
		return nil, err
	}
	if !seq.Empty() {
		return nil, &ParseError{Detail: "trailing data in RootCaKeyUpdateContent"}
	}
	return update, nil
}

// parseTaggedCertificate reads an optional certificate under an explicit context tag.
func parseTaggedCertificate(seq *cryptobyte.String, tag uint8, name string) (*x509.Certificate, error) {
	var content cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&content, &present, cbasn1.Tag(tag).ContextSpecific().Constructed()) {
		return nil, &ParseError{Detail: "invalid " + name}
	}
	if !present {
		return nil, nil
	}
	var elem cryptobyte.String
	if !content.ReadASN1Element(&elem, cbasn1.SEQUENCE) || !content.Empty() {
		return nil, &ParseError{Detail: "invalid " + name}
	}
	cert, err := x509.ParseCertificate(elem)
	if err != nil {
		return nil, &ParseError{Detail: "invalid " + name, Err: err}
	}
	return cert, nil
}

// Verify checks the update as RFC 4210 §4.4 describes for an entity that
// trusts oldRoot. NewWithNew must be self-signed. NewWithOld must carry the
// key of NewWithNew under its name and be signed by oldRoot. A present
// OldWithNew must carry the key of oldRoot and be signed by the new key. A nil
// oldRoot checks only NewWithNew, which gives the caller no reason to trust it.
//
// Verify checks signatures and keys only. The caller decides about validity
// periods and whether oldRoot is still a trust anchor.
func (u *RootCAKeyUpdate) Verify(oldRoot *x509.Certificate) error {
	if u == nil || u.NewWithNew == nil {
		return errors.New("pkicmp: root CA key update has no newWithNew")
	}
	if err := slhdsasig.CheckSignatureFrom(u.NewWithNew, u.NewWithNew); err != nil {
		return fmt.Errorf("pkicmp: newWithNew is not self-signed: %w", err)
	}
	if oldRoot == nil {
		return nil
	}
	if u.NewWithOld == nil {
		return errors.New("pkicmp: root CA key update has no newWithOld")
	}
	if !bytes.Equal(u.NewWithOld.RawSubjectPublicKeyInfo, u.NewWithNew.RawSubjectPublicKeyInfo) {
		return errors.New("pkicmp: newWithOld does not carry the key of newWithNew")
	}
	if !bytes.Equal(u.NewWithOld.RawSubject, u.NewWithNew.RawSubject) {
		return errors.New("pkicmp: newWithOld does not name the subject of newWithNew")
	}
	if err := slhdsasig.CheckSignatureFrom(u.NewWithOld, oldRoot); err != nil {
		return fmt.Errorf("pkicmp: newWithOld is not signed by the old root: %w", err)
	}
	if u.OldWithNew != nil {
		if !bytes.Equal(u.OldWithNew.RawSubjectPublicKeyInfo, oldRoot.RawSubjectPublicKeyInfo) {
			return errors.New("pkicmp: oldWithNew does not carry the key of the old root")
		}
		if err := slhdsasig.CheckSignatureFrom(u.OldWithNew, u.NewWithNew); err != nil {
			return fmt.Errorf("pkicmp: oldWithNew is not signed by the new root: %w", err)
		}
	}
	return nil
}

// CertReqTemplate per RFC 9810 §5.3.19.16.
//
//	CertReqTemplateContent ::= SEQUENCE {
//	    certTemplate           CertTemplate,
//	    keySpec                Controls OPTIONAL }
type CertReqTemplate struct {
	// Template holds the fields the client should request. RFC 9483 §4.3.3
	// forbids publicKey and serialNumber in it.
	Template CertTemplate
	// KeySpec lists acceptable key types, one id-regCtrl-algId or
	// id-regCtrl-rsaKeyLen control per type.
	KeySpec []AttributeTypeAndValue
}

// NewCertReqTemplateInfo answers a certificate request template request (RFC
// 9483 §4.3.3). A nil template leaves the infoValue absent, which tells the
// client that the PKI imposes no requirements.
func NewCertReqTemplateInfo(t *CertReqTemplate) (InfoTypeAndValue, error) {
	itav := InfoTypeAndValue{InfoType: InfoTypeCertReqTemplate}
	if t == nil {
		return itav, nil
	}
	if len(t.Template.PublicKey) > 0 || t.Template.SerialNumber != nil {
		return InfoTypeAndValue{}, errors.New("pkicmp: certificate request template must not carry publicKey or serialNumber")
	}
	mctx := &marshalContext{MinRequiredPVNO: PVNO2}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		t.Template.marshal(mctx, b)
		if len(t.KeySpec) > 0 {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for i := range t.KeySpec {
					t.KeySpec[i].marshal(mctx, b)
				}
			})
		}
	})
	value, err := b.Bytes()
	if err != nil {
		return InfoTypeAndValue{}, err
	}
	itav.InfoValue = value
	return itav, nil
}

// ParseCertReqTemplateInfo returns the template of a certificate request
// template response, or nil when the PKI imposes no requirements.
func ParseCertReqTemplateInfo(itav InfoTypeAndValue) (*CertReqTemplate, error) {
	if err := checkInfoType(itav, InfoTypeCertReqTemplate); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	seq, err := infoValueSequence(itav, "CertReqTemplateContent")
	if err != nil {
		return nil, err
	}
	t := &CertReqTemplate{}
	if err := t.Template.unmarshal(&seq); err != nil {
		return nil, err
	}
	var keySpec cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&keySpec, &present, cbasn1.SEQUENCE) || !seq.Empty() {
		return nil, &ParseError{Detail: "invalid keySpec"}
	}
	for !keySpec.Empty() {
		var control AttributeTypeAndValue
		if err := control.unmarshal(&keySpec); err != nil {
			return nil, err
		}
		t.KeySpec = append(t.KeySpec, control)
	}
	if present && len(t.KeySpec) == 0 {
		return nil, &ParseError{Detail: "keySpec is empty"}
	}
	return t, nil
}

// CRLSource per RFC 9810 §5.3.19.17 names the CRL a client asks for.
//
//	CRLSource ::= CHOICE {
//	    dpn          [0] DistributionPointName,
//	    issuer       [1] GeneralNames }
type CRLSource struct {
	// DistributionPoint is the DER DistributionPointName of RFC 5280
	// §4.2.1.13 when the client names a distribution point.
	DistributionPoint []byte
	// Issuer names the CA that issues the CRL when DistributionPoint is
	// empty. RFC 9483 §4.3.4 sends one directoryName.
	Issuer []GeneralName
}

// NewCRLDistributionPointSource names a CRL by the URIs of its distribution point.
func NewCRLDistributionPointSource(uris ...string) CRLSource {
	var b cryptobyte.Builder
	// fullName [0] IMPLICIT GeneralNames holding uniformResourceIdentifier [6] IMPLICIT IA5String entries.
	b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		for _, uri := range uris {
			b.AddASN1(cbasn1.Tag(tagURI).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(uri))
			})
		}
	})
	return CRLSource{DistributionPoint: b.BytesOrPanic()}
}

// NewCRLIssuerSource names a CRL by its issuer, given as a DER Name such as
// [x509.Certificate.RawSubject] of the CA.
func NewCRLIssuerSource(rawIssuer []byte) CRLSource {
	return CRLSource{Issuer: []GeneralName{NewDirectoryNameFromRawDER(rawIssuer)}}
}

// IsZero reports whether the source names no CRL, which asks for the current
// CRL of the CA's choice (RFC 9810 §5.3.19.6).
func (s CRLSource) IsZero() bool {
	return len(s.DistributionPoint) == 0 && len(s.Issuer) == 0
}

// distributionPointNames returns the GeneralNames in the fullName of the
// distribution point. A relative name or a malformed value yields nothing.
func (s CRLSource) distributionPointNames() []GeneralName {
	dpn := cryptobyte.String(s.DistributionPoint)
	var fullName cryptobyte.String
	if !dpn.ReadASN1(&fullName, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil
	}
	var names []GeneralName
	for !fullName.Empty() {
		var name GeneralName
		if name.unmarshal(&fullName) != nil {
			return nil
		}
		names = append(names, name)
	}
	return names
}

// DistributionPointURIs returns the URIs in the fullName of the distribution point.
func (s CRLSource) DistributionPointURIs() []string {
	var uris []string
	for _, name := range s.distributionPointNames() {
		raw := cryptobyte.String(name.Raw)
		var uri cryptobyte.String
		if raw.ReadASN1(&uri, cbasn1.Tag(tagURI).ContextSpecific()) {
			uris = append(uris, string(uri))
		}
	}
	return uris
}

// DirectoryNames returns the DER Names of the directoryName entries in the
// issuer or in the fullName of the distribution point, for comparison with a
// CA's RawSubject. RFC 9483 §4.3.4 names the issuer when no distribution point
// is known, and clients that hold a CRL without an issuingDistributionPoint
// put its issuer in the fullName instead.
func (s CRLSource) DirectoryNames() [][]byte {
	var names [][]byte
	for _, name := range append(s.distributionPointNames(), s.Issuer...) {
		if der, ok := directoryNameDER(generalNameDER(&name)); ok {
			names = append(names, der)
		}
	}
	return names
}

// CRLStatus per RFC 9810 §5.3.19.17.
//
//	CRLStatus ::= SEQUENCE {
//	    source       CRLSource,
//	    thisUpdate   Time OPTIONAL }
type CRLStatus struct {
	// Source names the requested CRL.
	Source CRLSource
	// ThisUpdate is the thisUpdate time of the newest CRL the client holds
	// from Source. The zero time means it holds none.
	ThisUpdate time.Time
}

// NewCRLStatusListInfo asks for CRLs newer than the ones the client holds (RFC 9483 §4.3.4, which sends one status).
func NewCRLStatusListInfo(statuses ...CRLStatus) (InfoTypeAndValue, error) {
	if len(statuses) == 0 {
		return InfoTypeAndValue{}, errors.New("pkicmp: CRL status list requires at least one status")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, status := range statuses {
			status.marshal(b)
		}
	})
	value, err := b.Bytes()
	if err != nil {
		return InfoTypeAndValue{}, err
	}
	return InfoTypeAndValue{InfoType: InfoTypeCRLStatusList, InfoValue: value}, nil
}

// marshal encodes one CRLStatus.
func (c *CRLStatus) marshal(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// The CMP module uses explicit tags, so each source choice wraps its value.
		switch {
		case len(c.Source.DistributionPoint) > 0:
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(c.Source.DistributionPoint)
			})
		case len(c.Source.Issuer) > 0:
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for i := range c.Source.Issuer {
						c.Source.Issuer[i].marshal(nil, b)
					}
				})
			})
		default:
			b.SetError(errors.New("pkicmp: CRL status requires a distribution point or an issuer"))
			return
		}
		if !c.ThisUpdate.IsZero() {
			addTime(b, c.ThisUpdate)
		}
	})
}

// addTime encodes a Time as RFC 5280 §4.1.2.5 requires: UTCTime through 2049 and GeneralizedTime from 2050.
func addTime(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC()
	if t.Year() < 2050 {
		b.AddASN1UTCTime(t)
		return
	}
	b.AddASN1GeneralizedTime(t)
}

// readTime reads a Time of RFC 5280 §4.1, a UTCTime or a GeneralizedTime, and reports whether it was valid.
func readTime(s *cryptobyte.String, t *time.Time) bool {
	switch {
	case s.PeekASN1Tag(cbasn1.UTCTime):
		return s.ReadASN1UTCTime(t)
	case s.PeekASN1Tag(cbasn1.GeneralizedTime):
		return s.ReadASN1GeneralizedTime(t)
	default:
		return false
	}
}

// ParseCRLStatusListInfo returns the CRL statuses of a CRL update request. RFC
// 9810 requires at least one, so an absent or empty value is an error.
func ParseCRLStatusListInfo(itav InfoTypeAndValue) ([]CRLStatus, error) {
	if err := checkInfoType(itav, InfoTypeCRLStatusList); err != nil {
		return nil, err
	}
	seq, err := infoValueSequence(itav, "CRL status list")
	if err != nil {
		return nil, err
	}
	var statuses []CRLStatus
	for !seq.Empty() {
		var status CRLStatus
		if err := status.unmarshal(&seq); err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	if len(statuses) == 0 {
		return nil, &ParseError{Detail: "CRL status list is empty"}
	}
	return statuses, nil
}

// unmarshal decodes one CRLStatus.
func (c *CRLStatus) unmarshal(s *cryptobyte.String) error {
	var seq, source cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadAnyASN1(&source, &tag) {
		return &ParseError{Detail: "invalid CRLStatus"}
	}
	switch tag {
	case cbasn1.Tag(0).ContextSpecific().Constructed():
		var dpn cryptobyte.String
		var dpnTag cbasn1.Tag
		if !source.ReadAnyASN1Element(&dpn, &dpnTag) || !source.Empty() {
			return &ParseError{Detail: "invalid CRL distribution point name"}
		}
		// fullName [0] or nameRelativeToCRLIssuer [1] (RFC 5280 §4.2.1.13).
		fullName, relative := cbasn1.Tag(0).ContextSpecific().Constructed(), cbasn1.Tag(1).ContextSpecific().Constructed()
		if dpnTag != fullName && dpnTag != relative {
			return &ParseError{Detail: "invalid CRL distribution point name"}
		}
		c.Source.DistributionPoint = dpn
	case cbasn1.Tag(1).ContextSpecific().Constructed():
		var names cryptobyte.String
		if !source.ReadASN1(&names, cbasn1.SEQUENCE) || !source.Empty() || names.Empty() {
			return &ParseError{Detail: "invalid CRL issuer"}
		}
		for !names.Empty() {
			var name GeneralName
			if err := name.unmarshal(&names); err != nil {
				return err
			}
			c.Source.Issuer = append(c.Source.Issuer, name)
		}
	default:
		return &ParseError{Detail: "invalid CRL source"}
	}
	if seq.Empty() {
		return nil
	}
	var ok bool
	switch {
	case seq.PeekASN1Tag(cbasn1.UTCTime):
		ok = seq.ReadASN1UTCTime(&c.ThisUpdate)
	case seq.PeekASN1Tag(cbasn1.GeneralizedTime):
		ok = seq.ReadASN1GeneralizedTime(&c.ThisUpdate)
	default:
	}
	if !ok {
		return &ParseError{Detail: "invalid CRLStatus thisUpdate"}
	}
	if !seq.Empty() {
		return &ParseError{Detail: "trailing data in CRLStatus"}
	}
	return nil
}

// NewCRLsInfo answers a CRL update request (RFC 9483 §4.3.4). Without CRLs the
// infoValue is absent, which tells the client that no newer CRL is available.
func NewCRLsInfo(crls []*x509.RevocationList) InfoTypeAndValue {
	itav := InfoTypeAndValue{InfoType: InfoTypeCRLs}
	if len(crls) == 0 {
		return itav
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, crl := range crls {
			b.AddBytes(crl.Raw)
		}
	})
	itav.InfoValue = b.BytesOrPanic()
	return itav
}

// ParseCRLsInfo returns the CRLs of a CRL update response. An absent infoValue
// yields no CRLs and no error. The caller verifies each CRL's signature.
func ParseCRLsInfo(itav InfoTypeAndValue) ([]*x509.RevocationList, error) {
	if err := checkInfoType(itav, InfoTypeCRLs); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	seq, err := infoValueSequence(itav, "CRLs")
	if err != nil {
		return nil, err
	}
	var crls []*x509.RevocationList
	for !seq.Empty() {
		var elem cryptobyte.String
		if !seq.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
			return nil, &ParseError{Detail: "invalid CRL element"}
		}
		crl, err := x509.ParseRevocationList(elem)
		if err != nil {
			return nil, &ParseError{Detail: "invalid CRL", Err: err}
		}
		crls = append(crls, crl)
	}
	if len(crls) == 0 {
		return nil, &ParseError{Detail: "CRLs value is empty"}
	}
	return crls, nil
}

// NewCurrentCRLInfo answers a current CRL request (RFC 9810 §5.3.19.6). A nil
// crl leaves the infoValue absent.
func NewCurrentCRLInfo(crl *x509.RevocationList) InfoTypeAndValue {
	itav := InfoTypeAndValue{InfoType: InfoTypeCurrentCRL}
	if crl != nil {
		itav.InfoValue = bytes.Clone(crl.Raw)
	}
	return itav
}

// ParseCurrentCRLInfo returns the CRL of a current CRL response, or nil when the value is absent.
func ParseCurrentCRLInfo(itav InfoTypeAndValue) (*x509.RevocationList, error) {
	if err := checkInfoType(itav, InfoTypeCurrentCRL); err != nil {
		return nil, err
	}
	if len(itav.InfoValue) == 0 {
		return nil, nil
	}
	crl, err := x509.ParseRevocationList(itav.InfoValue)
	if err != nil {
		return nil, &ParseError{Detail: "invalid CRL", Err: err}
	}
	return crl, nil
}

// NewUnsupportedOIDsInfo lists requested info types the server does not support (RFC 9810 §5.3.19.7).
func NewUnsupportedOIDsInfo(oids ...asn1.ObjectIdentifier) InfoTypeAndValue {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, oid := range oids {
			b.AddASN1ObjectIdentifier(oid)
		}
	})
	return InfoTypeAndValue{InfoType: InfoTypeUnsupportedOIDs, InfoValue: b.BytesOrPanic()}
}

// ParseUnsupportedOIDsInfo returns the info types a server reported as unsupported.
func ParseUnsupportedOIDsInfo(itav InfoTypeAndValue) ([]asn1.ObjectIdentifier, error) {
	if err := checkInfoType(itav, InfoTypeUnsupportedOIDs); err != nil {
		return nil, err
	}
	seq, err := infoValueSequence(itav, "unsupported OIDs")
	if err != nil {
		return nil, err
	}
	var oids []asn1.ObjectIdentifier
	for !seq.Empty() {
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&oid) {
			return nil, &ParseError{Detail: "invalid unsupported OID"}
		}
		oids = append(oids, oid)
	}
	return oids, nil
}
