package pkicmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// revocationTestCertificate returns a certificate whose issuer is encoded as a PrintableString.
func revocationTestCertificate(t *testing.T, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Revocation Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// RFC 5280 §5.3.1 reason codes.
func TestCRLReason(t *testing.T) {
	assert.Equal(t, "keyCompromise", CRLReasonKeyCompromise.String())
	assert.Equal(t, "removeFromCRL", CRLReasonRemoveFromCRL.String())
	assert.Equal(t, "CRLReason(7)", CRLReason(7).String())

	for _, r := range []CRLReason{0, 1, 2, 3, 4, 5, 6, 8, 9, 10} {
		assert.True(t, r.Valid(), "reason %d", r)
	}
	for _, r := range []CRLReason{-1, 7, 11} {
		assert.False(t, r.Valid(), "reason %d", r)
	}
}

// RFC 9483 §4.2 requires serialNumber, issuer and one reasonCode.
func TestNewRevDetails(t *testing.T) {
	cert := revocationTestCertificate(t, big.NewInt(4242))

	details, err := NewRevDetails(cert, CRLReasonKeyCompromise)
	require.NoError(t, err)
	assert.Equal(t, 0, details.CertDetails.SerialNumber.Cmp(cert.SerialNumber))
	assert.Equal(t, cert.RawIssuer, details.CertDetails.Issuer, "the issuer must keep the certificate's encoding")
	assert.Empty(t, details.CertDetails.Subject.DirectoryName)
	assert.Empty(t, details.CertDetails.PublicKey)

	exts, err := details.CRLEntryExtensions()
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.True(t, exts[0].Id.Equal(oidCRLReason))
	var code asn1.Enumerated
	_, err = asn1.Unmarshal(exts[0].Value, &code)
	require.NoError(t, err)
	assert.Equal(t, asn1.Enumerated(CRLReasonKeyCompromise), code)

	// The serial number is copied, so later changes to the certificate do not leak in.
	cert.SerialNumber.SetInt64(1)
	assert.Equal(t, int64(4242), details.CertDetails.SerialNumber.Int64())

	t.Run("IssuerWithoutRawEncoding", func(t *testing.T) {
		built := &x509.Certificate{SerialNumber: big.NewInt(1), Issuer: pkix.Name{CommonName: "Built CA"}}
		details, err := NewRevDetails(built, CRLReasonUnspecified)
		require.NoError(t, err)
		var issuer pkix.RDNSequence
		_, err = asn1.Unmarshal(details.CertDetails.Issuer, &issuer)
		require.NoError(t, err)
		var name pkix.Name
		name.FillFromRDNSequence(&issuer)
		assert.Equal(t, "Built CA", name.CommonName)
	})

	t.Run("Errors", func(t *testing.T) {
		_, err := NewRevDetails(nil, CRLReasonUnspecified)
		assert.Error(t, err)
		_, err = NewRevDetails(&x509.Certificate{}, CRLReasonUnspecified)
		assert.Error(t, err)
		_, err = NewRevDetails(cert, CRLReason(7))
		assert.Error(t, err)
	})
}

// RFC 4211 §5 tags serialNumber [1] implicitly and issuer [3] explicitly.
func TestCertTemplateSerialAndIssuerASN1(t *testing.T) {
	cert := revocationTestCertificate(t, big.NewInt(0x0102))
	tmpl := CertTemplate{SerialNumber: big.NewInt(0x0102), Issuer: cert.RawIssuer}

	var b cryptobyte.Builder
	tmpl.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	der, err := b.Bytes()
	require.NoError(t, err)

	s := cryptobyte.String(der)
	var seq cryptobyte.String
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE))
	var serial cryptobyte.String
	require.True(t, seq.ReadASN1(&serial, cbasn1.Tag(1).ContextSpecific()))
	assert.Equal(t, []byte{0x01, 0x02}, []byte(serial))
	var issuer cryptobyte.String
	require.True(t, seq.ReadASN1(&issuer, cbasn1.Tag(3).ContextSpecific().Constructed()))
	assert.Equal(t, cert.RawIssuer, []byte(issuer))
	assert.True(t, seq.Empty())

	var parsed CertTemplate
	in := cryptobyte.String(der)
	require.NoError(t, parsed.unmarshal(&in))
	assert.Equal(t, 0, parsed.SerialNumber.Cmp(tmpl.SerialNumber))
	assert.Equal(t, tmpl.Issuer, parsed.Issuer)

	t.Run("NegativeSerial", func(t *testing.T) {
		tmpl := CertTemplate{SerialNumber: big.NewInt(-5)}
		var b cryptobyte.Builder
		tmpl.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		der, err := b.Bytes()
		require.NoError(t, err)
		var parsed CertTemplate
		in := cryptobyte.String(der)
		require.NoError(t, parsed.unmarshal(&in))
		assert.Equal(t, int64(-5), parsed.SerialNumber.Int64())
	})

	t.Run("NonMinimalSerial", func(t *testing.T) {
		in := cryptobyte.String([]byte{0x30, 0x04, 0x81, 0x02, 0x00, 0x01})
		var parsed CertTemplate
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("EmptySerial", func(t *testing.T) {
		in := cryptobyte.String([]byte{0x30, 0x02, 0x81, 0x00})
		var parsed CertTemplate
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("IssuerNotAName", func(t *testing.T) {
		in := cryptobyte.String([]byte{0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x01})
		var parsed CertTemplate
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("IssuerTrailingData", func(t *testing.T) {
		in := cryptobyte.String([]byte{0x30, 0x07, 0xa3, 0x05, 0x30, 0x00, 0x02, 0x01, 0x01})
		var parsed CertTemplate
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("MarshalRejectsInvalidIssuer", func(t *testing.T) {
		tmpl := CertTemplate{Issuer: []byte{0x02, 0x01, 0x01}}
		var b cryptobyte.Builder
		tmpl.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		_, err := b.Bytes()
		assert.Error(t, err)
	})
}

// RFC 9810 §5.3.9 revocation request round trip.
func TestRevReqContentASN1(t *testing.T) {
	cert := revocationTestCertificate(t, big.NewInt(77))
	details, err := NewRevDetails(cert, CRLReasonSuperseded)
	require.NoError(t, err)

	msg := NewPKIMessage(NewRRBody(&RevReqContent{details}), MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	require.Equal(t, BodyTypeRR, parsed.Body.Type)
	assert.Equal(t, "rr", parsed.Body.Type.String())

	content, err := parsed.Body.RR()
	require.NoError(t, err)
	require.Len(t, *content, 1)
	got := (*content)[0]
	assert.Equal(t, int64(77), got.CertDetails.SerialNumber.Int64())
	assert.Equal(t, cert.RawIssuer, got.CertDetails.Issuer)
	assert.Equal(t, details.CRLEntryDetails, got.CRLEntryDetails)

	t.Run("WithoutCRLEntryDetails", func(t *testing.T) {
		content := RevReqContent{{CertDetails: CertTemplate{SerialNumber: big.NewInt(1), Issuer: cert.RawIssuer}}}
		var b cryptobyte.Builder
		content.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		der, err := b.Bytes()
		require.NoError(t, err)
		var parsed RevReqContent
		in := cryptobyte.String(der)
		require.NoError(t, parsed.unmarshal(&in))
		require.Len(t, parsed, 1)
		assert.Nil(t, parsed[0].CRLEntryDetails)
		exts, err := parsed[0].CRLEntryExtensions()
		require.NoError(t, err)
		assert.Nil(t, exts)
	})

	t.Run("TrailingData", func(t *testing.T) {
		// RevDetails { CertTemplate {}, Extensions {}, INTEGER 1 }
		in := cryptobyte.String([]byte{0x30, 0x09, 0x30, 0x07, 0x30, 0x00, 0x30, 0x00, 0x02, 0x01, 0x01})
		var parsed RevReqContent
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("InvalidCRLEntryDetails", func(t *testing.T) {
		// RevDetails { CertTemplate {}, INTEGER 1 }
		in := cryptobyte.String([]byte{0x30, 0x07, 0x30, 0x05, 0x30, 0x00, 0x02, 0x01, 0x01})
		var parsed RevReqContent
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("MalformedExtensions", func(t *testing.T) {
		details := RevDetails{CRLEntryDetails: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
		_, err := details.CRLEntryExtensions()
		assert.Error(t, err)
	})

	t.Run("MarshalRejectsInvalidCRLEntryDetails", func(t *testing.T) {
		content := RevReqContent{{CRLEntryDetails: []byte{0x02, 0x01, 0x01}}}
		var b cryptobyte.Builder
		content.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		_, err := b.Bytes()
		assert.Error(t, err)
	})
}

// RFC 9810 §5.3.10 revocation response round trip.
func TestRevRepContentASN1(t *testing.T) {
	cert := revocationTestCertificate(t, big.NewInt(9))
	crl := []byte{0x30, 0x03, 0x02, 0x01, 0x05}

	rep := &RevRepContent{
		Status: []PKIStatusInfo{
			{Status: StatusAccepted},
			{Status: StatusRejection, FailInfo: FailCertRevoked, StatusString: PKIFreeText{"already revoked"}},
		},
		RevCerts: []CertID{
			{Issuer: NewDirectoryNameFromRawDER(cert.RawIssuer), SerialNumber: big.NewInt(9)},
			{Issuer: NewDirectoryNameFromRawDER(cert.RawIssuer), SerialNumber: big.NewInt(10)},
		},
		CRLs: [][]byte{crl},
	}

	msg := NewPKIMessage(NewRPBody(rep), MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	require.Equal(t, BodyTypeRP, parsed.Body.Type)
	assert.Equal(t, "rp", parsed.Body.Type.String())

	got, err := parsed.Body.RP()
	require.NoError(t, err)
	require.Len(t, got.Status, 2)
	assert.Equal(t, StatusAccepted, got.Status[0].Status)
	assert.Equal(t, FailCertRevoked, got.Status[1].FailInfo)
	require.Len(t, got.RevCerts, 2)
	assert.Equal(t, int64(9), got.RevCerts[0].SerialNumber.Int64())
	assert.Equal(t, NewDirectoryNameFromRawDER(cert.RawIssuer).Raw, got.RevCerts[1].Issuer.Raw)
	require.Len(t, got.CRLs, 1)
	assert.Equal(t, crl, got.CRLs[0])

	t.Run("StatusOnly", func(t *testing.T) {
		rep := RevRepContent{Status: []PKIStatusInfo{{Status: StatusAccepted}}}
		var b cryptobyte.Builder
		rep.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		der, err := b.Bytes()
		require.NoError(t, err)
		// SEQUENCE { SEQUENCE { PKIStatusInfo { INTEGER 0 } } }
		assert.Equal(t, []byte{0x30, 0x07, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00}, der)

		var parsed RevRepContent
		in := cryptobyte.String(der)
		require.NoError(t, parsed.unmarshal(&in))
		assert.Nil(t, parsed.RevCerts)
		assert.Nil(t, parsed.CRLs)
	})

	t.Run("TrailingData", func(t *testing.T) {
		in := cryptobyte.String([]byte{0x30, 0x0a, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01})
		var parsed RevRepContent
		assert.Error(t, parsed.unmarshal(&in))
	})

	t.Run("CertIDWithoutSerial", func(t *testing.T) {
		rep := RevRepContent{Status: []PKIStatusInfo{{}}, RevCerts: []CertID{{Issuer: NewDirectoryNameFromRawDER(cert.RawIssuer)}}}
		var b cryptobyte.Builder
		rep.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		_, err := b.Bytes()
		assert.Error(t, err)
	})

	t.Run("MarshalRejectsInvalidCRL", func(t *testing.T) {
		rep := RevRepContent{Status: []PKIStatusInfo{{}}, CRLs: [][]byte{{0x02, 0x01, 0x01}}}
		var b cryptobyte.Builder
		rep.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		_, err := b.Bytes()
		assert.Error(t, err)
	})
}

// OpenSSL 3.6 "openssl cmp -cmd rr -revreason 1" output, see testdata/generate.sh.
func TestOpenSSLGeneratedRevocationRequest(t *testing.T) {
	der, err := os.ReadFile("testdata/rr_golden.der")
	require.NoError(t, err)

	msg, err := ParsePKIMessage(der)
	require.NoError(t, err)
	require.Equal(t, BodyTypeRR, msg.Body.Type)

	content, err := msg.Body.RR()
	require.NoError(t, err)
	require.Len(t, *content, 1)
	details := (*content)[0]
	require.NotNil(t, details.CertDetails.SerialNumber)
	assert.NotEmpty(t, details.CertDetails.Issuer)

	exts, err := details.CRLEntryExtensions()
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.True(t, exts[0].Id.Equal(oidCRLReason))
	var code asn1.Enumerated
	_, err = asn1.Unmarshal(exts[0].Value, &code)
	require.NoError(t, err)
	assert.Equal(t, asn1.Enumerated(CRLReasonKeyCompromise), code)

	// Re-encoding the decoded content reproduces the OpenSSL bytes.
	var b cryptobyte.Builder
	content.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	reencoded, err := b.Bytes()
	require.NoError(t, err)
	body := cryptobyte.String(msg.Body.Raw)
	var original cryptobyte.String
	require.True(t, body.ReadASN1(&original, cbasn1.Tag(BodyTypeRR)))
	assert.Equal(t, []byte(original), reencoded)

	marshaled, err := msg.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, der, marshaled)
}

// A requester without the certificate names it by issuer and serial number.
func TestNewRevDetailsBySerial(t *testing.T) {
	issuer := pkix.Name{CommonName: "Serial CA", Organization: []string{"Example"}}
	serial := big.NewInt(4242)

	details, err := NewRevDetailsBySerial(issuer, serial, CRLReasonSuperseded)
	require.NoError(t, err)
	assert.Equal(t, 0, details.CertDetails.SerialNumber.Cmp(serial))
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(details.CertDetails.Issuer, &rdns)
	require.NoError(t, err)
	assert.Empty(t, rest)
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	assert.Equal(t, "Serial CA", name.CommonName)
	assert.Equal(t, []string{"Example"}, name.Organization)
	assert.Empty(t, details.CertDetails.Subject.DirectoryName)
	assert.Empty(t, details.CertDetails.PublicKey)

	exts, err := details.CRLEntryExtensions()
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.True(t, exts[0].Id.Equal(oidCRLReason))
	var code asn1.Enumerated
	_, err = asn1.Unmarshal(exts[0].Value, &code)
	require.NoError(t, err)
	assert.Equal(t, asn1.Enumerated(CRLReasonSuperseded), code)

	// The serial number is copied, so later changes do not leak in.
	serial.SetInt64(1)
	assert.Equal(t, int64(4242), details.CertDetails.SerialNumber.Int64())

	t.Run("Errors", func(t *testing.T) {
		_, err := NewRevDetailsBySerial(issuer, nil, CRLReasonUnspecified)
		assert.ErrorContains(t, err, "serial number is nil")
		_, err = NewRevDetailsBySerial(pkix.Name{}, big.NewInt(1), CRLReasonUnspecified)
		assert.ErrorContains(t, err, "issuer is empty")
		_, err = NewRevDetailsBySerial(issuer, big.NewInt(1), CRLReason(7))
		assert.ErrorContains(t, err, "invalid CRL reason")
	})
}

// RFC 5280 §5.3.2: invalidityDate is a GeneralizedTime in UTC.
func TestNewInvalidityDateExtension(t *testing.T) {
	warsaw := time.FixedZone("CET", 3600)
	at := time.Date(2026, 10, 1, 13, 30, 15, 123456789, warsaw)

	ext, err := NewInvalidityDateExtension(at)
	require.NoError(t, err)
	assert.True(t, ext.Id.Equal(oidInvalidityDate))
	assert.False(t, ext.Critical)
	// GeneralizedTime 20261001123015Z
	assert.Equal(t, []byte("\x18\x0f20261001123015Z"), ext.Value)

	var parsed time.Time
	rest, err := asn1.UnmarshalWithParams(ext.Value, &parsed, "generalized")
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.True(t, parsed.Equal(at.Truncate(time.Second)), "fractions of a second are dropped")

	_, err = NewInvalidityDateExtension(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Error(t, err, "GeneralizedTime has four year digits")
}

// Entry extensions are added after the reasonCode and travel through the encoding.
func TestRevDetailsAddCRLEntryExtension(t *testing.T) {
	cert := revocationTestCertificate(t, big.NewInt(5))
	details, err := NewRevDetails(cert, CRLReasonKeyCompromise)
	require.NoError(t, err)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	invalidity, err := NewInvalidityDateExtension(at)
	require.NoError(t, err)
	require.NoError(t, details.AddCRLEntryExtension(invalidity))

	content := RevReqContent{details}
	var b cryptobyte.Builder
	content.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	der, err := b.Bytes()
	require.NoError(t, err)
	var parsed RevReqContent
	in := cryptobyte.String(der)
	require.NoError(t, parsed.unmarshal(&in))
	require.Len(t, parsed, 1)
	exts, err := parsed[0].CRLEntryExtensions()
	require.NoError(t, err)
	require.Len(t, exts, 2)
	assert.True(t, exts[0].Id.Equal(oidCRLReason), "the reasonCode comes first")
	assert.Equal(t, invalidity, exts[1])

	t.Run("Duplicate", func(t *testing.T) {
		assert.ErrorContains(t, details.AddCRLEntryExtension(invalidity), "already carry extension 2.5.29.24")
	})

	t.Run("WithoutExtensions", func(t *testing.T) {
		bare := RevDetails{}
		require.NoError(t, bare.AddCRLEntryExtension(invalidity))
		exts, err := bare.CRLEntryExtensions()
		require.NoError(t, err)
		assert.Equal(t, []pkix.Extension{invalidity}, exts)
	})

	t.Run("MalformedExtensions", func(t *testing.T) {
		broken := RevDetails{CRLEntryDetails: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
		assert.Error(t, broken.AddCRLEntryExtension(invalidity))
	})
}
