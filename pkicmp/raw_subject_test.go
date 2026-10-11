package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// unusualSubject is a name pkix.Name cannot reproduce: domainComponent and
// emailAddress attributes, a non-canonical order and UTF8String values that
// would re-encode as PrintableString.
func unusualSubject() pkix.RDNSequence {
	utf8 := func(s string) asn1.RawValue { return asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(s)} }
	ia5 := func(s string) asn1.RawValue { return asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(s)} }
	atv := func(oid asn1.ObjectIdentifier, value asn1.RawValue) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{Type: oid, Value: value}}
	}
	domainComponent := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	return pkix.RDNSequence{
		atv(domainComponent, ia5("test")),
		atv(domainComponent, ia5("example")),
		atv(asn1.ObjectIdentifier{2, 5, 4, 3}, utf8("device-7")),
		atv(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, ia5("device@example.test")),
		atv(asn1.ObjectIdentifier{2, 5, 4, 10}, utf8("Example")),
	}
}

// parsedTemplate marshals an ir carrying template and returns the template as parsed back.
func parsedTemplate(t *testing.T, template pkicmp.CertTemplate) pkicmp.CertTemplate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template.PublicKey, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: template}}
	require.NoError(t, request.GeneratePOP(key))
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{request}), pkicmp.MessageOptions{})
	mustProtectMAC(t, msg, []byte("raw-subject-secret"))
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	ir, err := parsed.Body.IR()
	require.NoError(t, err)
	require.Len(t, *ir, 1)
	return (*ir)[0].CertReq.CertTemplate
}

// Parsing keeps the subject DER as sent, alongside the decoded name.
func TestCertTemplateRawSubject(t *testing.T) {
	t.Run("KeepsRequestedEncoding", func(t *testing.T) {
		subject := unusualSubject()
		want, err := asn1.Marshal(subject)
		require.NoError(t, err)

		template := parsedTemplate(t, pkicmp.CertTemplate{Subject: pkicmp.GeneralName{DirectoryName: subject}})
		assert.Equal(t, want, template.RawSubject)
		assert.Len(t, template.Subject.DirectoryName, len(subject))
	})

	t.Run("AbsentSubject", func(t *testing.T) {
		assert.Nil(t, parsedTemplate(t, pkicmp.CertTemplate{}).RawSubject)
	})
}
