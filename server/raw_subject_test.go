package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// requestedSubject returns a subject pkix.Name cannot reproduce, as an
// RDNSequence and as DER: domainComponent and emailAddress attributes, a
// non-canonical order and UTF8String values.
func requestedSubject(t *testing.T) (pkix.RDNSequence, []byte) {
	t.Helper()
	atv := func(oid asn1.ObjectIdentifier, tag int, value string) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{Type: oid, Value: asn1.RawValue{Tag: tag, Bytes: []byte(value)}}}
	}
	domainComponent := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	rdns := pkix.RDNSequence{
		atv(domainComponent, asn1.TagIA5String, "test"),
		atv(domainComponent, asn1.TagIA5String, "example"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagUTF8String, "device-7"),
		atv(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, asn1.TagIA5String, "device@example.test"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 10}, asn1.TagUTF8String, "Example"),
	}
	der, err := asn1.Marshal(rdns)
	require.NoError(t, err)
	return rdns, der
}

// rawSubjectRequest returns a MAC-protected request for subject, a p10cr when p10cr is set and an ir otherwise.
func rawSubjectRequest(t *testing.T, secret []byte, subject pkix.RDNSequence, subjectDER []byte, p10cr bool) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var body *pkicmp.PKIBody
	if p10cr {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{RawSubject: subjectDER}, key)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		body = pkicmp.NewP10CRBody(csr)
	} else {
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)
		request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{PublicKey: pub}}}
		if subject != nil {
			request.CertReq.CertTemplate.Subject = pkicmp.GeneralName{DirectoryName: subject}
		}
		require.NoError(t, request.GeneratePOP(key))
		body = pkicmp.NewIRBody(&pkicmp.CertReqMessages{request})
	}
	msg := pkicmp.NewPKIMessage(body, macMessageOpts())
	protectMAC(msg, secret)
	return msg
}

// With WithRawSubject the issued certificate carries the subject exactly as
// requested. Without it the subject is rebuilt from pkix.Name.
func TestRawSubject(t *testing.T) {
	secret := []byte("raw-subject-secret")
	subject, subjectDER := requestedSubject(t)

	for _, p10cr := range []bool{false, true} {
		name := "CRMF"
		if p10cr {
			name = "PKCS10"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("Preserved", func(t *testing.T) {
				ts, ca := newConfirmingServer(t, secret, server.WithRawSubject())
				resp := postCMP(t, ts, rawSubjectRequest(t, secret, subject, subjectDER, p10cr))
				cert := issuedCertificate(t, resp)
				assert.Equal(t, subjectDER, ca.template.RawSubject)
				assert.Equal(t, subjectDER, cert.RawSubject)
			})

			t.Run("RebuiltByDefault", func(t *testing.T) {
				ts, ca := newConfirmingServer(t, secret)
				resp := postCMP(t, ts, rawSubjectRequest(t, secret, subject, subjectDER, p10cr))
				cert := issuedCertificate(t, resp)
				assert.Nil(t, ca.template.RawSubject)
				assert.NotEqual(t, subjectDER, cert.RawSubject)
				// pkix.Name keeps the typed attributes but drops the others.
				assert.Equal(t, "CN=device-7,O=Example", cert.Subject.String())
			})
		})
	}

	// A CA can still supply the subject of a request that has none.
	// LightweightPolicy requires a subject, so this server runs without it.
	t.Run("AbsentSubject", func(t *testing.T) {
		ca := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
		ts := httptest.NewServer(server.NewCAServer(ca, nil, server.WithRawSubject(), server.WithSecretLookup(&staticMACLookup{secret: secret})))
		defer ts.Close()
		resp := postCMP(t, ts, rawSubjectRequest(t, secret, nil, nil, false))
		require.Equal(t, pkicmp.StatusAccepted, statusInfoOf(t, resp).Status)
		require.True(t, ca.called)
		assert.Nil(t, ca.template.RawSubject)
	})
}
