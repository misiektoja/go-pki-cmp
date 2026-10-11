package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/client"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// capturedRequest is the part of a CRMF request the subject tests inspect.
type capturedRequest struct {
	sender      []byte
	templateRaw []byte
	extensions  []pkix.Extension
}

// subjectTestServer answers one CRMF request of the given type and its certConf, recording the request.
func subjectTestServer(t *testing.T, pki testPKI, respType pkicmp.BodyType, captured chan<- capturedRequest) *httptest.Server {
	t.Helper()
	signer := &certyaml.Certificate{Subject: "cn=subject-test-ca-signer", Issuer: pki.ca}
	signerKey, err := signer.PrivateKey()
	require.NoError(t, err)
	signerCert, err := signer.X509Certificate()
	require.NoError(t, err)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		header := pkicmp.PKIHeader{PVNO: req.Header.PVNO, TransactionID: req.Header.TransactionID, RecipNonce: req.Header.SenderNonce}
		resp := &pkicmp.PKIMessage{Header: header, Body: pkicmp.NewPKIConfBody()}
		if req.Body.Type != pkicmp.BodyTypeCertConf {
			var requests *pkicmp.CertReqMessages
			if req.Body.Type == pkicmp.BodyTypeKUR {
				requests, err = req.Body.KUR()
			} else {
				requests, err = req.Body.CR()
			}
			if err != nil || len(*requests) != 1 {
				http.Error(w, "unexpected request body", http.StatusBadRequest)
				return
			}
			template := (*requests)[0].CertReq.CertTemplate
			var extensions []pkix.Extension
			if len(template.Extensions) > 0 {
				if _, err := asn1.Unmarshal(template.Extensions, &extensions); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			captured <- capturedRequest{sender: directoryName(t, req.Header.Sender), templateRaw: template.RawSubject, extensions: extensions}
			rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
				Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}}},
			}}}
			if respType == pkicmp.BodyTypeKUP {
				resp.Body = pkicmp.NewKUPBody(rep)
			} else {
				resp.Body = pkicmp.NewCPBody(rep)
			}
		}
		credentials, _ := pkicmp.NewSignatureCredentials(signerKey, &signerCert)
		_ = credentials.Protect(resp)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
}

// directoryName returns the Name DER inside a parsed directoryName GeneralName.
func directoryName(t *testing.T, name pkicmp.GeneralName) []byte {
	t.Helper()
	var element asn1.RawValue
	rest, err := asn1.Unmarshal(name.Raw, &element)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, 4, element.Tag)
	return element.Bytes
}

// issueWithSubject returns a key and a certificate from the test CA whose subject is the given DER.
func issueWithSubject(t *testing.T, pki testPKI, rawSubject []byte, dnsNames ...string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	caKey, err := pki.ca.PrivateKey()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		RawSubject:   rawSubject,
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// unusualRawSubject is a subject pkix.Name cannot reproduce: domainComponent attributes before
// the commonName, IA5String and UTF8String values and a multi-valued RDN.
func unusualRawSubject(t *testing.T) []byte {
	t.Helper()
	domainComponent := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	der, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: domainComponent, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("test")}}},
		{{Type: domainComponent, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("example")}}},
		{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("device-7")}},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("7")}},
		},
	})
	require.NoError(t, err)
	return der
}

// Signed requests and key updates name a certificate with its subject as encoded in that certificate.
func TestCertificateSubjectEncoding(t *testing.T) {
	pki := newTestPKI()
	trusted := x509.NewCertPool()
	trusted.AddCert(pki.caCert)
	newKey, err := pki.ee.PrivateKey()
	require.NoError(t, err)
	raw := unusualRawSubject(t)

	// send runs one request against a fresh server and returns what the server received.
	send := func(t *testing.T, kur bool, oldKey crypto.Signer, oldCert *x509.Certificate, opts ...client.RequestOption) capturedRequest {
		t.Helper()
		respType := pkicmp.BodyTypeCP
		if kur {
			respType = pkicmp.BodyTypeKUP
		}
		captured := make(chan capturedRequest, 1)
		server := subjectTestServer(t, pki, respType, captured)
		defer server.Close()
		credentials, err := pkicmp.NewSignatureCredentials(oldKey, oldCert)
		require.NoError(t, err)
		c := client.NewClient(server.URL, client.WithTrustedCAs(trusted))
		if kur {
			_, err = c.SendKUR(context.Background(), newKey, credentials, opts...)
		} else {
			_, err = c.SendCR(context.Background(), newKey, credentials, opts...)
		}
		require.NoError(t, err)
		return <-captured
	}

	t.Run("KeyUpdateDefaultsToOldSubject", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, raw)
		got := send(t, true, oldKey, oldCert)
		assert.Equal(t, raw, got.templateRaw)
		assert.Equal(t, raw, got.sender)
	})

	t.Run("KeyUpdateUsesWithOldCertificate", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, raw)
		otherRaw, err := asn1.Marshal(pkix.Name{CommonName: "replaced-device"}.ToRDNSequence())
		require.NoError(t, err)
		_, replaced := issueWithSubject(t, pki, otherRaw)
		got := send(t, true, oldKey, oldCert, client.WithOldCertificate(replaced))
		assert.Equal(t, otherRaw, got.templateRaw)
	})

	t.Run("ExplicitTemplateSubjectWins", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, raw)
		want, err := asn1.Marshal(pkix.Name{CommonName: "chosen"}.ToRDNSequence())
		require.NoError(t, err)
		got := send(t, true, oldKey, oldCert, client.WithTemplateSubject(pkix.Name{CommonName: "chosen"}))
		assert.Equal(t, want, got.templateRaw)
	})

	// RFC 9483 §4.1.3: a certificate named only in subjectAltName is updated
	// with a NULL-DN subject and the same subjectAltName.
	t.Run("KeyUpdateOfEmptySubjectRepeatsSubjectAltName", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, []byte{0x30, 0x00}, "device.example.test")
		got := send(t, true, oldKey, oldCert)
		assert.Equal(t, []byte{0x30, 0x00}, got.templateRaw)
		var want pkix.Extension
		for _, ext := range oldCert.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				want = ext
			}
		}
		assert.Equal(t, []pkix.Extension{want}, got.extensions)
	})

	// RFC 9483 §4.1.1: a request that names the entity only in subjectAltName has a NULL-DN subject.
	t.Run("SubjectAltNameOnlyRequestHasNullDN", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, raw)
		names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("second.example.test")}})
		require.NoError(t, err)
		san := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: names}
		got := send(t, false, oldKey, oldCert, client.WithTemplateExtension(san))
		assert.Equal(t, []byte{0x30, 0x00}, got.templateRaw)
		assert.Equal(t, []pkix.Extension{san}, got.extensions)
	})

	t.Run("CertificationRequestKeepsTemplateEmpty", func(t *testing.T) {
		oldKey, oldCert := issueWithSubject(t, pki, raw)
		got := send(t, false, oldKey, oldCert)
		assert.Nil(t, got.templateRaw)
		assert.Equal(t, raw, got.sender)
	})
}
