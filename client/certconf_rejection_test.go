package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// confirmRecorder is a mock CA that answers ir or p10cr with a certificate and records the certConf it receives.
type confirmRecorder struct {
	mu       sync.Mutex
	issue    func(req *pkicmp.PKIMessage) []byte
	adjust   func(rep *pkicmp.CertRepMessage)
	answer   *pkicmp.PKIBody
	statuses []pkicmp.CertStatus
}

// serve starts the mock CA, MAC-protecting every response with "secret".
func (r *confirmRecorder) serve(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		msg, err := pkicmp.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var respBody *pkicmp.PKIBody
		switch msg.Body.Type {
		case pkicmp.BodyTypeCertConf:
			conf, _ := msg.Body.CertConf()
			r.mu.Lock()
			r.statuses = append(r.statuses, *conf...)
			r.mu.Unlock()
			respBody = pkicmp.NewPKIConfBody()
			if r.answer != nil {
				respBody = r.answer
			}
		default:
			rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
				Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: r.issue(msg)}}},
			}}}
			if r.adjust != nil {
				r.adjust(rep)
			}
			respBody = pkicmp.NewIPBody(rep)
			if msg.Body.Type == pkicmp.BodyTypeP10CR {
				respBody = pkicmp.NewCPBody(rep)
			}
		}
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{PVNO: msg.Header.PVNO, TransactionID: msg.Header.TransactionID, RecipNonce: msg.Header.SenderNonce},
			Body:   respBody,
		}
		creds, _ := pkicmp.NewMACCredentials([]byte("secret"))
		_ = creds.Protect(resp)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// recorded returns the certConf statuses received so far.
func (r *confirmRecorder) recorded() []pkicmp.CertStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]pkicmp.CertStatus(nil), r.statuses...)
}

// issueFor returns a certificate from issuer for pub.
func issueFor(t *testing.T, issuer *certyaml.Certificate, pub any) *x509.Certificate {
	t.Helper()
	issuerCert, err := issuer.X509Certificate()
	require.NoError(t, err)
	issuerKey, err := issuer.PrivateKey()
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "enrolled-ee"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &issuerCert, pub, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// sendIR enrolls a fresh P-256 key with MAC credentials and the given trust anchors.
func sendIR(t *testing.T, url string, trusted *x509.Certificate) (*client.EnrollResult, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(trusted)
	c := client.NewClient(url, client.WithTrustedCAs(pool))
	return c.SendIR(context.Background(), key, creds, client.WithSenderKID([]byte("test")), client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
}

// assertRejected checks that exactly one certConf rejected cert with text.
func assertRejected(t *testing.T, statuses []pkicmp.CertStatus, cert *x509.Certificate, text string) {
	t.Helper()
	require.Len(t, statuses, 1, "the client must send exactly one certConf")
	status := statuses[0]
	require.NotNil(t, status.StatusInfo, "a rejection needs statusInfo")
	assert.Equal(t, pkicmp.StatusRejection, status.StatusInfo.Status)
	assert.Zero(t, status.StatusInfo.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{text}, status.StatusInfo.StatusString)
	assert.Equal(t, int64(0), status.CertReqID)
	expected, err := pkicmp.NewCertStatus(cert, 0)
	require.NoError(t, err)
	assert.Equal(t, expected.CertHash, status.CertHash, "certHash must identify the rejected certificate")
}

// RFC 9483 §3.6.1: a certificate that fails validation is rejected in certConf.
func TestRejectedCertificateUntrusted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	other := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherCert, err := other.X509Certificate()
	require.NoError(t, err)

	var issued *x509.Certificate
	rec := &confirmRecorder{issue: func(req *pkicmp.PKIMessage) []byte {
		issued = issueFor(t, ca, requestedPublicKey(req))
		return issued.Raw
	}}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &otherCert)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.NotContains(t, err.Error(), "rejection not confirmed")
	assertRejected(t, rec.recorded(), issued, "certificate validation failed")
}

// RFC 9483 §3.6.1: a certificate for another key is rejected in certConf.
func TestRejectedCertificateForDifferentKey(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issued := issueFor(t, ca, &otherKey.PublicKey)
	rec := &confirmRecorder{issue: func(*pkicmp.PKIMessage) []byte { return issued.Raw }}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &caCert)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "issued certificate does not certify the requested public key", ce.Op)
	assertRejected(t, rec.recorded(), issued, "certificate does not certify the requested public key")
}

// A CA that refuses the rejecting certConf does not replace the reason for the rejection.
func TestRejectedCertificateNotConfirmed(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	other := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherCert, err := other.X509Certificate()
	require.NoError(t, err)

	rec := &confirmRecorder{
		issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestedPublicKey(req)).Raw },
		answer: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
			PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemUnavail},
		}),
	}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &otherCert)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.Contains(t, err.Error(), "rejection not confirmed by the CA")
	assert.False(t, pkicmp.HasFailure(err, pkicmp.FailSystemUnavail), "the CA's answer to certConf must not look like the reason")
	assert.Len(t, rec.recorded(), 1)
}

// A certificate the client accepts is still confirmed without statusInfo.
func TestAcceptedCertificateConfirmed(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	rec := &confirmRecorder{issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestedPublicKey(req)).Raw }}
	ts := rec.serve(t)

	result, err := sendIR(t, ts.URL, &caCert)
	require.NoError(t, err)
	statuses := rec.recorded()
	require.Len(t, statuses, 1)
	assert.Nil(t, statuses[0].StatusInfo)
	expected, err := pkicmp.NewCertStatus(result.Certificate, 0)
	require.NoError(t, err)
	assert.Equal(t, expected.CertHash, statuses[0].CertHash)
}

// confirmingCA issues from ca and records how each certificate was confirmed.
type confirmingCA struct {
	ca       *certyaml.Certificate
	mu       sync.Mutex
	statuses []server.ConfirmStatus
}

// IssueCertificate signs the template with the test CA.
func (c *confirmingCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	caCert, err := c.ca.X509Certificate()
	if err != nil {
		return nil, err
	}
	caKey, err := c.ca.PrivateKey()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &caCert, tmpl.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: cert}, nil
}

// ConfirmCertificate records the confirmation outcome.
func (c *confirmingCA) ConfirmCertificate(_ context.Context, _ *x509.Certificate, status server.ConfirmStatus, _ any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses = append(c.statuses, status)
	return nil
}

// Against the server package, the CA learns of the rejection at once.
func TestRejectedCertificateReachesServer(t *testing.T) {
	backend := &confirmingCA{ca: &certyaml.Certificate{Subject: "cn=issuing-ca"}}
	srv := server.NewCAServer(backend, server.LightweightPolicy(), server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) {
		return []byte("secret"), nil
	})))
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	other := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherCert, err := other.X509Certificate()
	require.NoError(t, err)

	_, err = sendIR(t, ts.URL, &otherCert)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.NotContains(t, err.Error(), "rejection not confirmed")

	backend.mu.Lock()
	defer backend.mu.Unlock()
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, backend.statuses)
}

// A CA that issues and then refuses the confirming certConf yields a ConfirmationError carrying the certificate.
func TestAcceptedCertificateConfirmationRefused(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	var issued *x509.Certificate
	rec := &confirmRecorder{
		issue: func(req *pkicmp.PKIMessage) []byte {
			issued = issueFor(t, ca, requestedPublicKey(req))
			return issued.Raw
		},
		answer: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
			PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure},
		}),
	}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &caCert)
	var ce *client.ConfirmationError
	require.ErrorAs(t, err, &ce)
	require.NotNil(t, ce.Certificate)
	assert.Equal(t, issued.Raw, ce.Certificate.Raw)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailSystemFailure), "the CA's status must stay reachable")
	assert.Contains(t, err.Error(), "certConf")
}
