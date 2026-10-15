//go:build integration

package openssl

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// approvingCA holds each certificate request until the check numbered decideAt, then issues or rejects it.
type approvingCA struct {
	ca       *certyaml.Certificate
	decideAt int
	reject   bool
	mu       sync.Mutex
	pending  map[string]*x509.Certificate
	checks   int
}

// IssueCertificate keeps the request and answers that it waits for approval.
func (c *approvingCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pollRef := fmt.Sprintf("request-%d", len(c.pending)+1)
	c.pending[pollRef] = tmpl
	return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef, Reason: "waiting for approval"}}, nil
}

// CheckPending keeps the request waiting until decideAt, then issues or rejects it.
func (c *approvingCA) CheckPending(_ context.Context, pollRef string, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	tmpl := c.pending[pollRef]
	switch {
	case tmpl == nil:
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "unknown request"}
	case c.checks < c.decideAt:
		return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef, Reason: "still waiting"}}, nil
	case c.reject:
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "rejected by an operator"}
	}
	caCert, err := c.ca.X509Certificate()
	if err != nil {
		return nil, err
	}
	caKey, err := c.ca.PrivateKey()
	if err != nil {
		return nil, err
	}
	if tmpl.SerialNumber, err = server.GenerateSerial(); err != nil {
		return nil, err
	}
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &caCert, tmpl.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{&caCert}}, nil
}

// RFC 9483 §4.4: the OpenSSL client polls a waiting ir until the server issues or rejects it.
func TestOpenSSLClientPollsAtServer(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "approved", true: "rejected"}[reject], func(t *testing.T) {
			dir := t.TempDir()
			ca := &certyaml.Certificate{Subject: "cn=openssl-polling-ca"}
			require.NoError(t, ca.Generate())
			backend := &approvingCA{ca: ca, decideAt: 2, reject: reject, pending: map[string]*x509.Certificate{}}
			secret := server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("enrollment-secret"), nil })
			srv := server.NewCAServer(backend, server.LightweightPolicy(), server.WithSecretLookup(secret))
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			defer ts.Close()

			certOut := filepath.Join(dir, "issued.pem")
			out, err := runOpenSSLCMPClient(t,
				"-cmd", "ir",
				"-server", strings.TrimPrefix(ts.URL, "http://"),
				"-path", "/",
				"-ref", "test-ref",
				"-secret", "pass:enrollment-secret",
				"-newkey", writeNewKey(t, dir),
				"-subject", "/CN=openssl-polling-ee",
				"-certout", certOut,
				"-total_timeout", "30",
			)
			assert.Equal(t, 2, backend.checks, "the client polls until the decision")
			if reject {
				require.Error(t, err, "a rejected request must fail")
				assert.Contains(t, out, "notAuthorized")
				assert.NoFileExists(t, certOut)
				return
			}
			require.NoError(t, err, "openssl cmp ir with polling")
			pemBytes, err := os.ReadFile(certOut)
			require.NoError(t, err)
			assert.Contains(t, string(pemBytes), "BEGIN CERTIFICATE")
		})
	}
}

// delayingRevocationCA holds each revocation until its client polls, then revokes it.
type delayingRevocationCA struct {
	*revocationCA
	pending map[string]*server.RevocationRequest
}

// RevokeCertificate keeps the request and answers that it waits.
func (c *delayingRevocationCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pollRef := fmt.Sprintf("revocation-%d", len(c.pending)+1)
	c.pending[pollRef] = req
	return &server.WaitingError{CheckAfter: time.Second, PollRef: pollRef}
}

// CheckPending revokes the delayed request.
func (c *delayingRevocationCA) CheckPending(ctx context.Context, pollRef string, sender *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	req := c.pending[pollRef]
	c.mu.Unlock()
	if req == nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	}
	return nil, c.revocationCA.RevokeCertificate(ctx, req, sender)
}

// RFC 9483 §4.4: the OpenSSL client polls after an error message with status waiting and then receives the rp.
func TestOpenSSLClientPollsDelayedRevocation(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	dir := t.TempDir()
	ca := &certyaml.Certificate{Subject: "cn=openssl-delayed-rr-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	ee := &certyaml.Certificate{Subject: "cn=openssl-delayed-rr-ee", Issuer: ca}
	for _, c := range []*certyaml.Certificate{ca, ee} {
		require.NoError(t, c.Generate(), "generate cert for %s", c.Subject)
	}
	caFile := filepath.Join(dir, "ca.pem")
	eeCertFile := filepath.Join(dir, "ee.pem")
	eeKeyFile := filepath.Join(dir, "ee-key.pem")
	writeCertPEM(t, ca, caFile)
	writeCertPEM(t, ee, eeCertFile)
	writeKeyPEM(t, ee, eeKeyFile)
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	eeCert, err := ee.X509Certificate()
	require.NoError(t, err)

	revoker := &revocationCA{issued: []*x509.Certificate{&eeCert}, revoked: map[string]pkicmp.CRLReason{}}
	backend := &delayingRevocationCA{revocationCA: revoker, pending: map[string]*server.RevocationRequest{}}
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSigner(caKey, &caCert),
		server.WithCertificateLookup(revoker),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	_, err = runOpenSSLCMPClient(t,
		"-cmd", "rr",
		"-server", strings.TrimPrefix(ts.URL, "http://"),
		"-path", "/",
		"-cert", eeCertFile,
		"-key", eeKeyFile,
		"-oldcert", eeCertFile,
		"-revreason", "1",
		"-trusted", caFile,
		"-total_timeout", "30",
	)
	require.NoError(t, err, "openssl cmp rr with polling")
	assert.Len(t, backend.pending, 1, "the first rr waited")
	assert.Equal(t, pkicmp.CRLReasonKeyCompromise, revoker.revoked[eeCert.SerialNumber.String()])
}

// writeNewKey writes a fresh P-256 key for an enrollment and returns its file name.
func writeNewKey(t *testing.T, dir string) string {
	t.Helper()
	key := &certyaml.Certificate{Subject: "cn=openssl-polling-key"}
	require.NoError(t, key.Generate())
	file := filepath.Join(dir, "new-key.pem")
	writeKeyPEM(t, key, file)
	return file
}
