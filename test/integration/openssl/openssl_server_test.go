//go:build integration

package openssl

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// revocationCA is a CA that only revokes the certificates it was given.
type revocationCA struct {
	mu      sync.Mutex
	issued  []*x509.Certificate
	revoked map[string]pkicmp.CRLReason
}

// IssueCertificate refuses every request, since these tests exercise revocation only.
func (c *revocationCA) IssueCertificate(context.Context, server.RequestType, *x509.Certificate, *server.SenderIdentity) (*server.Response, error) {
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
}

// RevokeCertificate records the revocation of a known certificate.
func (c *revocationCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var cert *x509.Certificate
	for _, issued := range c.issued {
		if issued.SerialNumber.Cmp(req.SerialNumber) == 0 {
			cert = issued
		}
	}
	if err := req.Match(cert); err != nil {
		return err
	}
	if _, ok := c.revoked[cert.SerialNumber.String()]; ok {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailCertRevoked, StatusText: "certificate already revoked"}
	}
	c.revoked[cert.SerialNumber.String()] = req.Reason
	return nil
}

// LookupCertificate finds a known certificate by its subject name.
func (c *revocationCA) LookupCertificate(_ pkix.Name, subject pkix.Name, _ []byte) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// certyaml issues end-entity certificates without a subject key identifier.
	for _, cert := range c.issued {
		if cert.Subject.String() == subject.String() {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// runOpenSSLCMPClient runs "openssl cmp" and returns its combined output and exit error.
func runOpenSSLCMPClient(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("openssl", append([]string{"cmp"}, args...)...).CombinedOutput()
	t.Logf("openssl cmp %s\n%s", strings.Join(args, " "), out)
	return string(out), err
}

func TestOpenSSLClientRevokesAtServer(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	dir := t.TempDir()

	// The CA certificate also protects CMP responses, so it needs digitalSignature (RFC 9483 §3.5).
	ca := &certyaml.Certificate{Subject: "cn=openssl-rr-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	ee := &certyaml.Certificate{Subject: "cn=openssl-rr-ee", Issuer: ca}
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

	backend := &revocationCA{issued: []*x509.Certificate{&eeCert}, revoked: map[string]pkicmp.CRLReason{}}
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSigner(caKey, &caCert),
		server.WithCertificateLookup(backend),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	args := []string{
		"-cmd", "rr",
		"-server", strings.TrimPrefix(ts.URL, "http://"),
		"-path", "/",
		"-cert", eeCertFile,
		"-key", eeKeyFile,
		"-oldcert", eeCertFile,
		"-revreason", "1",
		"-trusted", caFile,
	}

	_, err = runOpenSSLCMPClient(t, args...)
	require.NoError(t, err, "openssl cmp rr")
	assert.Equal(t, pkicmp.CRLReasonKeyCompromise, backend.revoked[eeCert.SerialNumber.String()])

	// RFC 9483 §5.1.3: revoking the same certificate again is rejected with certRevoked.
	out, err := runOpenSSLCMPClient(t, args...)
	require.Error(t, err, "second revocation must be rejected")
	assert.Contains(t, out, "certRevoked")
}
