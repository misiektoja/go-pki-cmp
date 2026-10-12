//go:build integration

package cmptestsuite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

const sharedSecret = "test-shared-secret"

func TestCMPTestSuite(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH")
	}

	port, ra, crlPath := startMockServer(t)

	configDir := renderConfig(t, configData{Port: port, RAKey: ra.keyPath, RACert: ra.certPath, RAChain: ra.chainPath, CRLFile: crlPath})

	reportsDir, err := filepath.Abs("reports")
	require.NoError(t, err)

	t.Logf("running cmp-test-suite against port %d (reports: %s)", port, reportsDir)

	runErr := runCMPTestSuite(t, runOpts{
		ConfigDir:  configDir,
		ReportsDir: reportsDir,
	})

	t.Log("--- cmp-test-suite results ---")
	reportResults(t, reportsDir)
	require.NoError(t, runErr, "cmp-test-suite run failed")
}

// startMockServer starts the CMP mock server in a goroutine. It returns the
// port, the registration authority it trusts and a file holding its current CRL.
func startMockServer(t *testing.T) (int, raCredentials, string) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(newPrefixWriter(os.Stdout, "[mockserver] "), &slog.HandlerOptions{Level: slog.LevelDebug}))

	ca, err := mockserver.New(map[string][]byte{
		"CN=CMP Client": []byte(sharedSecret),
	}, logger)
	require.NoError(t, err)

	ra := newRACredentials(t, ca)
	crlPath := writeCurrentCRL(t, ca)
	lookup := server.CertificateLookupFunc(func(issuer, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
		if bytes.Equal(senderKID, ra.cert.SubjectKeyId) {
			return ra.cert, nil
		}
		return ca.LookupCertificate(issuer, subject, senderKID)
	})
	// RFC 9483 §5.2.2.1 requires the RA to sign the nested message.
	authorizer := server.RAAuthorizerFunc(func(_ context.Context, sender *server.SenderIdentity, _ *pkicmp.PKIMessage, _ *server.SenderIdentity) error {
		if sender.MACVerified {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailWrongIntegrity, StatusText: "nested message must be signed"}
		}
		if !sender.Certificate.Equal(ra.cert) {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not a registration authority"}
		}
		return nil
	})

	srv := server.NewCAServer(ca,
		server.LightweightPolicy(),
		// The suite asserts the RFC 9483 message construction rules that
		// deployed clients break, so it needs the strict receiver behaviour
		// rather than the interoperable default.
		server.WithStrictProfileValidation(),
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithExtraCerts([]*x509.Certificate{ca.Cert()}),
		server.WithImplicitConfirm(),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(lookup),
		server.WithRAAuthorizer(authorizer),
	)

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port

	logger.Info("listening", "addr", ln.Addr().String())

	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { httpSrv.Close() })

	// Wait for readiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return port, ra, crlPath
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mockserver did not become ready")
	return 0, ra, crlPath
}

// writeCurrentCRL writes the CRL the mock CA serves now to a PEM file, for the suite's CRL update tests.
func writeCurrentCRL(t *testing.T, ca *mockserver.MockCA) string {
	t.Helper()
	crl, err := ca.LatestCRL(context.Background(), pkicmp.CRLSource{}, nil)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "current_crl.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw}), 0o644))
	return path
}

// raCredentials is the registration authority the suite signs nested messages with.
type raCredentials struct {
	cert      *x509.Certificate
	keyPath   string
	certPath  string
	chainPath string
}

// newRACredentials issues a registration authority certificate from ca for the RA key shipped with the suite.
//
// The suite's own RA certificate has a fixed expiry date, so only its key is
// reused. The key file is encrypted in the form the suite's loader expects.
func newRACredentials(t *testing.T, ca *mockserver.MockCA) raCredentials {
	t.Helper()

	keyPath, err := filepath.Abs(filepath.Join(cmpTestSuiteDir, "data", "keys", "private-key-ecdsa.pem"))
	require.NoError(t, err)
	certPEM, err := os.ReadFile(filepath.Join(cmpTestSuiteDir, "data", "trusted_ras", "ra_cms_cert_ecdsa.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "no certificate in the suite's RA certificate file")
	suiteCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotEmpty(t, suiteCert.SubjectKeyId, "the RA certificate is looked up by senderKID")

	serial, err := server.GenerateSerial()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "CMP Test RA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: suiteCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert(), suiteCert.PublicKey, ca.Key())
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	dir := t.TempDir()
	raPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert().Raw})
	ra := raCredentials{
		cert:      cert,
		keyPath:   keyPath,
		certPath:  filepath.Join(dir, "ra_cert.pem"),
		chainPath: filepath.Join(dir, "ra_chain.pem"),
	}
	require.NoError(t, os.WriteFile(ra.certPath, raPEM, 0o644))
	require.NoError(t, os.WriteFile(ra.chainPath, slices.Concat(raPEM, caPEM), 0o644))
	return ra
}
