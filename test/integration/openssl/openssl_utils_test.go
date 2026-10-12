//go:build integration

package openssl

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
)

// opensslCMPServerOpts configures the behavior of the OpenSSL CMP server.
type opensslCMPServerOpts struct {
	// HMAC protection: set both to enable MAC-based authentication.
	SrvRef    string
	SrvSecret string

	// Polling: if PollCount > 0, the server returns PollRep that many times
	// before returning the certificate. CheckAfter is the suggested wait time (seconds).
	PollCount  int
	CheckAfter int

	// Forced error: set SendError=true along with PKIStatus and Failure to
	// make the server unconditionally return an error PKIMessage.
	// PKIStatus 2 = rejection, Failure values are FailInfo bit numbers (0-26).
	SendError bool
	PKIStatus *int
	Failure   *int

	// FailureBits: raw failure info bitmask (0..2^27 - 1). Overrides Failure.
	FailureBits *int
	// StatusString: human readable status string to include in response.
	StatusString string

	// RefCert passes the enrolled certificate as -ref_cert. The OpenSSL 4.0.3
	// mock server crashes on a certReqTemplate request without it, but it also
	// makes the server expect that certificate in the oldCertID of a kur.
	RefCert bool

	// Root CA key update and CRL returned in general responses.
	RspNewWithNew *x509.Certificate
	RspNewWithOld *x509.Certificate
	RspOldWithNew *x509.Certificate
	RspCRL        *x509.RevocationList
}

// opensslCMPServer represents a running OpenSSL CMP server.
type opensslCMPServer struct {
	// Endpoint is the HTTP base URL ("http://localhost:<port>").
	Endpoint string

	// CACert is the CA certificate used to issue all PKI certs in this test.
	// Pass to client.NewClient as the caCert (recipient) parameter.
	CACert *x509.Certificate

	// RspCert is the certificate the server returns for every enrollment.
	// Tests assert that the received certificate matches this value.
	RspCert *x509.Certificate

	// RspKey is the private key of RspCert. Enrollment tests must request a
	// certificate for this key: the mock server replies with RspCert whatever was
	// asked for, and the client requires the issued certificate to certify the
	// requested key.
	RspKey crypto.Signer

	// ClientCert and ClientKey are a pre-issued ECDSA P-256 cert/key pair.
	// Use them as the existing credentials in Certify() and KeyUpdate() tests.
	ClientCert *x509.Certificate
	ClientKey  crypto.Signer
}

// newOpenSSLCMPServer generates a temp PKI, starts "openssl cmp -port <port>",
// and returns an opensslCMPServer with the endpoint URL and the relevant certs.
// The server process is killed automatically when the test ends.
//
// If the openssl binary is not found the test is skipped.
func newOpenSSLCMPServer(t *testing.T, opts opensslCMPServerOpts) *opensslCMPServer {
	t.Helper()

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}

	dir := t.TempDir()

	// -------------------------------------------------------------------
	// 1. Generate the PKI hierarchy using certyaml.
	//    ca → server   (signs CMP response messages)
	//    ca → rsp      (returned as the enrolled certificate)
	//    ca → client   (used as existing cert in CR / KUR tests)
	// -------------------------------------------------------------------
	ca := &certyaml.Certificate{Subject: "cn=openssl-test-ca"}
	server := &certyaml.Certificate{Subject: "cn=openssl-test-server", Issuer: ca}
	rsp := &certyaml.Certificate{Subject: "cn=openssl-test-rsp", Issuer: ca}
	client := &certyaml.Certificate{Subject: "cn=openssl-test-client", Issuer: ca}

	// Generate in dependency order.
	for _, c := range []*certyaml.Certificate{ca, server, rsp, client} {
		require.NoError(t, c.Generate(), "generate cert for %s", c.Subject)
	}

	// Write to files so openssl can read them.
	caFile := filepath.Join(dir, "ca.pem")
	srvCertFile := filepath.Join(dir, "server.pem")
	srvKeyFile := filepath.Join(dir, "server-key.pem")
	rspCertFile := filepath.Join(dir, "rsp.pem")
	rspKeyFile := filepath.Join(dir, "rsp-key.pem")
	clientCertFile := filepath.Join(dir, "client.pem")

	writeCertPEM(t, ca, caFile)
	writeCertPEM(t, server, srvCertFile)
	writeKeyPEM(t, server, srvKeyFile)
	writeCertPEM(t, rsp, rspCertFile)
	writeKeyPEM(t, rsp, rspKeyFile)
	writeCertPEM(t, client, clientCertFile)

	// -------------------------------------------------------------------
	// 2. Find a free port and build the openssl command.
	// -------------------------------------------------------------------
	port := freePort(t)

	args := []string{
		"cmp",
		"-port", fmt.Sprintf("%d", port),
		"-srv_cert", srvCertFile,
		"-srv_key", srvKeyFile,
		"-srv_trusted", caFile,
		"-rsp_cert", rspCertFile,
		"-rsp_key", rspKeyFile,
		"-rsp_capubs", caFile,
		"-digest", "SHA256",
		"-mac", "HMAC-SHA256",
	}

	if opts.SrvRef != "" {
		args = append(args, "-srv_ref", opts.SrvRef, "-srv_secret", "pass:"+opts.SrvSecret)
	}
	if opts.PollCount > 0 {
		args = append(args,
			"-poll_count", fmt.Sprintf("%d", opts.PollCount),
			"-check_after", fmt.Sprintf("%d", opts.CheckAfter),
		)
	}
	if opts.SendError {
		args = append(args, "-send_error")
	}
	if opts.PKIStatus != nil {
		args = append(args, "-pkistatus", fmt.Sprintf("%d", *opts.PKIStatus))
	}
	if opts.Failure != nil {
		args = append(args, "-failure", fmt.Sprintf("%d", *opts.Failure))
	}
	if opts.FailureBits != nil {
		args = append(args, "-failurebits", fmt.Sprintf("%d", *opts.FailureBits))
	}
	if opts.StatusString != "" {
		args = append(args, "-statusstring", opts.StatusString)
	}
	if opts.RefCert {
		args = append(args, "-ref_cert", rspCertFile)
	}
	for _, rsp := range []struct {
		flag string
		cert *x509.Certificate
	}{
		{"-rsp_newwithnew", opts.RspNewWithNew},
		{"-rsp_newwithold", opts.RspNewWithOld},
		{"-rsp_oldwithnew", opts.RspOldWithNew},
	} {
		if rsp.cert != nil {
			file := filepath.Join(dir, strings.TrimPrefix(rsp.flag, "-")+".pem")
			writePEM(t, file, "CERTIFICATE", rsp.cert.Raw)
			args = append(args, rsp.flag, file)
		}
	}
	if opts.RspCRL != nil {
		file := filepath.Join(dir, "rsp_crl.pem")
		writePEM(t, file, "X509 CRL", opts.RspCRL.Raw)
		args = append(args, "-rsp_crl", file)
	}

	// -------------------------------------------------------------------
	// 3. Start the server and register cleanup.
	// -------------------------------------------------------------------
	cmd := exec.Command("openssl", args...)
	cmd.Stdout = os.Stderr // surface openssl output in test log
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "start openssl CMP server")
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// -------------------------------------------------------------------
	// 4. Wait until the server port is reachable (up to 5 s).
	// -------------------------------------------------------------------
	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	connected := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			connected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, connected, "openssl CMP server did not start within 5 s on %s", addr)

	// -------------------------------------------------------------------
	// 5. Extract the relevant certs from certyaml for use in tests.
	// -------------------------------------------------------------------
	caCertX509, err := ca.X509Certificate()
	require.NoError(t, err)

	rspCertX509, err := rsp.X509Certificate()
	require.NoError(t, err)

	rspKey, err := rsp.PrivateKey()
	require.NoError(t, err)

	clientCertX509, err := client.X509Certificate()
	require.NoError(t, err)

	tlsClient, err := client.TLSCertificate()
	require.NoError(t, err)
	clientKey, ok := tlsClient.PrivateKey.(crypto.Signer)
	require.True(t, ok, "client private key does not implement crypto.Signer")

	return &opensslCMPServer{
		Endpoint:   fmt.Sprintf("http://localhost:%d", port),
		CACert:     &caCertX509,
		RspCert:    &rspCertX509,
		RspKey:     rspKey,
		ClientCert: &clientCertX509,
		ClientKey:  clientKey,
	}
}

// TrustedCAs returns a CertPool containing the CA certificate for trust verification.
func (s *opensslCMPServer) TrustedCAs() *x509.CertPool {
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(s.CACert)
	return trustedCAs
}

// freePort returns an available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// writeCertPEM writes the certificate PEM of c to file.
func writeCertPEM(t *testing.T, c *certyaml.Certificate, file string) {
	t.Helper()
	certPEM, _, err := c.PEM()
	require.NoError(t, err, "PEM for %s", c.Subject)
	require.NoError(t, os.WriteFile(file, certPEM, 0600))
}

// writeKeyPEM writes the private key PEM of c to file.
func writeKeyPEM(t *testing.T, c *certyaml.Certificate, file string) {
	t.Helper()
	_, keyPEM, err := c.PEM()
	require.NoError(t, err, "PEM for %s", c.Subject)
	require.NoError(t, os.WriteFile(file, keyPEM, 0600))
}

// writePEM writes der to file as one PEM block of the given type.
func writePEM(t *testing.T, file, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
}
