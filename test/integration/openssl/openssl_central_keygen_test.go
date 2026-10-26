//go:build integration

package openssl

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// RFC 9483 §4.1.6: the client asks the OpenSSL mock server for central key
// generation in a signed cr. The server returns -rsp_cert with -rsp_key, signed
// with its protection key and encrypted for the client key by key agreement.
// The OpenSSL mock server cannot answer a MAC-protected request for central
// key generation, so that case runs only against the server of this module.
func TestOpenSSLCentralKeyGeneration(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{})
	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	result, err := c.SendCRWithCentralKeyGeneration(context.Background(), nil, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-central-keygen"}),
	)
	require.NoError(t, err, "SendCRWithCentralKeyGeneration")
	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber)
	require.NotNil(t, result.GeneratedKey)
	require.NotNil(t, result.GeneratedKey.PrivateKey, "OpenSSL sends a key type the client parses")
	der, err := x509.MarshalPKCS8PrivateKey(srv.RspKey)
	require.NoError(t, err)
	assert.Equal(t, der, result.GeneratedKey.PKCS8, "the key is -rsp_key")
}

// The OpenSSL client asks the server of this module for central key
// generation with -centralkeygen. It requires id-kp-cmKGA on the key
// generation authority. It reads a password-encrypted key only in the RFC 3211
// key wrap and a signed key only as id-data, which the server uses by default.
func TestOpenSSLClientCentralKeyGeneration(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	if major, minor := opensslVersion(t); major == 3 && minor < 5 {
		t.Skip("central key generation needs OpenSSL 3.5 or newer")
	}
	ca, err := mockserver.New(map[string][]byte{"test-ref": []byte("enrollment-secret")}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	srv := server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
		ca.CentralKeyGeneration(),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", ca.Cert().Raw)
	common := []string{
		"-server", strings.TrimPrefix(ts.URL, "http://"),
		"-path", "/",
		"-trusted", caFile,
		"-out_trusted", caFile,
		"-untrusted", caFile,
	}

	// centralKey runs one request for central key generation and checks that the key belongs to the certificate.
	centralKey := func(t *testing.T, name string, args ...string) string {
		t.Helper()
		certOut := filepath.Join(dir, name+".pem")
		keyOut := filepath.Join(dir, name+"-key.pem")
		_, err := runOpenSSLCMPClient(t, append(append([]string{
			"-centralkeygen",
			"-newkeyout", keyOut,
			"-subject", "/CN=openssl-" + name,
			"-certout", certOut,
		}, common...), args...)...)
		require.NoError(t, err, "openssl cmp -centralkeygen")
		pemBytes, err := os.ReadFile(certOut)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		pubOut := runOpenSSL(t, "pkey", "-in", keyOut, "-pubout", "-outform", "DER")
		assert.Equal(t, pubOut, cert.RawSubjectPublicKeyInfo, "the saved key belongs to the certificate")
		return certOut
	}

	t.Run("MAC", func(t *testing.T) {
		centralKey(t, "mac", "-cmd", "ir", "-ref", "test-ref", "-secret", "pass:enrollment-secret")
	})

	// A signed request gets the key encrypted for its protection key: by key
	// agreement for an EC key and by key transport for an RSA key.
	for _, tc := range []struct {
		name    string
		genpkey []string
	}{
		{"EC", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"}},
		{"RSA", []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"}},
	} {
		t.Run("signature "+tc.name, func(t *testing.T) {
			keyFile := filepath.Join(dir, tc.name+"-protection-key.pem")
			runOpenSSL(t, append([]string{"genpkey", "-out", keyFile}, tc.genpkey...)...)
			certFile := filepath.Join(dir, tc.name+"-protection.pem")
			_, err := runOpenSSLCMPClient(t, append([]string{
				"-cmd", "ir", "-ref", "test-ref", "-secret", "pass:enrollment-secret",
				"-newkey", keyFile, "-subject", "/CN=openssl-protection-" + tc.name, "-certout", certFile,
			}, common...)...)
			require.NoError(t, err, "openssl cmp ir for the protection certificate")
			centralKey(t, "signature-"+tc.name, "-cmd", "cr", "-cert", certFile, "-key", keyFile)
		})
	}
}
