//go:build integration

package openssl

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// encryptionCA certifies encryption keys, ML-KEM keys included, and records
// each confirmation with the proof-of-possession method behind it.
type encryptionCA struct {
	ca *certyaml.Certificate

	mu            sync.Mutex
	confirmations []server.ConfirmStatus
	methods       []server.POPMethod
}

// IssueCertificate certifies the requested key for key encipherment.
func (c *encryptionCA) IssueCertificate(ctx context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
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
	tmpl.KeyUsage = x509.KeyUsageKeyEncipherment
	var der []byte
	if pkicmp.IsKEMKey(tmpl.PublicKey) {
		spki, err := pkicmp.MarshalPublicKey(tmpl.PublicKey)
		if err != nil {
			return nil, err
		}
		der, err = kemcert.CreateCertificate(tmpl, &caCert, spki, caKey)
		if err != nil {
			return nil, err
		}
	} else if der, err = x509.CreateCertificate(rand.Reader, tmpl, &caCert, tmpl.PublicKey, caKey); err != nil {
		return nil, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods = append(c.methods, server.POPMethodFromContext(ctx))
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{&caCert}}, nil
}

// ConfirmCertificate records the confirmation status.
func (c *encryptionCA) ConfirmCertificate(ctx context.Context, _ *x509.Certificate, status server.ConfirmStatus, _ any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.confirmations = append(c.confirmations, status)
	c.methods = append(c.methods, server.POPMethodFromContext(ctx))
	return nil
}

// recorded returns copies of the confirmations and methods seen so far.
func (c *encryptionCA) recorded() ([]server.ConfirmStatus, []server.POPMethod) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]server.ConfirmStatus(nil), c.confirmations...), append([]server.POPMethod(nil), c.methods...)
}

// RFC 9810 §5.2.8.3.2: OpenSSL requests a certificate for a key that cannot
// sign with -popo 2, decrypts the encrypted certificate and proves possession
// by confirming its hash.
func TestOpenSSLClientEncryptedCertificatePOP(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	major := opensslMajorVersion(t)
	cases := []struct {
		name    string
		genpkey []string
		// mlkem keys need ML-KEM support in CMS, which OpenSSL has from 4.0.
		mlkem bool
		// options are additional openssl cmp options.
		options []string
		// confirmed is false when the client sends no certConf.
		unconfirmed bool
	}{
		{name: "ML-KEM-768", genpkey: []string{"-algorithm", "ML-KEM-768"}, mlkem: true},
		{name: "ML-KEM-1024", genpkey: []string{"-algorithm", "ML-KEM-1024"}, mlkem: true},
		{name: "RSA", genpkey: []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"}},
		{name: "EC P-256", genpkey: []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"}},
		// The server refuses implicit confirmation, so the client still sends certConf.
		{name: "ML-KEM-768 implicit confirm requested", genpkey: []string{"-algorithm", "ML-KEM-768"}, mlkem: true, options: []string{"-implicit_confirm"}},
		// Without certConf the certificate expires unconfirmed.
		{name: "ML-KEM-768 without confirmation", genpkey: []string{"-algorithm", "ML-KEM-768"}, mlkem: true, options: []string{"-disable_confirm"}, unconfirmed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mlkem && major < 4 {
				t.Skip("ML-KEM in CMS needs OpenSSL 4.0 or newer")
			}
			dir := t.TempDir()
			ca := &certyaml.Certificate{Subject: "cn=openssl-encryption-ca"}
			require.NoError(t, ca.Generate())
			backend := &encryptionCA{ca: ca}
			secret := server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("enrollment-secret"), nil })
			srv := server.NewCAServer(backend, server.LightweightPolicy(),
				server.WithSecretLookup(secret),
				server.WithEncryptedCertificatePOP(),
				server.WithConfirmWaitTime(time.Second),
			)
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			defer ts.Close()

			keyFile := filepath.Join(dir, "new-key.pem")
			runOpenSSL(t, append([]string{"genpkey", "-out", keyFile}, tc.genpkey...)...)
			caFile := filepath.Join(dir, "ca.pem")
			writeCertPEM(t, ca, caFile)
			certOut := filepath.Join(dir, "issued.pem")
			args := append([]string{
				"-cmd", "ir",
				"-server", strings.TrimPrefix(ts.URL, "http://"),
				"-path", "/",
				"-ref", "test-ref",
				"-secret", "pass:enrollment-secret",
				"-newkey", keyFile,
				"-popo", "2",
				"-subject", "/CN=openssl-" + strings.ReplaceAll(tc.name, " ", "-"),
				"-out_trusted", caFile,
				"-certout", certOut,
			}, tc.options...)
			_, err := runOpenSSLCMPClient(t, args...)
			require.NoError(t, err, "openssl cmp ir with -popo 2")

			pemBytes, err := os.ReadFile(certOut)
			require.NoError(t, err)
			block, _ := pem.Decode(pemBytes)
			require.NotNil(t, block)
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, x509.KeyUsageKeyEncipherment, cert.KeyUsage)
			pubOut := runOpenSSL(t, "pkey", "-in", keyFile, "-pubout", "-outform", "DER")
			assert.Equal(t, pubOut, cert.RawSubjectPublicKeyInfo, "the certificate certifies the new key")

			if tc.unconfirmed {
				time.Sleep(1100 * time.Millisecond)
				srv.CleanupExpired()
				confirmations, methods := backend.recorded()
				assert.Equal(t, []server.ConfirmStatus{server.ConfirmExpired}, confirmations, "the CA revokes an unconfirmed encrypted certificate")
				assert.Equal(t, []server.POPMethod{server.POPEncryptedCertificate, server.POPEncryptedCertificate}, methods)
				return
			}
			confirmations, methods := backend.recorded()
			assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, confirmations)
			assert.Equal(t, []server.POPMethod{server.POPEncryptedCertificate, server.POPEncryptedCertificate}, methods)
		})
	}
}
