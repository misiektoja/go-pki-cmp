//go:build integration

package openssl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// requireSLHDSA skips a test when the openssl binary is missing or older than 3.5, the first release with SLH-DSA.
func requireSLHDSA(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	if major, minor := opensslVersion(t); major == 3 && minor < 5 {
		t.Skip("SLH-DSA needs OpenSSL 3.5 or newer")
	}
}

// slhdsaCA certifies SLH-DSA keys with a classical CA and finds the certificates it issued.
type slhdsaCA struct {
	ca *certyaml.Certificate

	mu     sync.Mutex
	issued []*x509.Certificate
}

// IssueCertificate certifies the requested key for signing.
func (c *slhdsaCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
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
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	spki, err := pkicmp.MarshalPublicKey(tmpl.PublicKey)
	if err != nil {
		return nil, err
	}
	der, err := kemcert.CreateCertificate(tmpl, &caCert, spki, caKey)
	if err != nil {
		return nil, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issued = append(c.issued, issued)
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{&caCert}}, nil
}

// LookupCertificate finds an issued certificate by subject and subject key identifier.
func (c *slhdsaCA) LookupCertificate(_ pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cert := range c.issued {
		if cert.Subject.String() == subject.String() && bytes.Equal(cert.SubjectKeyId, senderKID) {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// TestOpenSSLClientSLHDSAKeys enrolls OpenSSL SLH-DSA keys at the server with
// ir, cr, kur and p10cr. The ir proves possession by signature, and the cr and
// kur are protected with the SLH-DSA key the ir certified.
func TestOpenSSLClientSLHDSAKeys(t *testing.T) {
	requireSLHDSA(t)
	dir := t.TempDir()
	// The CA signs the responses, which OpenSSL accepts only with digitalSignature (RFC 9483 §3.5).
	ca := &certyaml.Certificate{Subject: "cn=openssl-slh-dsa-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	require.NoError(t, ca.Generate())
	backend := &slhdsaCA{ca: ca}
	secret := server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("enrollment-secret"), nil })
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSecretLookup(secret),
		server.WithCertificateLookup(backend),
		server.WithSigner(caKey, &caCert),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()
	caFile := filepath.Join(dir, "ca.pem")
	writeCertPEM(t, ca, caFile)
	endpoint := []string{"-server", strings.TrimPrefix(ts.URL, "http://"), "-path", "/"}

	genkey := func(name, alg string) string {
		file := filepath.Join(dir, name+".pem")
		runOpenSSL(t, "genpkey", "-algorithm", alg, "-out", file)
		return file
	}
	// requireIssued checks that the certificate in file certifies the key in keyFile and has an SLH-DSA key of alg.
	requireIssued := func(file, keyFile, alg string) {
		t.Helper()
		pemBytes, err := os.ReadFile(file)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		pubOut := runOpenSSL(t, "pkey", "-in", keyFile, "-pubout", "-outform", "DER")
		assert.Equal(t, pubOut, cert.RawSubjectPublicKeyInfo, "the certificate certifies the new key")
		pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
		require.NoError(t, err)
		assert.Equal(t, alg, pub.(slhdsa.PublicKey).ID.String())
		assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
		require.NoError(t, cert.CheckSignatureFrom(&caCert))
	}

	irKey := genkey("ir-key", "SLH-DSA-SHA2-128s")
	irCert := filepath.Join(dir, "ir-cert.pem")
	_, err = runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "ir", "-ref", "test-ref", "-secret", "pass:enrollment-secret",
		"-newkey", irKey, "-subject", "/CN=openssl-slh-dsa-device",
		"-out_trusted", caFile, "-certout", irCert)...)
	require.NoError(t, err, "openssl cmp ir with an SLH-DSA key")
	requireIssued(irCert, irKey, "SLH-DSA-SHA2-128s")

	crKey := genkey("cr-key", "SLH-DSA-SHAKE-128f")
	crCert := filepath.Join(dir, "cr-cert.pem")
	_, err = runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "cr", "-cert", irCert, "-key", irKey, "-srvcert", caFile,
		"-newkey", crKey, "-subject", "/CN=openssl-slh-dsa-device",
		"-out_trusted", caFile, "-certout", crCert)...)
	require.NoError(t, err, "openssl cmp cr protected with an SLH-DSA key")
	requireIssued(crCert, crKey, "SLH-DSA-SHAKE-128f")

	kurKey := genkey("kur-key", "SLH-DSA-SHA2-256f")
	kurCert := filepath.Join(dir, "kur-cert.pem")
	_, err = runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "kur", "-cert", irCert, "-key", irKey, "-srvcert", caFile,
		"-newkey", kurKey, "-out_trusted", caFile, "-certout", kurCert)...)
	require.NoError(t, err, "openssl cmp kur with SLH-DSA keys")
	requireIssued(kurCert, kurKey, "SLH-DSA-SHA2-256f")

	csrKey := genkey("csr-key", "SLH-DSA-SHAKE-192f")
	csrFile := filepath.Join(dir, "request.csr")
	runOpenSSL(t, "req", "-new", "-key", csrKey, "-subj", "/CN=openssl-slh-dsa-p10cr", "-out", csrFile)
	p10Cert := filepath.Join(dir, "p10cr-cert.pem")
	_, err = runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "p10cr", "-ref", "test-ref", "-secret", "pass:enrollment-secret",
		"-csr", csrFile, "-out_trusted", caFile, "-certout", p10Cert)...)
	require.NoError(t, err, "openssl cmp p10cr with an SLH-DSA request")
	requireIssued(p10Cert, csrKey, "SLH-DSA-SHAKE-192f")
}

// TestOpenSSLServerSLHDSAKeys sends SLH-DSA requests to the OpenSSL mock
// server, which checks the proof of possession, the PKCS #10 signature and the
// SLH-DSA message protection with its own SLH-DSA implementation.
func TestOpenSSLServerSLHDSAKeys(t *testing.T) {
	requireSLHDSA(t)
	ca := &certyaml.Certificate{Subject: "cn=openssl-test-ca"}
	require.NoError(t, ca.Generate())
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)

	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(t, err)
	spki, err := pkicmp.MarshalPublicKey(key.Public())
	require.NoError(t, err)
	subject := pkix.Name{CommonName: "openssl-slh-dsa-rsp"}
	der, err := kemcert.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte("openssl-slh-dsa-rsp"),
	}, &caCert, spki, caKey)
	require.NoError(t, err)
	rspCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:         "test-ref",
		SrvSecret:      "enrollment-secret",
		CA:             ca,
		RspCertificate: rspCert,
	})
	// A mock server with a MAC reference names it in the senderKID of its
	// signed responses too, so signature-protected requests go to a second one.
	signedSrv := newOpenSSLCMPServer(t, opensslCMPServerOpts{CA: ca, RspCertificate: rspCert})
	// The mock server only supports PBM, not PBMAC1.
	macCreds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"), pkicmp.WithPBM())
	require.NoError(t, err)
	c := client.NewClient(srv.Endpoint, client.WithRecipient(srv.CACert.Subject), client.WithTrustedCAs(srv.TrustedCAs()))
	ctx := context.Background()

	ir, err := c.SendIR(ctx, key, macCreds, client.WithTemplateSubject(subject))
	require.NoError(t, err, "SendIR with an SLH-DSA proof of possession")
	assert.True(t, ir.Certificate.Equal(rspCert))

	oid, ok := pkicmp.SLHDSAAlgorithmOID(key.ID)
	require.True(t, ok)
	csrDER, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: subject}, spki, oid, key)
	require.NoError(t, err)
	p10cr, err := c.SendP10CR(ctx, csrDER, macCreds)
	require.NoError(t, err, "SendP10CR with an SLH-DSA request")
	assert.True(t, p10cr.Certificate.Equal(rspCert))

	creds, err := pkicmp.NewSignatureCredentials(key, rspCert)
	require.NoError(t, err)
	signed := client.NewClient(signedSrv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{rspCert}),
	)
	cr, err := signed.SendCR(ctx, key, creds, client.WithSender(subject), client.WithTemplateSubject(subject))
	require.NoError(t, err, "SendCR protected with an SLH-DSA key")
	assert.True(t, cr.Certificate.Equal(rspCert))
}
