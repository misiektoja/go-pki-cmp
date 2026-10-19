//go:build integration

package openssl

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// issuedLog records issued certificates so that signature-protected requests can name them.
type issuedLog struct {
	mu     sync.Mutex
	issued []*x509.Certificate
}

// add records an issued certificate.
func (l *issuedLog) add(cert *x509.Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.issued = append(l.issued, cert)
}

// LookupCertificate finds an issued certificate by subject and subject key identifier.
func (l *issuedLog) LookupCertificate(_ pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, cert := range l.issued {
		if cert.Subject.String() == subject.String() && bytes.Equal(cert.SubjectKeyId, senderKID) {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// slhdsaCA certifies SLH-DSA keys with a classical CA.
type slhdsaCA struct {
	issuedLog
	ca *certyaml.Certificate
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
	c.add(issued)
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{&caCert}}, nil
}

// slhdsaRootCA issues certificates signed by a self-signed SLH-DSA CA, which
// also signs the CMP responses.
type slhdsaRootCA struct {
	issuedLog
	cert *x509.Certificate
	key  slhdsa.PrivateKey
}

// newSLHDSARootCA creates a self-signed CA with an SLH-DSA key of parameter set id.
func newSLHDSARootCA(t *testing.T, id slhdsa.ID) *slhdsaRootCA {
	t.Helper()
	_, key, err := slhdsa.GenerateKey(rand.Reader, id)
	require.NoError(t, err)
	spki, err := pkicmp.MarshalPublicKey(key.Public())
	require.NoError(t, err)
	oid, ok := pkicmp.SLHDSAAlgorithmOID(id)
	require.True(t, ok)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssl-slh-dsa-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// The CA signs the responses, which OpenSSL accepts only with digitalSignature (RFC 9483 §3.5).
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte("openssl-slh-dsa-root"),
	}
	der, err := kemcert.CreateSLHDSACertificate(tmpl, tmpl, spki, oid, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &slhdsaRootCA{cert: cert, key: key}
}

// IssueCertificate certifies the requested key for signing with the SLH-DSA CA key.
func (c *slhdsaRootCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	var err error
	if tmpl.SerialNumber, err = server.GenerateSerial(); err != nil {
		return nil, err
	}
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	spki, err := pkicmp.MarshalPublicKey(tmpl.PublicKey)
	if err != nil {
		return nil, err
	}
	oid, _ := pkicmp.SLHDSAAlgorithmOID(c.key.ID)
	der, err := kemcert.CreateSLHDSACertificate(tmpl, c.cert, spki, oid, c.key)
	if err != nil {
		return nil, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c.add(issued)
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{c.cert}}, nil
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

// TestOpenSSLClientSLHDSACA enrolls OpenSSL keys at a server whose CA key is
// SLH-DSA. The CA signs the certificates and the responses to signature-protected
// requests, and OpenSSL confirms certificates whose signature names no hash.
func TestOpenSSLClientSLHDSACA(t *testing.T) {
	requireSLHDSA(t)
	dir := t.TempDir()
	backend := newSLHDSARootCA(t, slhdsa.SHA2_128f)
	secret := server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("enrollment-secret"), nil })
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSecretLookup(secret),
		server.WithCertificateLookup(backend),
		server.WithSigner(backend.key, backend.cert),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.cert.Raw}), 0o600))
	endpoint := []string{"-server", strings.TrimPrefix(ts.URL, "http://"), "-path", "/"}

	// requireIssued checks that the certificate in file certifies the key in keyFile and that OpenSSL trusts it.
	requireIssued := func(file, keyFile string) {
		t.Helper()
		pemBytes, err := os.ReadFile(file)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		pubOut := runOpenSSL(t, "pkey", "-in", keyFile, "-pubout", "-outform", "DER")
		assert.Equal(t, pubOut, cert.RawSubjectPublicKeyInfo, "the certificate certifies the new key")
		runOpenSSL(t, "verify", "-CAfile", caFile, file)
	}

	irKey := filepath.Join(dir, "ir-key.pem")
	runOpenSSL(t, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", irKey)
	irCert := filepath.Join(dir, "ir-cert.pem")
	_, err := runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "ir", "-ref", "test-ref", "-secret", "pass:enrollment-secret",
		"-newkey", irKey, "-subject", "/CN=openssl-device",
		"-out_trusted", caFile, "-certout", irCert)...)
	require.NoError(t, err, "openssl cmp ir at an SLH-DSA CA")
	requireIssued(irCert, irKey)

	// The kur is signed with the certificate the ir issued, so the response is
	// signed with the SLH-DSA CA key and checked against -srvcert.
	kurKey := filepath.Join(dir, "kur-key.pem")
	runOpenSSL(t, "genpkey", "-algorithm", "SLH-DSA-SHA2-128f", "-out", kurKey)
	kurCert := filepath.Join(dir, "kur-cert.pem")
	_, err = runOpenSSLCMPClient(t, append(endpoint,
		"-cmd", "kur", "-cert", irCert, "-key", irKey, "-srvcert", caFile,
		"-newkey", kurKey, "-out_trusted", caFile, "-certout", kurCert)...)
	require.NoError(t, err, "openssl cmp kur answered by an SLH-DSA CA")
	requireIssued(kurCert, kurKey)
}

// newRolloverKey returns an ECDSA P-256 key when id is zero and an SLH-DSA key of parameter set id otherwise.
func newRolloverKey(t *testing.T, id slhdsa.ID) crypto.Signer {
	t.Helper()
	if id == 0 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	_, key, err := slhdsa.GenerateKey(rand.Reader, id)
	require.NoError(t, err)
	return key
}

// signRolloverCert issues a root CA certificate named "Test Root" for pub,
// signed by signer under parent or self-signed when parent is nil. Either key
// may be an SLH-DSA key, which crypto/x509 can neither certify nor sign with.
func signRolloverCert(t *testing.T, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	// The identifier depends only on the key, so a link certificate shares it
	// with the root of its key and OpenSSL can build the chain by key identifier.
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski[:20],
	}
	if parent == nil {
		parent = tmpl
	}
	var der []byte
	if key, ok := signer.Public().(slhdsa.PublicKey); ok {
		oid, known := pkicmp.SLHDSAAlgorithmOID(key.ID)
		require.True(t, known)
		der, err = kemcert.CreateSLHDSACertificate(tmpl, parent, spki, oid, signer)
	} else {
		der, err = kemcert.CreateCertificate(tmpl, parent, spki, signer)
	}
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestOpenSSLClientSLHDSARootCAUpdate fetches root CA key updates (RFC 9483
// §4.3.2) from the server with the OpenSSL client, for rollovers in which the
// old root, the new root or both have SLH-DSA keys. OpenSSL verifies the new
// root through newWithOld against the old root and oldWithNew against the new root.
func TestOpenSSLClientSLHDSARootCAUpdate(t *testing.T) {
	requireSLHDSA(t)
	dir := t.TempDir()
	ca := &certyaml.Certificate{Subject: "cn=openssl-genm-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	ee := &certyaml.Certificate{Subject: "cn=openssl-genm-ee", Issuer: ca}
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

	rollovers := []struct {
		name     string
		old, new slhdsa.ID
	}{
		{"ECDSA to SLH-DSA", 0, slhdsa.SHA2_128f},
		{"SLH-DSA to SLH-DSA", slhdsa.SHA2_128f, slhdsa.SHAKE_128f},
		{"SLH-DSA to ECDSA", slhdsa.SHA2_128f, 0},
	}
	for _, r := range rollovers {
		t.Run(r.name, func(t *testing.T) {
			oldKey, newKey := newRolloverKey(t, r.old), newRolloverKey(t, r.new)
			oldRoot := signRolloverCert(t, oldKey.Public(), nil, oldKey)
			newRoot := signRolloverCert(t, newKey.Public(), nil, newKey)
			update := &pkicmp.RootCAKeyUpdate{
				NewWithNew: newRoot,
				NewWithOld: signRolloverCert(t, newKey.Public(), oldRoot, oldKey),
				OldWithNew: signRolloverCert(t, oldKey.Public(), newRoot, newKey),
			}
			backend := &supportCA{issued: []*x509.Certificate{&eeCert}, update: update}
			srv := server.NewCAServer(backend, server.LightweightPolicy(),
				server.WithSigner(caKey, &caCert),
				server.WithCertificateLookup(backend),
			)
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			defer ts.Close()

			out := t.TempDir()
			oldFile := filepath.Join(out, "old-root.pem")
			writePEM(t, oldFile, "CERTIFICATE", oldRoot.Raw)
			newWithNew := filepath.Join(out, "newwithnew.pem")
			newWithOld := filepath.Join(out, "newwithold.pem")
			oldWithNew := filepath.Join(out, "oldwithnew.pem")
			_, err := runOpenSSLCMPClient(t,
				"-cmd", "genm",
				"-server", strings.TrimPrefix(ts.URL, "http://"),
				"-path", "/",
				"-cert", eeCertFile,
				"-key", eeKeyFile,
				"-trusted", caFile,
				"-infotype", "rootCaCert", "-oldwithold", oldFile,
				"-newwithnew", newWithNew, "-newwithold", newWithOld, "-oldwithnew", oldWithNew,
			)
			require.NoError(t, err, "openssl cmp genm rootCaCert")
			assert.Equal(t, update.NewWithNew.Raw, readDERFile(t, newWithNew))
			assert.Equal(t, update.NewWithOld.Raw, readDERFile(t, newWithOld))
			assert.Equal(t, update.OldWithNew.Raw, readDERFile(t, oldWithNew))
			assert.True(t, backend.oldRoot.Equal(oldRoot), "the CA receives the root the request names")
		})
	}
}

// TestOpenSSLServerSLHDSARootCAUpdate fetches root CA key updates made by
// OpenSSL from the OpenSSL mock server, for rollovers in which the old root,
// the new root or both have SLH-DSA keys. The client verifies the SLH-DSA
// signatures OpenSSL made and refuses a newWithOld that another root signed.
func TestOpenSSLServerSLHDSARootCAUpdate(t *testing.T) {
	requireSLHDSA(t)
	ctx := context.Background()
	rollovers := []struct{ name, old, new string }{
		{"ECDSA to SLH-DSA", "EC", "SLH-DSA-SHA2-128f"},
		{"SLH-DSA to SLH-DSA", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"},
		{"SLH-DSA to ECDSA", "SLH-DSA-SHA2-128f", "EC"},
	}
	for _, r := range rollovers {
		t.Run(r.name, func(t *testing.T) {
			dir := t.TempDir()
			ext := filepath.Join(dir, "ca.ext")
			require.NoError(t, os.WriteFile(ext, []byte("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"), 0o600))
			// newRoot generates a key of algorithm alg and a self-signed root
			// certificate for it, in files named after name. Every root is
			// named "Test Root", because the OpenSSL mock server answers only
			// a request for a root of that name.
			newRoot := func(name, alg string) *x509.Certificate {
				key := filepath.Join(dir, name+"-key.pem")
				args := []string{"genpkey", "-algorithm", alg, "-out", key}
				if alg == "EC" {
					args = append(args, "-pkeyopt", "ec_paramgen_curve:P-256")
				}
				runOpenSSL(t, args...)
				runOpenSSL(t, "pkey", "-in", key, "-pubout", "-out", filepath.Join(dir, name+"-pub.pem"))
				file := filepath.Join(dir, name+".pem")
				runOpenSSL(t, "x509", "-new", "-key", key, "-subj", "/CN=Test Root", "-days", "1", "-extfile", ext, "-out", file)
				cert, err := x509.ParseCertificate(readDERFile(t, file))
				require.NoError(t, err)
				return cert
			}
			// link certifies the key of root subject with the key of root issuer.
			link := func(subject, issuer string) *x509.Certificate {
				file := filepath.Join(dir, subject+"-with-"+issuer+".pem")
				runOpenSSL(t, "x509", "-new", "-force_pubkey", filepath.Join(dir, subject+"-pub.pem"), "-subj", "/CN=Test Root",
					"-CA", filepath.Join(dir, issuer+".pem"), "-CAkey", filepath.Join(dir, issuer+"-key.pem"),
					"-days", "1", "-extfile", ext, "-out", file)
				cert, err := x509.ParseCertificate(readDERFile(t, file))
				require.NoError(t, err)
				return cert
			}
			// fetch asks a mock server that sends update for the root CA key update of oldRoot.
			fetch := func(oldRoot *x509.Certificate, update *pkicmp.RootCAKeyUpdate) (*pkicmp.RootCAKeyUpdate, error) {
				srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
					RspNewWithNew: update.NewWithNew,
					RspNewWithOld: update.NewWithOld,
					RspOldWithNew: update.OldWithNew,
				})
				creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
				require.NoError(t, err)
				c := client.NewClient(srv.Endpoint, client.WithRecipient(srv.CACert.Subject), client.WithTrustedCAs(srv.TrustedCAs()))
				return c.GetRootCAUpdate(ctx, oldRoot, creds)
			}

			oldRoot := newRoot("old", r.old)
			update := &pkicmp.RootCAKeyUpdate{
				NewWithNew: newRoot("new", r.new),
				NewWithOld: link("new", "old"),
				OldWithNew: link("old", "new"),
			}
			got, err := fetch(oldRoot, update)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.True(t, got.NewWithNew.Equal(update.NewWithNew))
			assert.True(t, got.NewWithOld.Equal(update.NewWithOld))
			assert.True(t, got.OldWithNew.Equal(update.OldWithNew))

			// The other root has an SLH-DSA key, so the forged newWithOld
			// carries a well-formed SLH-DSA signature by the wrong key.
			newRoot("other", "SLH-DSA-SHA2-128f")
			_, err = fetch(oldRoot, &pkicmp.RootCAKeyUpdate{NewWithNew: update.NewWithNew, NewWithOld: link("new", "other")})
			var clientErr *client.Error
			require.ErrorAs(t, err, &clientErr)
			assert.Equal(t, "verify root CA update", clientErr.Op)
		})
	}
}
