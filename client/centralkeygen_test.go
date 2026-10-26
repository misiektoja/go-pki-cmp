package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// p256Keys generates the ECDSA P-256 key pairs of central key generation.
var p256Keys = server.KeyGeneratorFunc(func(context.Context, *pkicmp.AlgorithmIdentifier, *server.SenderIdentity) (*server.GeneratedKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &server.GeneratedKey{PrivateKey: der, PublicKey: &key.PublicKey}, nil
})

// issueKGA returns a key generation authority key with a certificate for it
// that issuer signs. The key signs the certificate itself when issuer is nil.
func issueKGA(t *testing.T, issuer *certyaml.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(time.Now().UnixNano()),
		Subject:            pkix.Name{CommonName: "KGA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{pkicmp.OIDExtKeyUsageCMKGA},
		SubjectKeyId:       []byte{9, 9, 9},
	}
	parent, signer := tmpl, crypto.Signer(key)
	if issuer != nil {
		caCert, err := issuer.X509Certificate()
		require.NoError(t, err)
		caKey, err := issuer.PrivateKey()
		require.NoError(t, err)
		parent, signer = &caCert, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// serveCentralKeyGeneration serves ca with central key generation signed by
// kgaKey and kgaCert, for requests MAC-protected with "secret".
func serveCentralKeyGeneration(t *testing.T, ca server.CA, kgaKey crypto.Signer, kgaCert *x509.Certificate) string {
	t.Helper()
	srv := server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("secret"), nil })),
		server.WithCentralKeyGeneration(p256Keys, kgaKey, kgaCert),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts.URL
}

// requireGeneratedKey checks that the generated key of res belongs to its certificate.
func requireGeneratedKey(t *testing.T, res *client.EnrollResult, kga *x509.Certificate) {
	t.Helper()
	require.NotNil(t, res.GeneratedKey)
	key, ok := res.GeneratedKey.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "%T", res.GeneratedKey.PrivateKey)
	assert.True(t, key.PublicKey.Equal(res.Certificate.PublicKey))
	assert.True(t, res.GeneratedKey.Signer.Equal(kga))
	parsed, err := x509.ParsePKCS8PrivateKey(res.GeneratedKey.PKCS8)
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))
}

// A deferred central key generation request resumes from its JSON state and
// collects the key with the certificate.
func TestCentralKeyGenerationDeferred(t *testing.T) {
	ca := newDelayedCA(func(int) bool { return true })
	kgaKey, kgaCert := issueKGA(t, ca.ca)
	url := serveCentralKeyGeneration(t, ca, kgaKey, kgaCert)
	c := newPendingClient(t, url, ca)

	res, err := c.SendIRWithCentralKeyGeneration(context.Background(), nil, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "deferred keygen"}),
		client.WithDeferredPolling(),
	)
	require.NoError(t, err)
	require.NotNil(t, res.Pending)
	assert.True(t, res.Pending.CentralKeyGeneration)
	assert.Empty(t, res.Pending.PublicKey)
	assert.Equal(t, pkicmp.PVNO3, res.Pending.PVNO)

	encoded, err := json.Marshal(res.Pending)
	require.NoError(t, err)
	var pending client.PendingEnrollment
	require.NoError(t, json.Unmarshal(encoded, &pending))

	done, err := newPendingClient(t, url, ca).ResumeEnrollment(context.Background(), &pending, macCredentials(t))
	require.NoError(t, err)
	requireGeneratedKey(t, done, kgaCert)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
}

// A key signed by a key generation authority outside the trusted CAs is refused with a certConf rejection.
func TestCentralKeyGenerationUntrustedSigner(t *testing.T) {
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	kgaKey, kgaCert := issueKGA(t, nil)
	url := serveCentralKeyGeneration(t, ca, kgaKey, kgaCert)
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(&caCert)

	_, err = client.NewClient(url, client.WithTrustedCAs(pool)).SendIRWithCentralKeyGeneration(context.Background(), nil, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "untrusted keygen"}),
	)
	require.ErrorContains(t, err, "verify key generation authority")
	statuses := func() []server.ConfirmStatus {
		ca.mu.Lock()
		defer ca.mu.Unlock()
		return slices.Clone(ca.statuses)
	}
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, statuses())

	// Without trusted CAs the MAC of the response vouches for the key.
	res, err := client.NewClient(url).SendIRWithCentralKeyGeneration(context.Background(), nil, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "MAC keygen"}),
	)
	require.NoError(t, err)
	requireGeneratedKey(t, res, kgaCert)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected, server.ConfirmAccepted}, statuses())
}

// Credentials whose key cannot decrypt are refused before the request is sent.
func TestCentralKeyGenerationNeedsDecryptingCredentials(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, edKey.Public(), edKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	creds, err := pkicmp.NewSignatureCredentials(edKey, cert)
	require.NoError(t, err)

	_, err = client.NewClient("http://127.0.0.1:1").SendCRWithCentralKeyGeneration(context.Background(), nil, creds)
	require.ErrorContains(t, err, "cannot receive an encrypted private key")
}
