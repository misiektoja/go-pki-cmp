//go:build integration

package ejbca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// requireSLHDSACertificate checks that cert certifies key and chains to the EJBCA CA.
func requireSLHDSACertificate(t *testing.T, admin *ejbcaAdmin, cert *x509.Certificate, key slhdsa.PrivateKey) {
	t.Helper()
	require.NotNil(t, cert, "no certificate returned")
	pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	assert.True(t, pkicmp.PublicKeysEqual(pub, key.Public()), "certificate public key does not match the submitted key")
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")
}

// TestEJBCASLHDSAKeys enrolls SLH-DSA keys with an ir, a cr protected by the
// SLH-DSA key the ir certified and a p10cr. EJBCA checks the proof, the
// protection and the PKCS #10 signature with Bouncy Castle.
func TestEJBCASLHDSAKeys(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-slh-dsa"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)
	macCreds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)
	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)

	_, irKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(t, err)
	ir, err := c.SendIR(context.Background(), irKey, macCreds, client.WithTemplateSubject(pkix.Name{CommonName: name}))
	require.NoError(t, err, "SendIR with an SLH-DSA key")
	requireSLHDSACertificate(t, admin, ir.Certificate, irKey)

	// Reset end entity status to NEW so EJBCA accepts the next request.
	admin.CreateEndEntity(t, name, secret)
	_, crKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128f)
	require.NoError(t, err)
	sigCreds, err := pkicmp.NewSignatureCredentials(irKey, ir.Certificate)
	require.NoError(t, err)
	signed := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{ir.Certificate}),
	)
	cr, err := signed.SendCR(context.Background(), crKey, sigCreds,
		client.WithSender(ir.Certificate.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendCR protected with an SLH-DSA key")
	requireSLHDSACertificate(t, admin, cr.Certificate, crKey)

	admin.CreateEndEntity(t, name, secret)
	_, csrKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)
	spki, err := pkicmp.MarshalPublicKey(csrKey.Public())
	require.NoError(t, err)
	oid, ok := pkicmp.SLHDSAAlgorithmOID(csrKey.ID)
	require.True(t, ok)
	csrDER, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, spki, oid, csrKey)
	require.NoError(t, err)
	p10cr, err := c.SendP10CR(context.Background(), csrDER, macCreds)
	require.NoError(t, err, "SendP10CR with an SLH-DSA request")
	requireSLHDSACertificate(t, admin, p10cr.Certificate, csrKey)
}
