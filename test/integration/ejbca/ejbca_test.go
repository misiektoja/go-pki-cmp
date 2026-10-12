//go:build integration

package ejbca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestEJBCAInitializeECDSAP384(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-p384"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// Verify the public key in the cert matches the key we submitted.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "certificate public key is not ECDSA")
	assert.True(t, certPubKey.Equal(key.Public()), "certificate public key does not match the submitted key")

	// Verify the certificate is signed by the CA.
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")

	t.Logf("Issued certificate: %s (serial: %s)", cert.Subject, cert.SerialNumber)
}

func TestEJBCAInitializeRSA(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-rsa"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// Verify the public key in the cert matches the key we submitted.
	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	require.True(t, ok, "certificate public key is not RSA")
	assert.True(t, certPubKey.Equal(key.Public()), "certificate public key does not match the submitted key")

	// Verify the certificate is signed by the CA.
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")

	t.Logf("Issued certificate: %s (serial: %s)", cert.Subject, cert.SerialNumber)
}

func TestEJBCAInitializeVerifyCertificateFields(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-verify-fields"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// Verify subject matches request.
	assert.Equal(t, name, cert.Subject.CommonName, "subject CN")

	// Verify issuer matches the CA.
	assert.Equal(t, admin.CACert.Subject.CommonName, cert.Issuer.CommonName, "issuer CN")

	// Verify the public key in the cert matches the key we submitted.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "certificate public key is not ECDSA")
	assert.True(t, certPubKey.Equal(key.Public()), "certificate public key does not match the submitted key")

	// Verify the certificate is signed by the CA
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")

	t.Logf("Certificate verified: %s (serial: %s, issuer: %s)", cert.Subject, cert.SerialNumber, cert.Issuer)
}

func TestEJBCAInitializeWrongSecret(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-wrong-secret"
	correctSecret := "enrollment-secret"
	wrongSecret := "wrong-secret"
	admin.CreateEndEntity(t, name, correctSecret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(wrongSecret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.Error(t, err, "SendIR with wrong secret should have failed")

	var statusErr *pkicmp.PKIStatusError
	require.True(t, errors.As(err, &statusErr), "error should be *pkicmp.PKIStatusError, got %T: %v", err, err)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status, "status should indicate rejection")
	t.Logf("Error: %v, FailInfo: %v, StatusString: %s", statusErr, statusErr.FailInfo, statusErr.StatusString)
	assert.True(t, statusErr.FailInfo&pkicmp.FailBadRequest != 0, "failInfo should indicate bad request")
	assert.Contains(t, statusErr.StatusString, "Error while reading a certificate from the extraCert field", "status string should indicate MAC/shared-secret failure")

	t.Logf("Expected error: %v", err)
}

func TestEJBCAInitializeWithExtensionOverride(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-ext-override"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	// Use a custom OID extension to verify that CertTemplate.Extensions works.
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	customValue, err := asn1.Marshal("hello-extension-override")
	require.NoError(t, err)

	customExt := pkix.Extension{
		Id:    customOID,
		Value: customValue,
	}

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
		client.WithTemplateExtension(customExt),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// Verify the custom extension was honoured by the CA.
	found := slices.ContainsFunc(cert.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(customOID)
	})
	assert.True(t, found, "certificate should contain the custom extension we added in the request")

	t.Logf("Issued certificate: %s (serial: %s, extensions: %v)", cert.Subject, cert.SerialNumber, cert.Extensions)
}

func TestEJBCAInitializeContextCancellation(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-cancel"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
	)
	_, err = c.SendIR(ctx, key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.Error(t, err, "SendIR with cancelled context should have failed")

	t.Logf("Expected error: %v", err)
}

func TestEJBCAMultipleSequentialEnrollments(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	serials := make(map[string]bool)

	for i := range 3 {
		name := fmt.Sprintf("integration-test-seq-%d", i)
		secret := "enrollment-secret"
		admin.CreateEndEntity(t, name, secret)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		creds, err := pkicmp.NewMACCredentials([]byte(secret))
		require.NoError(t, err)

		c := client.NewClient(admin.Endpoint,
			client.WithRecipient(admin.CACert.Subject),
			client.WithTrustedCAs(admin.TrustedCAs()),
		)
		result, err := c.SendIR(context.Background(), key, creds,
			client.WithTemplateSubject(pkix.Name{CommonName: name}),
		)
		require.NoError(t, err, "SendIR %d", i)
		require.NotNil(t, result.Certificate, "enrollment %d: no certificate returned", i)

		serial := result.Certificate.SerialNumber.String()
		require.False(t, serials[serial], "enrollment %d: duplicate serial number %s", i, serial)
		serials[serial] = true

		t.Logf("Enrollment %d: %s (serial: %s)", i, result.Certificate.Subject, serial)
	}
}

func TestEJBCAInitializeInvalidEndpoint(t *testing.T) {
	admin := newEJBCAAdminClient(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"))
	require.NoError(t, err)

	c := client.NewClient("http://localhost:19999/nonexistent",
		client.WithRecipient(admin.CACert.Subject),
	)
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "integration-test-invalid-endpoint"}),
	)
	require.Error(t, err, "SendIR to invalid endpoint should have failed")

	t.Logf("Expected error: %v", err)
}

func TestEJBCACertify(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-certify"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	// Step 1: Get an initial certificate via SendIR
	initialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var creds pkicmp.Credentials
	creds, err = pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	initialResult, err := c.SendIR(context.Background(), initialKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	// Reset end entity status to NEW so EJBCA accepts the CR request.
	admin.CreateEndEntity(t, name, secret)

	// Step 2: Use the initial certificate to request a new one via SendCR.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err = pkicmp.NewSignatureCredentials(initialKey, initialResult.Certificate)
	require.NoError(t, err)

	c = client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{initialResult.Certificate}),
	)
	result, err := c.SendCR(context.Background(), newKey, creds,
		client.WithSender(initialResult.Certificate.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendCR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	assert.NotEqual(t, initialResult.Certificate.SerialNumber, cert.SerialNumber, "SendCR returned the same certificate serial — expected a new certificate")

	// Verify the public key in the cert matches the key we submitted.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "certificate public key is not ECDSA")
	assert.True(t, certPubKey.Equal(newKey.Public()), "certificate public key does not match the submitted key")

	// Verify the certificate is signed by the CA.
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")

	t.Logf("Certified: %s (serial: %s)", cert.Subject, cert.SerialNumber)
}

func TestEJBCAKeyUpdate(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-kur"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	// Step 1: Get an initial certificate via SendIR
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var creds pkicmp.Credentials
	creds, err = pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	initialResult, err := c.SendIR(context.Background(), oldKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	// Step 2: Update the key.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err = pkicmp.NewSignatureCredentials(oldKey, initialResult.Certificate)
	require.NoError(t, err)

	c = client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{initialResult.Certificate}),
	)
	result, err := c.SendKUR(context.Background(), newKey, creds,
		client.WithSender(initialResult.Certificate.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "integration-test-kur"}),
	)
	require.NoError(t, err, "SendKUR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	assert.NotEqual(t, initialResult.Certificate.SerialNumber, result.Certificate.SerialNumber,
		"SendKUR returned the same certificate serial — expected a new certificate")
	oldCertPubKey, ok := initialResult.Certificate.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "initial certificate public key is not ECDSA")
	newCertPubKey, ok := result.Certificate.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "updated certificate public key is not ECDSA")
	assert.False(t, oldCertPubKey.Equal(newCertPubKey),
		"public key should have changed after key update")

	// Verify other certificate parameters remained the same.
	assert.Equal(t, initialResult.Certificate.Subject, result.Certificate.Subject,
		"subject should remain the same after key update")
	assert.Equal(t, initialResult.Certificate.Issuer, result.Certificate.Issuer,
		"issuer should remain the same after key update")
	assert.Equal(t, initialResult.Certificate.SignatureAlgorithm, result.Certificate.SignatureAlgorithm,
		"signature algorithm should remain the same after key update")
	assert.Equal(t, initialResult.Certificate.PublicKeyAlgorithm, result.Certificate.PublicKeyAlgorithm,
		"public key algorithm should remain the same after key update")
	assert.Equal(t, initialResult.Certificate.KeyUsage, result.Certificate.KeyUsage,
		"key usage should remain the same after key update")
	assert.Equal(t, initialResult.Certificate.ExtKeyUsage, result.Certificate.ExtKeyUsage,
		"extended key usage should remain the same after key update")

	t.Logf("Updated: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestEJBCAKeyUpdateWrongKey(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-kur-wrong-key"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	// Step 1: Get an initial certificate via SendIR.
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	initialResult, err := c.SendIR(context.Background(), oldKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	// Step 2: Send KUR signed with a wrong key. Use a custom Credentials
	// implementation to bypass client-side key/cert validation and test that
	// the client correctly processes the server-side rejection.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wrongCreds := &wrongSignatureCredentials{matchingKey: oldKey, wrongKey: wrongKey, cert: initialResult.Certificate}

	c = client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{initialResult.Certificate}),
	)
	_, err = c.SendKUR(context.Background(), newKey, wrongCreds,
		client.WithSender(initialResult.Certificate.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.Error(t, err, "SendKUR with wrong key should have failed")

	var statusErr *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
	t.Logf("Expected error: %v", statusErr)
}

// wrongSignatureCredentials produces a message signed with a key that doesn't
// match the declared sender certificate, so the server will reject the signature.
// It first protects with the matching key (to populate header fields and raw DER),
// then replaces Protection with a signature computed by wrongKey over the same
// protected bytes. Both keys must be the same algorithm family.
type wrongSignatureCredentials struct {
	matchingKey crypto.Signer // key that matches cert — used to set up the message
	wrongKey    crypto.Signer // key that does NOT match cert — used for the forged signature
	cert        *x509.Certificate
}

func (c *wrongSignatureCredentials) Protect(msg *pkicmp.PKIMessage) error {
	// Sign with the correct key to set up header fields and marshal rawHeader/rawBody.
	sc, err := pkicmp.NewSignatureCredentials(c.matchingKey, c.cert)
	if err != nil {
		return err
	}
	if err := sc.Protect(msg); err != nil {
		return err
	}

	// Retrieve the protected bytes and replace the signature with one from wrongKey.
	data, err := msg.ProtectedData()
	if err != nil {
		return err
	}
	h := crypto.SHA256.New()
	h.Write(data)
	sig, err := c.wrongKey.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return err
	}
	msg.Protection = sig
	return nil
}

func TestEJBCAInitializeP10CR(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-p10cr"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create PKCS#10 CSR.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendP10CR(context.Background(), csrDER, creds)
	require.NoError(t, err, "SendP10CR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// Verify subject matches request.
	assert.Equal(t, name, cert.Subject.CommonName, "subject CN")

	// Verify the public key in the cert matches the key we submitted.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "certificate public key is not ECDSA")
	assert.True(t, certPubKey.Equal(key.Public()), "certificate public key does not match the submitted key")

	// Verify the certificate is signed by the CA
	_, err = cert.Verify(x509.VerifyOptions{Roots: admin.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate verification against CA")

	t.Logf("Issued certificate via P10CR: %s (serial: %s)", cert.Subject, cert.SerialNumber)
}

func TestEJBCAKeyUpdateSameKey(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-kur-same-key"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	// Step 1: Get an initial certificate via SendIR.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var creds pkicmp.Credentials
	creds, err = pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	initialResult, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	// Step 2: Update using the same key.
	creds, err = pkicmp.NewSignatureCredentials(key, initialResult.Certificate)
	require.NoError(t, err)

	c = client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
		client.WithExtraCerts([]*x509.Certificate{initialResult.Certificate}),
	)
	result, err := c.SendKUR(context.Background(), key, creds,
		client.WithSender(initialResult.Certificate.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendKUR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	assert.NotEqual(t, initialResult.Certificate.SerialNumber, result.Certificate.SerialNumber,
		"SendKUR returned the same certificate serial — expected a new certificate")

	// Verify the public key is the same.
	assert.True(t, initialResult.Certificate.PublicKey.(*ecdsa.PublicKey).Equal(result.Certificate.PublicKey),
		"public key should be the same after key update with same key")

	t.Logf("Updated (same key): %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestEJBCAMultipleExtensions(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-multi-ext"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	// Extension 1: SAN
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	sanValue, err := asn1.Marshal([]asn1.RawValue{
		{Tag: 2, Class: 2, Bytes: []byte("multi.example.com")},
		{Tag: 2, Class: 2, Bytes: []byte("test.multi.example.com")},
	})
	require.NoError(t, err)

	// Extension 2: Custom OID
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}
	customValue, err := asn1.Marshal("multi-ext-test")
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
		client.WithTemplateExtension(pkix.Extension{Id: sanOID, Value: sanValue}),
		client.WithTemplateExtension(pkix.Extension{Id: customOID, Value: customValue}),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	assert.Contains(t, cert.DNSNames, "multi.example.com")
	assert.Contains(t, cert.DNSNames, "test.multi.example.com")
	foundCustom := slices.ContainsFunc(cert.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(customOID)
	})
	assert.True(t, foundCustom, "custom extension not found")

	t.Logf("Issued certificate with multiple extensions: %s", cert.Subject)
}

func TestEJBCAChainVerification(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-chain"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.NoError(t, err, "SendIR")

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")

	// In signature protection mode, EJBCA should return the CA certificate in ExtraCertificates.
	assert.NotEmpty(t, result.ExtraCertificates, "ExtraCertificates should not be empty")

	trustedCAs := x509.NewCertPool()
	for _, c := range result.ExtraCertificates {
		trustedCAs.AddCert(c)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     trustedCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err, "verification using returned extra certs")

	t.Logf("Chain verified using %d extra certificates", len(result.ExtraCertificates))
}

func TestEJBCALargeKeys(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	secret := "enrollment-secret"

	t.Run("RSA-4096", func(t *testing.T) {
		name := "integration-test-rsa4096"
		admin.CreateEndEntity(t, name, secret)

		key, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)

		creds, err := pkicmp.NewMACCredentials([]byte(secret))
		require.NoError(t, err)

		c := client.NewClient(admin.Endpoint,
			client.WithRecipient(admin.CACert.Subject),
			client.WithTrustedCAs(admin.TrustedCAs()),
		)
		result, err := c.SendIR(context.Background(), key, creds,
			client.WithTemplateSubject(pkix.Name{CommonName: name}),
		)
		require.NoError(t, err, "SendIR RSA-4096")
		require.NotNil(t, result.Certificate)
		assert.Equal(t, 4096, result.Certificate.PublicKey.(*rsa.PublicKey).N.BitLen())
	})

	t.Run("ECDSA-P521", func(t *testing.T) {
		name := "integration-test-p521"
		admin.CreateEndEntity(t, name, secret)

		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		creds, err := pkicmp.NewMACCredentials([]byte(secret))
		require.NoError(t, err)

		c := client.NewClient(admin.Endpoint,
			client.WithRecipient(admin.CACert.Subject),
			client.WithTrustedCAs(admin.TrustedCAs()),
		)
		result, err := c.SendIR(context.Background(), key, creds,
			client.WithTemplateSubject(pkix.Name{CommonName: name}),
		)
		require.NoError(t, err, "SendIR P-521")
		require.NotNil(t, result.Certificate)
		assert.Equal(t, elliptic.P521(), result.Certificate.PublicKey.(*ecdsa.PublicKey).Curve)
	})
}

func TestEJBCAInitializeWrongSubject(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-subject-ok"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "integration-test-wrong-subject"}),
	)
	require.Error(t, err, "SendIR with wrong subject should have failed")

	var statusErr *pkicmp.PKIStatusError
	require.True(t, errors.As(err, &statusErr), "error should be *pkicmp.PKIStatusError")
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status, "status should indicate rejection")
	assert.True(t, statusErr.FailInfo&pkicmp.FailIncorrectData != 0, "failInfo should indicate incorrect data")
	assert.Contains(t, statusErr.StatusString, "Wrong username or password", "status string should indicate wrong username/password")
}

func TestEJBCAInitializeFailNoTrustedCAs(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-no-trust"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	// Omit client.WithTrustedCAs().
	// Even though the request is PBM-protected, EJBCA responds with signature protection.
	// The client requires trusted CAs to verify the signature on the response.
	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
	)
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: name}),
	)
	require.Error(t, err, "SendIR without trusted CAs should have failed verify response")
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)

	t.Logf("Expected error: %v", err)
}

// EJBCA Community Edition does not implement general messages. It answers
// with a protected rejection, which the client must verify and return as a
// status error, not as an unsupported info type.
func TestEJBCAGeneralMessageRejected(t *testing.T) {
	admin := newEJBCAAdminClient(t)
	name := "integration-test-genm"
	secret := "enrollment-secret"
	admin.CreateEndEntity(t, name, secret)

	creds, err := pkicmp.NewMACCredentials([]byte(secret))
	require.NoError(t, err)

	c := client.NewClient(admin.Endpoint,
		client.WithRecipient(admin.CACert.Subject),
		client.WithTrustedCAs(admin.TrustedCAs()),
	)
	_, err = c.GetCACertificates(context.Background(), creds,
		client.WithSender(pkix.Name{CommonName: name}),
	)
	require.Error(t, err)
	assert.NotErrorIs(t, err, client.ErrInfoTypeNotSupported)

	var statusErr *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
	assert.NotZero(t, statusErr.FailInfo&pkicmp.FailBadRequest, "failInfo should indicate bad request")
	t.Logf("Expected error: %v", err)
}
