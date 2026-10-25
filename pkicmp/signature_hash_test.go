package pkicmp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// selfSignedFor returns a self-signed certificate for key.
func selfSignedFor(t *testing.T, key crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// protectedWith protects a pkiconf with creds and returns it parsed again, as a peer sees it.
func protectedWith(t *testing.T, creds pkicmp.Credentials, cert *x509.Certificate) *pkicmp.PKIMessage {
	t.Helper()
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject)})
	require.NoError(t, creds.Protect(msg))
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	return parsed
}

// SignatureCredentials.WithHash replaces the digest the key type selects. SHA-1 verifies only
// on request, as RFC 9481 §7.1 deprecates it, and keys without a digest refuse the option.
func TestSignatureCredentialsWithHash(t *testing.T) {
	ecdsaWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ecdsaWithSHA512 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	ecdsaWithSHA1 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedFor(t, key, "device")
	creds, err := pkicmp.NewSignatureCredentials(key, cert)
	require.NoError(t, err)

	sha512Creds, err := creds.WithHash(crypto.SHA512)
	require.NoError(t, err)
	msg := protectedWith(t, sha512Creds, cert)
	assert.True(t, msg.Header.ProtectionAlg.Algorithm.Equal(ecdsaWithSHA512), "protectionAlg %v", msg.Header.ProtectionAlg.Algorithm)
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: cert})
	assert.NoError(t, err)

	msg = protectedWith(t, creds, cert)
	assert.True(t, msg.Header.ProtectionAlg.Algorithm.Equal(ecdsaWithSHA256), "the original credentials keep the default digest")

	sha1Creds, err := creds.WithHash(crypto.SHA1)
	require.NoError(t, err)
	msg = protectedWith(t, sha1Creds, cert)
	assert.True(t, msg.Header.ProtectionAlg.Algorithm.Equal(ecdsaWithSHA1), "protectionAlg %v", msg.Header.ProtectionAlg.Algorithm)
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: cert})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonUnsupportedAlgorithm, ve.Reason)
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: cert, AllowSHA1Signatures: true})
	assert.NoError(t, err)

	_, err = creds.WithHash(crypto.SHA224)
	var pe *pkicmp.ProtectionError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, pkicmp.ReasonUnsupportedAlgorithm, pe.Reason)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edCreds, err := pkicmp.NewSignatureCredentials(edKey, selfSignedFor(t, edKey, "ed25519-device"))
	require.NoError(t, err)
	_, err = edCreds.WithHash(crypto.SHA256)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, pkicmp.ReasonUnsupportedAlgorithm, pe.Reason)
	assert.ErrorContains(t, err, "take no digest")
}
