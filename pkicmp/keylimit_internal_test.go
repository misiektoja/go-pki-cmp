package pkicmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaPublicKeyOfSize returns an RSA public key with a random modulus of exactly
// bits bits. Nothing signs with it, so it need not be a product of primes.
func rsaPublicKeyOfSize(t *testing.T, bits int) *rsa.PublicKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	require.NoError(t, err)
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	return &rsa.PublicKey{N: n, E: 65537}
}

// certificateWithKey issues a certificate for pub, signed by a fresh ECDSA key.
func certificateWithKey(t *testing.T, pub any) *x509.Certificate {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "oversized"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// The modulus bound is checked where keys are parsed, so every path that takes
// a key from a peer refuses an oversized one before any arithmetic.
func TestParsePublicKeyBoundsRSAModulus(t *testing.T) {
	assert.Equal(t, 16384, MaxRSAModulusBits)

	der, err := x509.MarshalPKIXPublicKey(rsaPublicKeyOfSize(t, MaxRSAModulusBits))
	require.NoError(t, err)
	_, err = ParsePublicKey(der)
	assert.NoError(t, err, "a key at the bound is accepted")

	der, err = x509.MarshalPKIXPublicKey(rsaPublicKeyOfSize(t, MaxRSAModulusBits+8))
	require.NoError(t, err)
	_, err = ParsePublicKey(der)
	assert.ErrorIs(t, err, ErrRSAKeyTooLarge)
}

// A PKCS #10 request is verified with its own key, so the bound applies before
// the self-signature check.
func TestCheckCertificateRequestSignatureRefusesOversizedRSAKey(t *testing.T) {
	spki, err := x509.MarshalPKIXPublicKey(rsaPublicKeyOfSize(t, 32768))
	require.NoError(t, err)
	subject, err := asn1.Marshal(pkix.Name{CommonName: "device"}.ToRDNSequence())
	require.NoError(t, err)
	sig := make([]byte, 32768/8)
	_, err = rand.Read(sig)
	require.NoError(t, err)
	type tbs struct {
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	der, err := asn1.Marshal(struct {
		TBS                tbs
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBS:                tbs{Subject: asn1.RawValue{FullBytes: subject}, PublicKey: asn1.RawValue{FullBytes: spki}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSAEncryption, Parameters: asn1.NullRawValue},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)

	assert.ErrorIs(t, CheckCertificateRequestSignature(csr), ErrRSAKeyTooLarge)
}

// The certificate that signs a message comes from the peer's extraCerts, so
// the protection check applies the bound to its key.
func TestSignatureCheckerRefusesOversizedRSACertificate(t *testing.T) {
	check, err := signatureChecker(AlgorithmIdentifier{Algorithm: oidSHA256WithRSAEncryption}, false)
	require.NoError(t, err)
	cert := certificateWithKey(t, rsaPublicKeyOfSize(t, 32768))
	assert.ErrorIs(t, check(cert, []byte("data"), make([]byte, 32768/8)), ErrRSAKeyTooLarge)
}
