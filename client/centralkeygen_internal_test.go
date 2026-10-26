package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestParseGeneratedKey reads the PKCS #8, SEC 1 and PKCS #1 keys a key package may carry.
func TestParseGeneratedKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	for name, der := range map[string][]byte{"PKCS #8": pkcs8, "SEC 1": sec1, "PKCS #1": x509.MarshalPKCS1PrivateKey(rsaKey)} {
		t.Run(name, func(t *testing.T) {
			key, normalized, err := parseGeneratedKey(der)
			require.NoError(t, err)
			require.NotNil(t, key)
			parsed, err := x509.ParsePKCS8PrivateKey(normalized)
			require.NoError(t, err)
			assert.True(t, parsed.(interface{ Equal(crypto.PrivateKey) bool }).Equal(key))
		})
	}
	_, _, err = parseGeneratedKey([]byte{0x30, 0x00})
	assert.Error(t, err)
}

// mlkemOneAsymmetricKey returns an ML-KEM-768 OneAsymmetricKey version 2 with publicKey and a certificate shell for pub.
func mlkemOneAsymmetricKey(t *testing.T, publicKey []byte, pub *mlkem.EncapsulationKey768) ([]byte, *x509.Certificate) {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2})
		})
		b.AddASN1OctetString(make([]byte, 66))
		b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			b.AddBytes(publicKey)
		})
	})
	return b.BytesOrPanic(), &x509.Certificate{RawSubjectPublicKeyInfo: spki}
}

// TestCheckGeneratedKeyUnparsed checks a key type the client cannot parse through the public key of its OneAsymmetricKey.
func TestCheckGeneratedKeyUnparsed(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	pub := dk.EncapsulationKey()
	der, cert := mlkemOneAsymmetricKey(t, pub.Bytes(), pub)

	key, pkcs8, err := parseGeneratedKey(der)
	require.NoError(t, err)
	assert.Nil(t, key)
	assert.Equal(t, der, pkcs8)
	assert.NoError(t, checkGeneratedKey(key, pkcs8, cert))

	other, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	wrong, _ := mlkemOneAsymmetricKey(t, other.EncapsulationKey().Bytes(), pub)
	assert.ErrorContains(t, checkGeneratedKey(nil, wrong, cert), "does not match")

	// A version 1 key without its public key cannot be checked.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.ErrorContains(t, checkGeneratedKey(nil, []byte{0x30, 0x03, 0x02, 0x01, 0x00}, cert), "carries no public key")
	assert.ErrorContains(t, checkGeneratedKey(ecKey, nil, cert), "does not match")
}
