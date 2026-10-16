package cms

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// encryptedValueKey returns the RSA test key of the Bouncy Castle EncryptedValue vectors.
func encryptedValueKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "encval", "rsa-key.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(strings.ReplaceAll(string(data), "TESTING KEY", "PRIVATE KEY")))
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(*rsa.PrivateKey)
}

// TestDecryptBouncyCastleEncryptedValueVectors decrypts EncryptedValue vectors
// that Bouncy Castle 1.86 produced with testdata/encval/generate.sh.
func TestDecryptBouncyCastleEncryptedValueVectors(t *testing.T) {
	key := encryptedValueKey(t)
	cert, err := os.ReadFile(filepath.Join("testdata", "encval", "cert.der"))
	require.NoError(t, err)
	for _, name := range []string{"des-ede3-pkcs1", "aes128-pkcs1", "aes256-pkcs1", "aes256-oaep-sha256"} {
		t.Run(name, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", "encval", name+".der"))
			require.NoError(t, err)
			plain, err := DecryptEncryptedValue(der, key)
			require.NoError(t, err)
			assert.Equal(t, cert, plain)
		})
	}
}

// encryptedValueFields splits an EncryptedValue into its encoded fields.
func encryptedValueFields(t *testing.T, der []byte) []cryptobyte.String {
	t.Helper()
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE))
	var fields []cryptobyte.String
	for !seq.Empty() {
		var field cryptobyte.String
		require.True(t, seq.ReadAnyASN1Element(&field, nil))
		fields = append(fields, field)
	}
	return fields
}

// encodeEncryptedValue builds an EncryptedValue from encoded fields.
func encodeEncryptedValue(fields ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, f := range fields {
			b.AddBytes(f)
		}
	})
	return b.BytesOrPanic()
}

// NewEncryptedValue writes the fields every CMP version 2 peer reads, and its output decrypts.
func TestEncryptedValueRoundTrip(t *testing.T) {
	key := encryptedValueKey(t)
	content := []byte("an encrypted certificate")
	der, err := NewEncryptedValue(content, &key.PublicKey)
	require.NoError(t, err)

	fields := encryptedValueFields(t, der)
	require.Len(t, fields, 4, "symmAlg, encSymmKey, keyAlg and encValue")
	symmAlg, err := readImplicitAlgorithm(fields[0], 1)
	require.NoError(t, err)
	assert.True(t, symmAlg.oid.Equal(oidAES256CBC))
	assert.Equal(t, byte(0x82), fields[1][0], "encSymmKey is [2] IMPLICIT BIT STRING")
	keyAlg, err := readImplicitAlgorithm(fields[2], 3)
	require.NoError(t, err)
	assert.True(t, keyAlg.oid.Equal(oidRSAEncryption))
	assert.True(t, keyAlg.paramsAbsentOrNull())
	assert.Equal(t, byte(cbasn1.BIT_STRING), fields[3][0])

	plain, err := DecryptEncryptedValue(der, key)
	require.NoError(t, err)
	assert.Equal(t, content, plain)
}

// The optional intendedAlg and valueHint are skipped, and an absent keyAlg means PKCS #1 v1.5.
func TestDecryptEncryptedValueOptionalFields(t *testing.T) {
	key := encryptedValueKey(t)
	der, err := NewEncryptedValue([]byte("content"), &key.PublicKey)
	require.NoError(t, err)
	f := encryptedValueFields(t, der)
	intendedAlg := []byte{0xa0, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	emptyHint := []byte{0x84, 0x00}

	for name, fields := range map[string][][]byte{
		"intendedAlg and empty valueHint": {intendedAlg, f[0], f[1], f[2], emptyHint, f[3]},
		"no keyAlg":                       {f[0], f[1], f[3]},
	} {
		t.Run(name, func(t *testing.T) {
			plain, err := DecryptEncryptedValue(encodeEncryptedValue(fields...), key)
			require.NoError(t, err)
			assert.Equal(t, "content", string(plain))
		})
	}
}

// Malformed and unsupported EncryptedValues are refused.
func TestDecryptEncryptedValueRefused(t *testing.T) {
	key := encryptedValueKey(t)
	der, err := NewEncryptedValue([]byte("content"), &key.PublicKey)
	require.NoError(t, err)
	f := encryptedValueFields(t, der)
	implicitAlgorithm := func(tag uint8, oid asn1.ObjectIdentifier, params []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.Tag(tag).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			b.AddBytes(params)
		})
		return b.BytesOrPanic()
	}
	shortIV := implicitAlgorithm(1, oidAES256CBC, []byte{0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0})
	unknownCipher := implicitAlgorithm(1, oidAES256Wrap, []byte{0x04, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	unknownKeyAlg := implicitAlgorithm(3, oidSHA256, nil)
	unusedBits := []byte{0x03, 0x02, 0x01, 0x00}

	for _, tc := range []struct {
		name string
		der  []byte
		want string
	}{
		{"no symmAlg", encodeEncryptedValue(f[1], f[2], f[3]), "no symmAlg"},
		{"no encSymmKey", encodeEncryptedValue(f[0], f[2], f[3]), "no encSymmKey"},
		{"no encValue", encodeEncryptedValue(f[0], f[1], f[2]), "invalid EncryptedValue"},
		{"short IV", encodeEncryptedValue(shortIV, f[1], f[2], f[3]), "invalid symmAlg parameters"},
		{"unknown cipher", encodeEncryptedValue(unknownCipher, f[1], f[2], f[3]), "unsupported EncryptedValue symmAlg"},
		{"unknown keyAlg", encodeEncryptedValue(f[0], f[1], unknownKeyAlg, f[3]), "unsupported EncryptedValue keyAlg"},
		{"partial byte encValue", encodeEncryptedValue(f[0], f[1], f[2], unusedBits), "invalid EncryptedValue"},
		{"trailing data", append(der, 0x00), "invalid EncryptedValue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptEncryptedValue(tc.der, key)
			assert.ErrorContains(t, err, tc.want)
		})
	}

	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	_, err = DecryptEncryptedValue(der, kem)
	assert.ErrorContains(t, err, "RSA")
}

// A PKCS #1 v1.5 padding error yields a random key of the cipher's size
// instead of an error, so it fails later like any other wrong key and the
// result does not reveal whether the padding was valid (RFC 3218 §2.3.2).
func TestDecryptEncryptedValuePaddingOracle(t *testing.T) {
	key := encryptedValueKey(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := NewEncryptedValue([]byte("content"), &key.PublicKey)
	require.NoError(t, err)
	v, err := parseEncryptedValue(der)
	require.NoError(t, err)

	right, err := valueKey(key, v, 32)
	require.NoError(t, err)
	random, err := valueKey(other, v, 32)
	require.NoError(t, err, "a padding error is not reported")
	assert.Len(t, random, 32)
	assert.NotEqual(t, right, random)

	// With the right key but a changed IV the padding of the content breaks,
	// which is reported with the same error as a wrong key.
	f := encryptedValueFields(t, der)
	symmAlg := append(cryptobyte.String(nil), f[0]...)
	symmAlg[len(symmAlg)-1] ^= 0x01
	_, err = DecryptEncryptedValue(encodeEncryptedValue(symmAlg, f[1], f[2], f[3]), key)
	assert.ErrorIs(t, err, errDecrypt)
}
