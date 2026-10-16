package cms

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// TestDecryptBouncyCastleKEMVectors decrypts KEMRecipientInfo envelopes that
// Bouncy Castle 1.86 produced with testdata/kem/generate.sh. Bouncy Castle uses
// KDF3 with SHA-256 by default, which OpenSSL 4.0 does not implement. EJBCA
// configures SHAKE256.
func TestDecryptBouncyCastleKEMVectors(t *testing.T) {
	seed := make([]byte, mlkem.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := mlkem.NewDecapsulationKey768(seed)
	require.NoError(t, err)
	cases := []struct {
		file string
		kdf  asn1.ObjectIdentifier
	}{
		{file: "default.der", kdf: oidKDF3},
		{file: "kdf3-sha256.der", kdf: oidKDF3},
		{file: "kdf3-sha256-null-ukm.der", kdf: oidKDF3},
		{file: "kdf3-sha512-aes128.der", kdf: oidKDF3},
		{file: "kdf2-sha256.der", kdf: oidKDF2},
		{file: "hkdf-sha256.der", kdf: oidHKDFSHA256},
		{file: "shake256.der", kdf: oidSHAKE256},
		{file: "shake256-ukm-aes128.der", kdf: oidSHAKE256},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", "kem", tc.file))
			require.NoError(t, err)
			assert.True(t, bytes.Contains(der, encodeOID(tc.kdf)), "the vector uses the expected KDF")
			plain, err := Decrypt(der, key)
			require.NoError(t, err)
			assert.Equal(t, "go-pki-cmp KEM recipient vector", string(plain))
		})
	}
}

// encodeOID returns the DER encoding of an OBJECT IDENTIFIER.
func encodeOID(oid asn1.ObjectIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(oid)
	return b.BytesOrPanic()
}

// TestKDF3 checks KDF3 against a vector computed from RFC 9690 Appendix B.1: SHA-256(00000001 || Z || OtherInfo).
func TestKDF3(t *testing.T) {
	z := []byte("shared secret")
	info := []byte("info")
	got, err := kdf3(crypto.SHA256, z, info, 40)
	require.NoError(t, err)
	first := sha256.Sum256(append(append([]byte{0, 0, 0, 1}, z...), info...))
	second := sha256.Sum256(append(append([]byte{0, 0, 0, 2}, z...), info...))
	assert.Equal(t, append(first[:], second[:8]...), got)
}

// TestSHAKE256KDF checks that the SHAKE256 KDF reads the shared secret and then OtherInfo, as Bouncy Castle does.
func TestSHAKE256KDF(t *testing.T) {
	derive, err := kemKeyDerivation(kdfAlgorithm(t, oidSHAKE256, nil))
	require.NoError(t, err)
	got, err := derive([]byte("shared secret"), []byte("info"), 24)
	require.NoError(t, err)
	assert.Equal(t, sha3.SumSHAKE256([]byte("shared secretinfo"), 24), got)
}

// kdfAlgorithm encodes a KDF AlgorithmIdentifier with raw parameters, or absent parameters when params is nil.
func kdfAlgorithm(t *testing.T, oid asn1.ObjectIdentifier, params []byte) algorithmIdentifier {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddBytes(params)
	})
	s := cryptobyte.String(b.BytesOrPanic())
	alg, err := readAlgorithmIdentifier(&s)
	require.NoError(t, err)
	return alg
}

// TestKEMKeyDerivationSelection checks which KEMRecipientInfo KDFs and parameters are accepted.
func TestKEMKeyDerivationSelection(t *testing.T) {
	hashWithParams := func(oid asn1.ObjectIdentifier, params []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			b.AddBytes(params)
		})
		return b.BytesOrPanic()
	}
	null := []byte{0x05, 0x00}
	accepted := []struct {
		name string
		alg  algorithmIdentifier
	}{
		{"HKDF-SHA256", kdfAlgorithm(t, oidHKDFSHA256, nil)},
		{"HKDF-SHA512", kdfAlgorithm(t, oidHKDFSHA512, nil)},
		{"KDF3 SHA-256", kdfAlgorithm(t, oidKDF3, algorithm(oidSHA256))},
		{"KDF3 SHA-384 NULL parameters", kdfAlgorithm(t, oidKDF3, hashWithParams(oidSHA384, null))},
		{"KDF2 SHA-512", kdfAlgorithm(t, oidKDF2, algorithm(oidSHA512))},
		{"SHAKE256", kdfAlgorithm(t, oidSHAKE256, nil)},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			derive, err := kemKeyDerivation(tc.alg)
			require.NoError(t, err)
			kek, err := derive([]byte("shared secret"), []byte("info"), 32)
			require.NoError(t, err)
			assert.Len(t, kek, 32)
		})
	}
	refused := []struct {
		name string
		alg  algorithmIdentifier
	}{
		{"HKDF with parameters", kdfAlgorithm(t, oidHKDFSHA256, null)},
		{"KDF3 without parameters", kdfAlgorithm(t, oidKDF3, nil)},
		{"KDF3 with NULL parameters", kdfAlgorithm(t, oidKDF3, null)},
		{"KDF3 SHA-1", kdfAlgorithm(t, oidKDF3, algorithm(oidSHA1))},
		{"KDF3 unknown hash", kdfAlgorithm(t, oidKDF3, algorithm(oidAES256Wrap))},
		{"KDF3 hash with parameters", kdfAlgorithm(t, oidKDF3, hashWithParams(oidSHA256, []byte{0x02, 0x01, 0x01}))},
		{"X9.63 ECDH KDF", kdfAlgorithm(t, oidStdDHSHA256KDF, nil)},
		{"SHAKE256 with parameters", kdfAlgorithm(t, oidSHAKE256, null)},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kemKeyDerivation(tc.alg)
			assert.Error(t, err)
		})
	}
}
