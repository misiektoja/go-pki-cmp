package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// unhex decodes a hex string that may contain spaces.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err)
	return b
}

// testRID returns an issuerAndSerialNumber identifier with a fixed issuer Name.
func testRID() RecipientID {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier([]int{2, 5, 4, 3})
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte("Test CA")) })
			})
		})
	})
	return RecipientID{Issuer: b.BytesOrPanic(), SerialNumber: big.NewInt(4242)}
}

func TestKeyWrapRFC3394Vectors(t *testing.T) {
	cases := []struct{ name, kek, key, wrapped string }{
		{"4.1", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"},
		{"4.2", "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"},
		{"4.3", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"},
		{"4.6", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kek, key, want := unhex(t, tc.kek), unhex(t, tc.key), unhex(t, tc.wrapped)
			got, err := wrapKey(kek, key)
			require.NoError(t, err)
			assert.Equal(t, want, got)
			unwrapped, err := unwrapKey(kek, want)
			require.NoError(t, err)
			assert.Equal(t, key, unwrapped)
		})
	}
}

func TestKeyUnwrapRejectsTampering(t *testing.T) {
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F")
	wrapped := unhex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	wrapped[10] ^= 1
	_, err := unwrapKey(kek, wrapped)
	assert.ErrorIs(t, err, errUnwrap)
	_, err = unwrapKey(kek, wrapped[:16])
	assert.ErrorIs(t, err, errUnwrap)
}

// TestKEMKeyDerivationRFC9936 checks the KEMRecipientInfo key derivation and wrap against RFC 9936 Appendix C.
// The example uses ML-KEM-512, so it starts from the published shared secret rather than from a decapsulation.
func TestKEMKeyDerivationRFC9936(t *testing.T) {
	sharedSecret := unhex(t, "7DF12D412AE299A24FDE6D7C3BB8E3194C80AD3C733DCF2775E09FE8BEDB86D8")
	info, err := kemOtherInfo(algorithm(oidAES128Wrap), nil, 16)
	require.NoError(t, err)
	assert.Equal(t, unhex(t, "3010300B0609608648016503040105020110"), info)
	kek, err := hkdf.Key(sha256.New, sharedSecret, nil, string(info), 16)
	require.NoError(t, err)
	assert.Equal(t, unhex(t, "CF453A3E2BAE0A78701B8206C185A008"), kek)
	wrapped, err := wrapKey(kek, unhex(t, "C5153005588269A0A59F3C01943FDD56"))
	require.NoError(t, err)
	assert.Equal(t, unhex(t, "C050E4392F9C14DD0AC2220203F317D701F94F9DD92778F5"), wrapped)
}

// TestX963KDF checks the KDF against a vector computed by hand from SEC 1 §3.6.1: SHA-256(Z || 00000001 || SharedInfo).
func TestX963KDF(t *testing.T) {
	z := []byte("shared secret")
	info := []byte("info")
	got, err := x963KDF(crypto.SHA256, z, info, 40)
	require.NoError(t, err)
	first := sha256.Sum256(append(append(bytes.Clone(z), 0, 0, 0, 1), info...))
	second := sha256.Sum256(append(append(bytes.Clone(z), 0, 0, 0, 2), info...))
	assert.Equal(t, append(first[:], second[:8]...), got)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	kem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	kem1024, err := mlkem.GenerateKey1024()
	require.NoError(t, err)

	cases := []struct {
		name    string
		pub     crypto.PublicKey
		priv    any
		version int64
		riTag   cbasn1.Tag
	}{
		{"RSA-OAEP", &rsaKey.PublicKey, rsaKey, 0, cbasn1.SEQUENCE},
		{"ECDH P-256", &p256.PublicKey, p256, 2, cbasn1.Tag(1).ContextSpecific().Constructed()},
		{"ECDH P-384", p384.PublicKey(), p384, 2, cbasn1.Tag(1).ContextSpecific().Constructed()},
		{"ECDH P-521", &p521.PublicKey, p521, 2, cbasn1.Tag(1).ContextSpecific().Constructed()},
		{"ML-KEM-768", kem768.EncapsulationKey(), kem768, 3, cbasn1.Tag(4).ContextSpecific().Constructed()},
		{"ML-KEM-1024", kem1024.EncapsulationKey(), kem1024, 3, cbasn1.Tag(4).ContextSpecific().Constructed()},
	}
	for _, tc := range cases {
		for _, rid := range []RecipientID{testRID(), {SubjectKeyID: []byte{1, 2, 3, 4}}} {
			name := tc.name + " issuerAndSerial"
			if rid.SubjectKeyID != nil {
				name = tc.name + " subjectKeyIdentifier"
			}
			t.Run(name, func(t *testing.T) {
				for _, content := range [][]byte{nil, []byte("0123456789abcdef"), bytes.Repeat([]byte("certificate"), 100)} {
					der, err := Encrypt(content, tc.pub, rid)
					require.NoError(t, err)

					// Check the structure: version, one RecipientInfo of the expected type, AES-256-CBC content.
					s := cryptobyte.String(der)
					var seq, set, ri cryptobyte.String
					var version int64
					var riTag cbasn1.Tag
					require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE) && s.Empty())
					require.True(t, seq.ReadASN1Integer(&version) && seq.ReadASN1(&set, cbasn1.SET) && set.ReadAnyASN1Element(&ri, &riTag) && set.Empty())
					want := tc.version
					if rid.SubjectKeyID != nil && want == 0 {
						want = 2
					}
					assert.Equal(t, want, version)
					assert.Equal(t, tc.riTag, riTag)
					gotRID := recipientIDOf(t, ri, riTag)
					if rid.SubjectKeyID != nil {
						assert.Equal(t, rid.SubjectKeyID, gotRID.SubjectKeyID)
					} else {
						assert.Equal(t, rid.Issuer, gotRID.Issuer)
						assert.Equal(t, 0, rid.SerialNumber.Cmp(gotRID.SerialNumber))
					}

					got, err := Decrypt(der, tc.priv)
					require.NoError(t, err)
					assert.Equal(t, content, append([]byte(nil), got...))
				}
			})
		}
	}
}

// recipientIDOf extracts the recipient identifier of an encoded RecipientInfo.
func recipientIDOf(t *testing.T, ri cryptobyte.String, tag cbasn1.Tag) RecipientID {
	t.Helper()
	var seq cryptobyte.String
	var version int64
	switch tag {
	case cbasn1.SEQUENCE:
		require.True(t, ri.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1Integer(&version))
	case cbasn1.Tag(1).ContextSpecific().Constructed():
		var keys, rek cryptobyte.String
		require.True(t, ri.ReadASN1(&seq, tag) && seq.ReadASN1Integer(&version))
		seq.SkipASN1(cbasn1.Tag(0).ContextSpecific().Constructed())
		seq.SkipASN1(cbasn1.SEQUENCE)
		require.True(t, seq.ReadASN1(&keys, cbasn1.SEQUENCE) && keys.ReadASN1(&rek, cbasn1.SEQUENCE))
		seq = rek
	case cbasn1.Tag(4).ContextSpecific().Constructed():
		var ori cryptobyte.String
		require.True(t, ri.ReadASN1(&ori, tag))
		ori.SkipASN1(cbasn1.OBJECT_IDENTIFIER)
		require.True(t, ori.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1Integer(&version))
	default:
		t.Fatalf("unexpected RecipientInfo tag %v", tag)
	}
	rid, err := readRecipientIdentifier(&seq)
	require.NoError(t, err)
	return rid
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherP256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	kem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	otherKEM768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	kem1024, err := mlkem.GenerateKey1024()
	require.NoError(t, err)

	content := []byte("secret")
	toRSA, err := Encrypt(content, &rsaKey.PublicKey, testRID())
	require.NoError(t, err)
	toP256, err := Encrypt(content, p256.PublicKey(), testRID())
	require.NoError(t, err)
	toKEM768, err := Encrypt(content, kem768.EncapsulationKey(), testRID())
	require.NoError(t, err)

	_, err = Decrypt(toRSA, otherRSA)
	assert.ErrorIs(t, err, errDecrypt)
	_, err = Decrypt(toP256, otherP256)
	assert.ErrorIs(t, err, errDecrypt)
	_, err = Decrypt(toP256, p384)
	assert.ErrorContains(t, err, "not on the recipient's curve")
	_, err = Decrypt(toKEM768, otherKEM768)
	assert.ErrorIs(t, err, errDecrypt)
	_, err = Decrypt(toKEM768, kem1024)
	assert.ErrorContains(t, err, "does not match the decryption key")
	_, err = Decrypt(toRSA, p256)
	assert.ErrorIs(t, err, errNoRecipient)
	_, err = Decrypt(toKEM768, rsaKey)
	assert.ErrorIs(t, err, errNoRecipient)
}

func TestDecryptRejectsTamperedContent(t *testing.T) {
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	der, err := Encrypt([]byte("certificate bytes"), kem.EncapsulationKey(), testRID())
	require.NoError(t, err)
	// Flipping a bit in the last ciphertext block breaks the padding check.
	tampered := bytes.Clone(der)
	tampered[len(tampered)-1] ^= 0x80
	_, err = Decrypt(tampered, kem)
	assert.Error(t, err)
	_, err = Decrypt(der[:len(der)-1], kem)
	assert.Error(t, err)
	_, err = Decrypt(append(bytes.Clone(der), 0), kem)
	assert.Error(t, err)
}

func TestEncryptRejectsUnsupportedKeys(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = Encrypt([]byte("x"), x25519.PublicKey(), testRID())
	assert.ErrorContains(t, err, "unsupported ECDH curve")

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	_, err = Encrypt([]byte("x"), &p224.PublicKey, testRID())
	assert.Error(t, err)

	_, err = Encrypt([]byte("x"), "not a key", testRID())
	assert.ErrorContains(t, err, "unsupported recipient key type")
}

func TestEncryptRejectsInvalidRecipientID(t *testing.T) {
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	for name, rid := range map[string]RecipientID{
		"empty":            {},
		"no serial":        {Issuer: testRID().Issuer},
		"issuer not a seq": {Issuer: []byte{0x04, 0x00}, SerialNumber: big.NewInt(1)},
		"both forms":       {Issuer: testRID().Issuer, SerialNumber: big.NewInt(1), SubjectKeyID: []byte{1}},
		"empty key id":     {SubjectKeyID: []byte{}},
	} {
		_, err := Encrypt([]byte("x"), kem.EncapsulationKey(), rid)
		assert.Error(t, err, name)
	}
}

// TestParseOAEPParams checks the RFC 4055 defaults, explicit hashes and a label.
func TestParseOAEPParams(t *testing.T) {
	opts, err := parseOAEPParams(cryptobyte.String{0x30, 0x00})
	require.NoError(t, err)
	assert.Equal(t, &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}, opts)

	// SEQUENCE { [0] sha384, [1] mgf1(sha256), [2] pSpecified("a") }
	params := unhex(t, "303d a00d300b0609608648016503040202 a11a301806092a864886f70d010108300b0609608648016503040201 a210300e06092a864886f70d010109040161")
	opts, err = parseOAEPParams(cryptobyte.String(params))
	require.NoError(t, err)
	assert.Equal(t, &rsa.OAEPOptions{Hash: crypto.SHA384, MGFHash: crypto.SHA256, Label: []byte("a")}, opts)

	_, err = parseOAEPParams(cryptobyte.String{0x30, 0x02, 0x05, 0x00})
	assert.Error(t, err, "unknown fields are refused")
}

// TestDecryptRefusesPKCS1v15 checks that RSA key transport other than RSAES-OAEP is refused.
func TestDecryptRefusesPKCS1v15(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := Encrypt([]byte("x"), &key.PublicKey, testRID())
	require.NoError(t, err)
	oaep := unhex(t, "06092a864886f70d010107")
	require.Equal(t, 1, bytes.Count(der, oaep))
	v15 := bytes.Replace(der, oaep, unhex(t, "06092a864886f70d010101"), 1)
	_, err = Decrypt(v15, key)
	assert.ErrorContains(t, err, "only RSAES-OAEP is accepted")
}
