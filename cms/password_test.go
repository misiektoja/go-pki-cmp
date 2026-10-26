package cms

import (
	"bytes"
	"crypto/aes"
	"encoding/asn1"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// envelopeFields returns the version, the single RecipientInfo and the content type of an EnvelopedData.
func envelopeFields(t *testing.T, der []byte) (int64, cryptobyte.String, asn1.ObjectIdentifier) {
	t.Helper()
	s := cryptobyte.String(der)
	var seq, set, ri, eci cryptobyte.String
	var version int64
	var riTag cbasn1.Tag
	var contentType asn1.ObjectIdentifier
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE) && s.Empty())
	require.True(t, seq.ReadASN1Integer(&version) && seq.ReadASN1(&set, cbasn1.SET))
	require.True(t, set.ReadAnyASN1Element(&ri, &riTag) && set.Empty())
	require.True(t, seq.ReadASN1(&eci, cbasn1.SEQUENCE) && eci.ReadASN1ObjectIdentifier(&contentType))
	return version, ri, contentType
}

// passwordKEKAlgorithm returns the keyEncryptionAlgorithm OID of a PasswordRecipientInfo.
func passwordKEKAlgorithm(t *testing.T, ri cryptobyte.String) asn1.ObjectIdentifier {
	t.Helper()
	var seq cryptobyte.String
	var version int64
	require.True(t, ri.ReadASN1(&seq, cbasn1.Tag(3).ContextSpecific().Constructed()))
	require.True(t, seq.ReadASN1Integer(&version))
	assert.Equal(t, int64(0), version, "PasswordRecipientInfo version")
	require.True(t, seq.SkipASN1(cbasn1.Tag(0).ContextSpecific().Constructed()))
	alg, err := readAlgorithmIdentifier(&seq)
	require.NoError(t, err)
	return alg.oid
}

// TestPasswordRoundTrip encrypts for both password forms and decrypts with either.
func TestPasswordRoundTrip(t *testing.T) {
	secret := []byte("shared secret")
	cases := []struct {
		name      string
		recipient any
		kek       asn1.ObjectIdentifier
	}{
		{"AES key wrap", Password(secret), oidAES256Wrap},
		{"PWRI-KEK", PWRIKEKPassword(secret), oidPWRIKEK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, content := range [][]byte{nil, []byte("0123456789abcdef"), bytes.Repeat([]byte("key"), 200)} {
				der, err := Encrypt(content, tc.recipient, RecipientID{})
				require.NoError(t, err)
				version, ri, contentType := envelopeFields(t, der)
				assert.Equal(t, int64(3), version)
				assert.Equal(t, oidData, contentType)
				assert.Equal(t, tc.kek, passwordKEKAlgorithm(t, ri))

				for _, key := range []any{Password(secret), PWRIKEKPassword(secret)} {
					got, err := Decrypt(der, key)
					require.NoError(t, err)
					assert.Equal(t, content, append([]byte(nil), got...))
				}
			}
		})
	}
}

// TestEncryptSignedDataLabelsContent checks the content type of EncryptSignedData for a key and a password.
func TestEncryptSignedDataLabelsContent(t *testing.T) {
	for _, recipient := range []any{Password("secret"), PWRIKEKPassword("secret")} {
		der, err := EncryptSignedData([]byte("signed data"), recipient, RecipientID{})
		require.NoError(t, err)
		_, _, contentType := envelopeFields(t, der)
		assert.Equal(t, oidSignedData, contentType)
		got, err := Decrypt(der, recipient)
		require.NoError(t, err)
		assert.Equal(t, []byte("signed data"), got)
	}
}

// TestDecryptOpenSSLPasswordRecipients decrypts the OpenSSL vectors in testdata/pwri.
func TestDecryptOpenSSLPasswordRecipients(t *testing.T) {
	content, err := os.ReadFile("testdata/pwri/content.txt")
	require.NoError(t, err)
	for _, name := range []string{"aes256.der", "aes128.der"} {
		t.Run(name, func(t *testing.T) {
			der, err := os.ReadFile("testdata/pwri/" + name)
			require.NoError(t, err)
			// The vectors are ContentInfo structures around the EnvelopedData.
			s := cryptobyte.String(der)
			var ci, explicit, env cryptobyte.String
			require.True(t, s.ReadASN1(&ci, cbasn1.SEQUENCE) && ci.SkipASN1(cbasn1.OBJECT_IDENTIFIER))
			require.True(t, ci.ReadASN1(&explicit, cbasn1.Tag(0).ContextSpecific().Constructed()))
			require.True(t, explicit.ReadASN1Element(&env, cbasn1.SEQUENCE))

			got, err := Decrypt(env, Password("shared secret"))
			require.NoError(t, err)
			assert.Equal(t, content, got)

			_, err = Decrypt(env, Password("other secret"))
			assert.ErrorIs(t, err, errDecrypt)
		})
	}
}

// TestDecryptRejectsWrongPassword checks that both key wraps fail alike for a wrong password.
func TestDecryptRejectsWrongPassword(t *testing.T) {
	for _, recipient := range []any{Password("right"), PWRIKEKPassword("right")} {
		der, err := Encrypt([]byte("content"), recipient, RecipientID{})
		require.NoError(t, err)
		_, err = Decrypt(der, Password("wrong"))
		assert.ErrorIs(t, err, errDecrypt)
	}
}

// TestPWRIKEKWrapRoundTrip wraps keys of several sizes and refuses a broken check value.
func TestPWRIKEKWrapRoundTrip(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	iv := bytes.Repeat([]byte{9}, aes.BlockSize)
	for _, size := range []int{16, 24, 32, 64} {
		key := bytes.Repeat([]byte{byte(size)}, size)
		wrapped, err := wrapPWRIKEK(kek, iv, key)
		require.NoError(t, err)
		assert.Zero(t, len(wrapped)%aes.BlockSize)
		got, err := unwrapPWRIKEK(kek, iv, wrapped)
		require.NoError(t, err)
		assert.Equal(t, key, got)

		// Changing one IV byte flips the same byte of the first inner block,
		// here a check byte, which no longer complements the key byte.
		otherIV := bytes.Clone(iv)
		otherIV[1] ^= 0x55
		_, err = unwrapPWRIKEK(kek, otherIV, wrapped)
		assert.ErrorIs(t, err, errDecrypt)
	}
	_, err := unwrapPWRIKEK(kek, iv, make([]byte, aes.BlockSize))
	assert.ErrorIs(t, err, errDecrypt)
}

// pwri encodes a PasswordRecipientInfo with the given PBKDF2 parameters and key encryption algorithm.
func pwri(pbkdf2Params func(b *cryptobyte.Builder), kekAlgorithm []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPBKDF2)
			b.AddASN1(cbasn1.SEQUENCE, pbkdf2Params)
		})
		b.AddBytes(kekAlgorithm)
		b.AddASN1OctetString(make([]byte, 40))
	})
	return b.BytesOrPanic()
}

// TestOpenPasswordRecipientRejectsParameters refuses PBKDF2 and key wrap parameters it cannot honor.
func TestOpenPasswordRecipientRejectsParameters(t *testing.T) {
	salt := []byte("0123456789abcdef")
	cases := []struct {
		name   string
		params func(b *cryptobyte.Builder)
		kek    []byte
		want   string
	}{
		{"too many iterations", func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(maxPasswordIterations + 1)
		}, algorithm(oidAES256Wrap), "iteration count"},
		{"zero iterations", func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(0)
		}, algorithm(oidAES256Wrap), "iteration count"},
		{"key length mismatch", func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(1000)
			b.AddASN1Int64(16)
		}, algorithm(oidAES256Wrap), "key length"},
		{"unknown prf", func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(1000)
			b.AddBytes(algorithm(oidSHA256))
		}, algorithm(oidAES256Wrap), "pseudorandom function"},
		{"unknown key encryption", func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(1000)
		}, algorithm(oidAES256CBC), "key encryption algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched, err := openPasswordRecipient(pwri(tc.params, tc.kek), []byte("secret"))
			assert.True(t, matched)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestEncryptRejectsPasswordRecipientID refuses a recipient identifier and an empty password.
func TestEncryptRejectsPasswordRecipientID(t *testing.T) {
	_, err := Encrypt([]byte("x"), Password("secret"), RecipientID{SubjectKeyID: []byte{1}})
	assert.Error(t, err)
	_, err = Encrypt([]byte("x"), Password(nil), RecipientID{})
	assert.Error(t, err)
}
