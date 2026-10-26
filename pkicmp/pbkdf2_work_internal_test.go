package pkicmp

import (
	"crypto"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The iteration bound applies to the whole derivation, so a long key from a
// short PRF cannot multiply the work the iteration count alone permits.
func TestValidatePBKDF2Work(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		iterations, keyLength int
		prf                   crypto.Hash
		maximum               int
		ok                    bool
	}{
		{"OneBlockAtMaximum", 500000, 32, crypto.SHA256, 500000, true},
		{"TwoBlocksWithinMaximum", 250000, 64, crypto.SHA256, 500000, true},
		{"TwoBlocksOverMaximum", 250001, 64, crypto.SHA256, 500000, false},
		{"DefaultClientParametersWithSHA1", 10000, 32, crypto.SHA1, 500000, true},
		{"SevenSHA1BlocksAtMaximumCount", 500000, 128, crypto.SHA1, 500000, false},
		{"SevenSHA1BlocksWithinMaximum", 71428, 128, crypto.SHA1, 500000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePBKDF2Work(tc.iterations, tc.keyLength, tc.prf, tc.maximum)
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			var pe *ParseError
			require.ErrorAs(t, err, &pe)
			assert.Contains(t, pe.Detail, "PBKDF2 work too large")
		})
	}
}

// A PBMAC1 message whose key length multiplies the iterations past the maximum
// is refused before the derivation runs, and such credentials cannot be built
// under the same limits.
func TestPBMAC1WorkIsBounded(t *testing.T) {
	secret := []byte("shared-secret")
	// 128 bytes from HMAC-SHA1 take seven PBKDF2 blocks, so these parameters
	// cost seven times the 150000 iterations they declare, more than the
	// default maximum permits.
	params := pbmac1Options{
		Secret:         secret,
		IterationCount: 150000,
		KeyLength:      128,
		PRF:            oidHMACWithSHA1,
		MAC:            oidHMACWithSHA512,
	}
	newMessage := func() *PKIMessage {
		return NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryName(pkix.Name{CommonName: "sender"})})
	}

	var pe *ParseError
	require.ErrorAs(t, newMessage().protectWithPBMAC1Options(params), &pe)
	assert.Contains(t, pe.Detail, "PBKDF2 work too large")

	// Raising the limit on the protecting side produces the message a peer
	// outside this library's limits would send.
	relaxed := params
	relaxed.MaxIterationCount = 1 << 30
	msg := newMessage()
	require.NoError(t, msg.protectWithPBMAC1Options(relaxed))
	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(encoded)
	require.NoError(t, err)

	_, err = parsed.Verify(VerifyOptions{SharedSecret: secret})
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Detail, "PBKDF2 work too large")

	_, err = parsed.Verify(VerifyOptions{SharedSecret: secret, MaxMACIterationCount: 1 << 30})
	assert.NoError(t, err, "a verifier that permits the work accepts the MAC")
}

// The default maximum leaves room for the PBMAC1 parameters the Siemens CMP
// test suite sends with every PRF: 262144 iterations and a 32-byte key, which
// take two blocks from HMAC-SHA224.
func TestDefaultMaximumAcceptsTwoBlockDerivation(t *testing.T) {
	secret := []byte("shared-secret")
	msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryName(pkix.Name{CommonName: "sender"})})
	require.NoError(t, msg.protectWithPBMAC1Options(pbmac1Options{
		Secret:         secret,
		IterationCount: 262144,
		KeyLength:      32,
		PRF:            oidHMACWithSHA224,
		MAC:            oidHMACWithSHA224,
	}))
	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(encoded)
	require.NoError(t, err)

	vr, err := parsed.Verify(VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}
