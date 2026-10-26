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
	// cost seven times the 100000 iterations they declare.
	params := pbmac1Options{
		Secret:         secret,
		IterationCount: 100000,
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
