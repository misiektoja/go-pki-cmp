package pkicmp_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// The default minimum is the 100 iterations RFC 4211 §4.4 requires. A peer
// that sends fewer is refused unless the verifier lowers the minimum, and
// credentials send fewer only with WithMACIterationLimits.
func TestDefaultMACIterationMinimum(t *testing.T) {
	secret := []byte("default-minimum-secret")
	assert.Equal(t, 100, pkicmp.DefaultMinMACIterationCount)
	below := pkicmp.DefaultMinMACIterationCount - 1

	for _, alg := range []struct {
		name string
		opts []pkicmp.MACCredentialOption
	}{
		{"PasswordBasedMac", []pkicmp.MACCredentialOption{pkicmp.WithPBM()}},
		{"PBMAC1", nil},
	} {
		t.Run(alg.name, func(t *testing.T) {
			creds, err := pkicmp.NewMACCredentials(secret, append(alg.opts, pkicmp.WithMACIterationCount(below))...)
			if err == nil {
				err = creds.Protect(pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{}))
			}
			var pe *pkicmp.ParseError
			require.ErrorAs(t, err, &pe, "sending below the default minimum")
			assert.Contains(t, pe.Detail, "iterationCount too small")

			msg := macProtected(t, secret, append(alg.opts, pkicmp.WithMACIterationCount(below), pkicmp.WithMACIterationLimits(below, 0))...)
			_, err = msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
			require.ErrorAs(t, err, &pe, "verifying below the default minimum")
			assert.Contains(t, pe.Detail, "iterationCount too small: 99 (minimum 100)")

			vr, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret, MinMACIterationCount: below})
			require.NoError(t, err)
			assert.True(t, vr.MACVerified)
		})
	}
}
