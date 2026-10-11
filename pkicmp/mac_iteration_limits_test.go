package pkicmp_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// macProtected returns a pkiconf protected with the given credential options, after a DER round trip.
func macProtected(t *testing.T, secret []byte, opts ...pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	t.Helper()
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})
	creds, err := pkicmp.NewMACCredentials(secret, opts...)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	return parsed
}

// The receiver bounds the iteration count the sender chose, for both MAC
// algorithms, before deriving any key.
func TestVerifyMACIterationLimits(t *testing.T) {
	secret := []byte("iteration-limit-secret")
	for _, alg := range []struct {
		name string
		opts []pkicmp.MACCredentialOption
	}{
		{"PasswordBasedMac", []pkicmp.MACCredentialOption{pkicmp.WithPBM()}},
		{"PBMAC1", nil},
	} {
		t.Run(alg.name, func(t *testing.T) {
			msg := macProtected(t, secret, append(alg.opts, pkicmp.WithMACIterationCount(5000))...)

			for _, tc := range []struct {
				name     string
				min, max int
				detail   string
			}{
				{"AboveMaximum", 0, 4999, "iterationCount too large: 5000 (maximum 4999)"},
				{"BelowMinimum", 5001, 0, "iterationCount too small: 5000 (minimum 5001)"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					_, err := msg.Verify(pkicmp.VerifyOptions{
						SharedSecret:         secret,
						MinMACIterationCount: tc.min,
						MaxMACIterationCount: tc.max,
					})
					var pe *pkicmp.ParseError
					require.ErrorAs(t, err, &pe)
					assert.Contains(t, pe.Detail, tc.detail)
				})
			}

			t.Run("WithinRange", func(t *testing.T) {
				vr, err := msg.Verify(pkicmp.VerifyOptions{
					SharedSecret:         secret,
					MinMACIterationCount: 5000,
					MaxMACIterationCount: 5000,
				})
				require.NoError(t, err)
				assert.True(t, vr.MACVerified)
			})
		})
	}
}

// A count above the default maximum needs the limit raised on every side that
// handles it: the sender, the verifier and the responder that echoes it.
func TestMACIterationCountAboveDefaultMaximum(t *testing.T) {
	secret := []byte("raised-limit-secret")
	count := pkicmp.DefaultMaxMACIterationCount + 1
	for _, alg := range []struct {
		name string
		opts []pkicmp.MACCredentialOption
	}{
		{"PasswordBasedMac", []pkicmp.MACCredentialOption{pkicmp.WithPBM()}},
		{"PBMAC1", nil},
	} {
		t.Run(alg.name, func(t *testing.T) {
			creds, err := pkicmp.NewMACCredentials(secret, append(alg.opts, pkicmp.WithMACIterationCount(count))...)
			require.NoError(t, err)
			var pe *pkicmp.ParseError
			require.ErrorAs(t, creds.Protect(pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})), &pe)
			assert.Contains(t, pe.Detail, "iterationCount too large")

			msg := macProtected(t, secret, append(alg.opts, pkicmp.WithMACIterationCount(count), pkicmp.WithMACIterationLimits(0, count))...)

			_, err = msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
			require.ErrorAs(t, err, &pe)
			assert.Contains(t, pe.Detail, "iterationCount too large")

			vr, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret, MaxMACIterationCount: count})
			require.NoError(t, err)

			// The verified parameters carry the limits they were accepted under,
			// so echoing them needs no further option.
			echoed := macProtected(t, secret, vr.ProtectionParams)
			_, err = echoed.Verify(pkicmp.VerifyOptions{SharedSecret: secret, MinMACIterationCount: count, MaxMACIterationCount: count})
			require.NoError(t, err)

			// Raw parameters carry no limits, so the default maximum applies to
			// them until the caller widens it.
			raw, err := pkicmp.NewMACCredentials(secret, pkicmp.WithProtectionAlgorithm(msg.Header.ProtectionAlg))
			require.NoError(t, err)
			require.ErrorAs(t, raw.Protect(pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})), &pe)
			assert.Contains(t, pe.Detail, "iterationCount too large")

			widened := macProtected(t, secret, pkicmp.WithProtectionAlgorithm(msg.Header.ProtectionAlg), pkicmp.WithMACIterationLimits(0, count))
			_, err = widened.Verify(pkicmp.VerifyOptions{SharedSecret: secret, MinMACIterationCount: count, MaxMACIterationCount: count})
			require.NoError(t, err)
		})
	}
}
