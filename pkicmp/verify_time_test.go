package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// expiredSignature returns a parsed message signed with a certificate valid from three to one hours before now, the
// signer certificate and a pool holding its CA, which became valid within the signer's validity and is still valid.
func expiredSignature(t *testing.T, now time.Time) (*pkicmp.PKIMessage, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-150 * time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Signer"},
		NotBefore:    now.Add(-3 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		SubjectKeyId: []byte{0xAA, 0xBB, 0xCC},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
	require.NoError(t, err)
	signerCert, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(signerCert.RawSubject),
	})
	mustProtectSig(t, msg, signerKey, signerCert)
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return parsed, signerCert, pool
}

// CurrentTime sets when the protection certificate and its chain must be valid, and the zero value means the time
// of the call. A TrustedCert is checked alone, so the validity of its CA does not matter.
func TestVerifyCurrentTime(t *testing.T) {
	now := time.Now()
	msg, signerCert, pool := expiredSignature(t, now)
	// ReasonUnknown stands for a message that verifies.
	cases := map[string]struct {
		at          time.Time
		trustedCert pkicmp.InvalidReason
		chain       pkicmp.InvalidReason
	}{
		"zero value":            {trustedCert: pkicmp.ReasonCertificateExpired, chain: pkicmp.ReasonUntrustedSigner},
		"signer and CA valid":   {at: now.Add(-2 * time.Hour)},
		"signer not yet valid":  {at: now.Add(-3*time.Hour - time.Second), trustedCert: pkicmp.ReasonCertificateExpired, chain: pkicmp.ReasonUntrustedSigner},
		"signer just expired":   {at: now.Add(-time.Hour + time.Second), trustedCert: pkicmp.ReasonCertificateExpired, chain: pkicmp.ReasonUntrustedSigner},
		"CA not yet valid":      {at: now.Add(-165 * time.Minute), chain: pkicmp.ReasonUntrustedSigner},
		"last second of signer": {at: signerCert.NotAfter},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Run("trusted certificate", func(t *testing.T) {
				vr, err := msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert, CurrentTime: tc.at})
				assertVerifiedAt(t, vr, err, signerCert, tc.trustedCert)
			})
			t.Run("chain", func(t *testing.T) {
				vr, err := msg.Verify(pkicmp.VerifyOptions{
					TrustPool:   pool,
					ExtraCerts:  msg.ExtraCerts,
					SenderKID:   msg.Header.SenderKID,
					CurrentTime: tc.at,
				})
				assertVerifiedAt(t, vr, err, signerCert, tc.chain)
			})
		})
	}
}

// assertVerifiedAt checks that verification accepted signer when reason is ReasonUnknown and failed with reason
// otherwise.
func assertVerifiedAt(t *testing.T, vr *pkicmp.VerifyResult, err error, signer *x509.Certificate, reason pkicmp.InvalidReason) {
	t.Helper()
	if reason == pkicmp.ReasonUnknown {
		require.NoError(t, err)
		assert.True(t, vr.ProtectionCertificate.Equal(signer))
		return
	}
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, reason, ve.Reason)
}
