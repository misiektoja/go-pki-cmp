package pkicmp_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// signedMessage returns a parsed, signature-protected message with the given sender.
func signedMessage(t *testing.T, sender pkicmp.GeneralName) (*pkicmp.PKIMessage, *x509.CertPool) {
	t.Helper()
	caCert, signerKey, signerCert := generateCAAndSigner(t)

	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{Sender: sender})
	mustProtectSig(t, msg, signerKey, signerCert)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return parsed, pool
}

// Chaining to a trust anchor proves a certificate is trusted, not that it belongs
// to the sender the header names. RFC 9483 §3.5 requires the sender field to match
// the subject of the CMP protection certificate.
func TestVerifySignatureBindsSenderToCertificate(t *testing.T) {
	t.Run("SenderMatchesSubject", func(t *testing.T) {
		msg, pool := signedMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "Signer"}))

		vr, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: msg.ExtraCerts,
			SenderKID:  msg.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.False(t, vr.MACVerified)
	})

	// The attack from the review: a certificate that chains to a configured
	// anchor but belongs to an unrelated identity.
	t.Run("SenderNamesDifferentIdentity", func(t *testing.T) {
		msg, pool := signedMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "totally-unrelated-service"}))

		_, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: msg.ExtraCerts,
			SenderKID:  msg.Header.SenderKID,
		})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonSenderMismatch, ve.Reason)
	})

	// RFC 4210 §5.1.1 requires a NULL DN when the sender does not know its own
	// name, so there is nothing to bind and the message must still verify.
	t.Run("NullDNSenderStillVerifies", func(t *testing.T) {
		msg, pool := signedMessage(t, pkicmp.GeneralName{})

		vr, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: msg.ExtraCerts,
			SenderKID:  msg.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.False(t, vr.MACVerified)
	})
}

// A certificate resolved from the verifier's own database is trusted, which
// still says nothing about who sent the message. RFC 9483 §3.5 applies to this
// path exactly as it does to the chain-building one.
func TestVerifyTrustedCertBindsSenderToCertificate(t *testing.T) {
	trustedCertMessage := func(t *testing.T, sender pkicmp.GeneralName) (*pkicmp.PKIMessage, *x509.Certificate) {
		t.Helper()
		_, signerKey, signerCert := generateCAAndSigner(t)

		msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{Sender: sender})
		mustProtectSig(t, msg, signerKey, signerCert)

		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)
		return parsed, signerCert
	}

	t.Run("SenderMatchesSubject", func(t *testing.T) {
		msg, signerCert := trustedCertMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "Signer"}))

		vr, err := msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert})
		require.NoError(t, err)
		assert.Equal(t, signerCert, vr.ProtectionCertificate)
	})

	// A lookup keyed on senderKID alone returns the right certificate for the
	// wrong claimed identity, which is the case this check exists for.
	t.Run("SenderNamesDifferentIdentity", func(t *testing.T) {
		msg, signerCert := trustedCertMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "privileged-service"}))

		_, err := msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonSenderMismatch, ve.Reason)
	})

	// RFC 4210 §5.1.1 NULL DN carries no name to bind, and the certificate the
	// verifier resolved is what authenticates the message.
	t.Run("NullDNSenderStillVerifies", func(t *testing.T) {
		msg, signerCert := trustedCertMessage(t, pkicmp.GeneralName{})

		vr, err := msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert})
		require.NoError(t, err)
		assert.Equal(t, signerCert, vr.ProtectionCertificate)
	})
}

// RFC 9483 §3.1 requires the same kind of protection for every message of a PKI
// management operation, and RFC 9810 §5.2.3 gives the mismatch its own failInfo
// bit. A verifier that pins the mechanism must not accept the other one.
func TestVerifyRequiredProtection(t *testing.T) {
	secret := []byte("shared-secret")

	macMessage := func(t *testing.T) *pkicmp.PKIMessage {
		t.Helper()
		msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})
		mustProtectMAC(t, msg, secret)
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)
		return parsed
	}

	t.Run("MACMessageRejectedWhenSignatureRequired", func(t *testing.T) {
		msg := macMessage(t)

		_, err := msg.Verify(pkicmp.VerifyOptions{
			RequiredProtection: pkicmp.ProtectionSignature,
			SharedSecret:       secret,
		})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonUnexpectedProtection, ve.Reason)
	})

	t.Run("SignatureMessageRejectedWhenMACRequired", func(t *testing.T) {
		msg, pool := signedMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "Signer"}))

		_, err := msg.Verify(pkicmp.VerifyOptions{
			RequiredProtection: pkicmp.ProtectionMAC,
			SharedSecret:       secret,
			TrustPool:          pool,
			ExtraCerts:         msg.ExtraCerts,
		})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonUnexpectedProtection, ve.Reason)
	})

	t.Run("MatchingMechanismAccepted", func(t *testing.T) {
		msg := macMessage(t)

		vr, err := msg.Verify(pkicmp.VerifyOptions{
			RequiredProtection: pkicmp.ProtectionMAC,
			SharedSecret:       secret,
		})
		require.NoError(t, err)
		assert.True(t, vr.MACVerified)
	})

	// A server cannot know which mechanism a peer will use for the first message
	// of an operation, so the zero value must keep accepting either one.
	t.Run("ProtectionAnyAcceptsEither", func(t *testing.T) {
		msg := macMessage(t)

		vr, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
		require.NoError(t, err)
		assert.True(t, vr.MACVerified)

		sig, pool := signedMessage(t, pkicmp.NewDirectoryName(pkix.Name{CommonName: "Signer"}))
		vr, err = sig.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: sig.ExtraCerts,
			SenderKID:  sig.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.False(t, vr.MACVerified)
	})

	// Without a pinned mechanism a MAC-protected message still reports the
	// missing secret rather than a mechanism error.
	t.Run("ProtectionAnyReportsMissingSecret", func(t *testing.T) {
		msg := macMessage(t)

		_, err := msg.Verify(pkicmp.VerifyOptions{})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonMissingSharedSecret, ve.Reason)
	})
}
