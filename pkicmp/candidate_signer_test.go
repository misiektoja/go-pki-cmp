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

// signedWithoutExtraCerts returns a parsed signature-protected message whose extraCerts were removed after signing.
func signedWithoutExtraCerts(t *testing.T) (*pkicmp.PKIMessage, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caCert, signerKey, signerCert := generateCAAndSigner(t)
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(signerCert.RawSubject),
	})
	mustProtectSig(t, msg, signerKey, signerCert)
	// extraCerts are outside the protected part, so the signature still verifies without them.
	msg.ExtraCerts = nil

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	require.Empty(t, parsed.ExtraCerts)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return parsed, signerCert, pool
}

// A signed message with no certificate to verify it is reported as such rather than as a bad signature.
func TestVerifyReportsNoCandidateSigner(t *testing.T) {
	msg, signerCert, pool := signedWithoutExtraCerts(t)

	cases := map[string][]pkicmp.CMPCertificate{
		"no certificates":        nil,
		"unparseable only":       {{Raw: []byte{0x30, 0x00}}},
		"senderKID matches none": {{Raw: otherCertificate(t).Raw}},
	}
	for name, extraCerts := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := msg.Verify(pkicmp.VerifyOptions{TrustPool: pool, ExtraCerts: extraCerts, SenderKID: msg.Header.SenderKID})
			var ve *pkicmp.VerificationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, pkicmp.ReasonNoCandidateSigner, ve.Reason)
		})
	}

	t.Run("out-of-band signer certificate", func(t *testing.T) {
		vr, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: []pkicmp.CMPCertificate{{Raw: signerCert.Raw}},
			SenderKID:  msg.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.Equal(t, signerCert.Raw, vr.ProtectionCertificate.Raw)
	})

	t.Run("missing trust anchors take precedence", func(t *testing.T) {
		_, err := msg.Verify(pkicmp.VerifyOptions{SenderKID: msg.Header.SenderKID})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)
	})
}

// A message whose candidate signers all fail the chain is reported as untrusted, because no signature was
// checked. A trusted candidate with the wrong key still makes it a signature failure.
func TestVerifyReportsUntrustedSigner(t *testing.T) {
	msg, _, pool := signedWithoutExtraCerts(t)
	// Each hierarchy has a signer with the same name and senderKID as the message signer but its own key.
	otherCA, _, otherSigner := generateCAAndSigner(t)
	_, _, untrustedSigner := generateCAAndSigner(t)

	t.Run("no candidate chains", func(t *testing.T) {
		_, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: []pkicmp.CMPCertificate{{Raw: untrustedSigner.Raw}},
			SenderKID:  msg.Header.SenderKID,
		})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonUntrustedSigner, ve.Reason)
		var unknownAuthority x509.UnknownAuthorityError
		assert.ErrorAs(t, err, &unknownAuthority)
	})

	t.Run("a trusted candidate with another key", func(t *testing.T) {
		both := pool.Clone()
		both.AddCert(otherCA)
		_, err := msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  both,
			ExtraCerts: []pkicmp.CMPCertificate{{Raw: untrustedSigner.Raw}, {Raw: otherSigner.Raw}},
			SenderKID:  msg.Header.SenderKID,
		})
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonSignatureFailed, ve.Reason)
	})
}

// A response may carry its CA certificates next to the signer's without a senderKID, as NCM sends them. The failure of
// the certificate with the sender's name is reported, not that the trusted CA certificate has another name.
func TestVerifyReportsTheSendersCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caCert := selfSignedCA(t, caKey, "Test CA")
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerCert := issueSigner(t, caCert, caKey, signerKey, x509.KeyUsageDigitalSignature)
	// NCM signs with its issuing CA certificate, which may only sign certificates and CRLs.
	certSignOnly := issueSigner(t, caCert, caKey, signerKey, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)

	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(signerCert.RawSubject),
	})
	mustProtectSig(t, msg, signerKey, signerCert)
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	cases := []struct {
		name       string
		damage     bool
		extraCerts []*x509.Certificate
		opts       pkicmp.VerifyOptions
		reason     pkicmp.InvalidReason
	}{
		{name: "verifies", extraCerts: []*x509.Certificate{caCert, signerCert}},
		{name: "damaged signature", damage: true, extraCerts: []*x509.Certificate{caCert, signerCert}, reason: pkicmp.ReasonSignatureFailed},
		{
			name:       "signer expired",
			extraCerts: []*x509.Certificate{caCert, signerCert},
			opts:       pkicmp.VerifyOptions{CurrentTime: signerCert.NotAfter.Add(time.Second)},
			reason:     pkicmp.ReasonUntrustedSigner,
		},
		{
			name:       "signer not permitted to sign",
			extraCerts: []*x509.Certificate{caCert, certSignOnly},
			opts:       pkicmp.VerifyOptions{RequireDigitalSignatureKeyUsage: true},
			reason:     pkicmp.ReasonKeyUsageNotPermitted,
		},
		{name: "only certificates of other names", extraCerts: []*x509.Certificate{caCert, otherCertificate(t)}, reason: pkicmp.ReasonSenderMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pkicmp.ParsePKIMessage(der)
			require.NoError(t, err)
			if tc.damage {
				parsed.Protection[len(parsed.Protection)/2] ^= 0xff
			}
			opts := tc.opts
			opts.TrustPool = pool
			for _, cert := range tc.extraCerts {
				opts.ExtraCerts = append(opts.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
			}
			vr, err := parsed.Verify(opts)
			if tc.reason == pkicmp.ReasonUnknown {
				require.NoError(t, err)
				assert.True(t, vr.ProtectionCertificate.Equal(signerCert))
				return
			}
			var ve *pkicmp.VerificationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, tc.reason, ve.Reason)
		})
	}
}

// issueSigner certifies key under issuer for the name Signer with the given key usage. The certificate expires half
// an hour before a CA from selfSignedCA.
func issueSigner(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Signer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// otherCertificate returns a certificate whose SubjectKeyId differs from the signer's.
func otherCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return selfSignedCA(t, key, "Other CA")
}
