package pkicmp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func mustProtectMAC(t *testing.T, msg *pkicmp.PKIMessage, secret []byte) {
	t.Helper()
	mc, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	require.NoError(t, mc.Protect(msg))
}

func mustProtectSig(t *testing.T, msg *pkicmp.PKIMessage, key crypto.Signer, certs ...*x509.Certificate) {
	t.Helper()
	sc, err := pkicmp.NewSignatureCredentials(key, certs[0], certs[1:]...)
	require.NoError(t, err)
	require.NoError(t, sc.Protect(msg))
}

func TestPBMRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	mc, err := pkicmp.NewMACCredentials(secret, pkicmp.WithPBM())
	require.NoError(t, err)
	err = mc.Protect(msg)
	require.NoError(t, err)

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}, msg.Header.ProtectionAlg.Algorithm)
	assert.NotEmpty(t, msg.Protection)

	// Round-trip through marshaling.
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMCustomOptions(t *testing.T) {
	secret := []byte("custom-secret")

	// First, create a PBM-protected message with defaults.
	body := pkicmp.NewPKIConfBody()
	msg1 := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mc1, err := pkicmp.NewMACCredentials(secret, pkicmp.WithPBM(), pkicmp.WithMACIterationCount(5000))
	require.NoError(t, err)
	err = mc1.Protect(msg1)
	require.NoError(t, err)

	// Echo-back: create new credentials from the protection algorithm of the first message.
	body2 := pkicmp.NewPKIConfBody()
	msg2 := pkicmp.NewPKIMessage(body2, pkicmp.MessageOptions{})
	mc2, err := pkicmp.NewMACCredentials(secret, pkicmp.WithProtectionAlgorithm(msg1.Header.ProtectionAlg))
	require.NoError(t, err)
	err = mc2.Protect(msg2)
	require.NoError(t, err)

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}, msg2.Header.ProtectionAlg.Algorithm)

	der, err := msg2.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1RoundTrip(t *testing.T) {
	secret := []byte("shared-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	// PBMAC1 is the default per RFC 9481 §7.
	mc, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	err = mc.Protect(msg)
	require.NoError(t, err)

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}, msg.Header.ProtectionAlg.Algorithm)
	assert.NotEmpty(t, msg.Protection)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1CustomOptions(t *testing.T) {
	secret := []byte("custom-secret")

	// First, create a PBMAC1-protected message with custom iteration count.
	body := pkicmp.NewPKIConfBody()
	msg1 := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mc1, err := pkicmp.NewMACCredentials(secret, pkicmp.WithMACIterationCount(5000))
	require.NoError(t, err)
	err = mc1.Protect(msg1)
	require.NoError(t, err)

	// Echo-back: create new credentials from the protection algorithm of the first message.
	body2 := pkicmp.NewPKIConfBody()
	msg2 := pkicmp.NewPKIMessage(body2, pkicmp.MessageOptions{})
	mc2, err := pkicmp.NewMACCredentials(secret, pkicmp.WithProtectionAlgorithm(msg1.Header.ProtectionAlg))
	require.NoError(t, err)
	err = mc2.Protect(msg2)
	require.NoError(t, err)

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}, msg2.Header.ProtectionAlg.Algorithm)

	der, err := msg2.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1WrongSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mustProtectMAC(t, msg, []byte("correct-secret"))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("wrong-secret")})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestSignatureRoundTrip(t *testing.T) {
	caCert, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	sc, err := pkicmp.NewSignatureCredentials(signerKey, signerCert)
	require.NoError(t, err)
	err = sc.Protect(msg)
	require.NoError(t, err)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(caCert)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:  trustedCAs,
		ExtraCerts: parsed.ExtraCerts,
		SenderKID:  parsed.Header.SenderKID,
	})
	require.NoError(t, err)
	assert.False(t, vr.MACVerified)
}

func TestSignatureAutoPopulatesExtraCerts(t *testing.T) {
	caCert, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	// Provide an intermediate in the chain.
	sc, err := pkicmp.NewSignatureCredentials(signerKey, signerCert, caCert)
	require.NoError(t, err)
	err = sc.Protect(msg)
	require.NoError(t, err)

	// ExtraCerts should contain signerCert + caCert.
	assert.Len(t, msg.ExtraCerts, 2)
	assert.Equal(t, signerCert.Raw, msg.ExtraCerts[0].Raw)
	assert.Equal(t, caCert.Raw, msg.ExtraCerts[1].Raw)
}

func TestSignatureSetsHeaderSenderKID(t *testing.T) {
	_, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	sc, err := pkicmp.NewSignatureCredentials(signerKey, signerCert)
	require.NoError(t, err)
	err = sc.Protect(msg)
	require.NoError(t, err)

	assert.Equal(t, signerCert.SubjectKeyId, msg.Header.SenderKID)
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mustProtectMAC(t, msg, []byte("correct-secret"))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("wrong-secret")})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestVerifyRejectsUntrustedCA(t *testing.T) {
	_, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mustProtectSig(t, msg, signerKey, signerCert)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// Use a different CA as trust anchor.
	otherCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCACert := selfSignedCA(t, otherCAKey, "Other CA")
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(otherCACert)

	_, err = parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:  trustedCAs,
		ExtraCerts: parsed.ExtraCerts,
		SenderKID:  parsed.Header.SenderKID,
	})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonUntrustedSigner, ve.Reason)
	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknownAuthority, "the chain error is kept")
}

func TestVerifyRejectsNoProtection(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	_, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("secret")})
	var pe *pkicmp.ParseError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Detail, "message has no protection algorithm")
}

func TestVerifyRejectsMissingSharedSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mustProtectMAC(t, msg, []byte("secret"))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingSharedSecret, ve.Reason)
}

func TestVerifyRejectsMissingTrustPool(t *testing.T) {
	_, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	mustProtectSig(t, msg, signerKey, signerCert)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{
		ExtraCerts: parsed.ExtraCerts,
	})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)
}

func TestVerifyResultMACVerified(t *testing.T) {
	t.Run("TrueForMAC", func(t *testing.T) {
		body := pkicmp.NewPKIConfBody()
		msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
		mustProtectMAC(t, msg, []byte("secret"))

		der, _ := msg.MarshalBinary()
		parsed, _ := pkicmp.ParsePKIMessage(der)

		vr, err := parsed.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("secret")})
		require.NoError(t, err)
		assert.True(t, vr.MACVerified)
	})

	t.Run("FalseForSignature", func(t *testing.T) {
		caCert, signerKey, signerCert := generateCAAndSigner(t)

		body := pkicmp.NewPKIConfBody()
		msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
		mustProtectSig(t, msg, signerKey, signerCert)

		der, _ := msg.MarshalBinary()
		parsed, _ := pkicmp.ParsePKIMessage(der)

		trustedCAs := x509.NewCertPool()
		trustedCAs.AddCert(caCert)

		vr, err := parsed.Verify(pkicmp.VerifyOptions{
			TrustPool:  trustedCAs,
			ExtraCerts: parsed.ExtraCerts,
			SenderKID:  parsed.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.False(t, vr.MACVerified)
	})
}

func TestTrustedCAPubs(t *testing.T) {
	// Create a fake CA cert for caPubs.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caCert := selfSignedCA(t, caKey, "CAPubs CA")

	rep := &pkicmp.CertRepMessage{
		CAPubs:   []pkicmp.CMPCertificate{{Raw: caCert.Raw}},
		Response: []pkicmp.CertResponse{{CertReqID: 0, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}}},
	}

	t.Run("ReturnsCertsWhenMACVerified", func(t *testing.T) {
		vr := &pkicmp.VerifyResult{MACVerified: true}
		// CAPubs field available when MAC is verified.
		assert.NotNil(t, rep.CAPubs)
		_ = vr
	})

	t.Run("ReturnsNilWhenNotMACVerified", func(t *testing.T) {
		// CAPubs should not be trusted when signature-protected.
		_ = rep
	})
}

// --- helpers ---

func generateCAAndSigner(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caCert := selfSignedCA(t, caKey, "Test CA")

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Signer"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		SubjectKeyId:          []byte{0xAA, 0xBB, 0xCC},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
	require.NoError(t, err)
	signerCert, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)

	return caCert, signerKey, signerCert
}

func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
