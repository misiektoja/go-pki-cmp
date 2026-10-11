package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestNewMACCredentials(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		creds, err := pkicmp.NewMACCredentials([]byte("secret"))
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("EmptySecret", func(t *testing.T) {
		_, err := pkicmp.NewMACCredentials([]byte{})
		require.Error(t, err)
		var pe *pkicmp.ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, pkicmp.ReasonMissingSharedSecret, pe.Reason)
	})

	t.Run("NilSecret", func(t *testing.T) {
		_, err := pkicmp.NewMACCredentials(nil)
		require.Error(t, err)
	})

	t.Run("SecretIsCopied", func(t *testing.T) {
		original := []byte("secret")
		creds, _ := pkicmp.NewMACCredentials(original)
		original[0] = 'X'
		// Verify the credential still works with the original value by protecting a message
		msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})
		err := creds.Protect(msg)
		require.NoError(t, err)
	})
}

func TestNewSignatureCredentials(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	caCert, _ = x509.ParseCertificate(caDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Signer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
	signerCert, _ := x509.ParseCertificate(signerDER)

	t.Run("Valid", func(t *testing.T) {
		creds, err := pkicmp.NewSignatureCredentials(signerKey, signerCert)
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("WithChain", func(t *testing.T) {
		creds, err := pkicmp.NewSignatureCredentials(signerKey, signerCert, caCert)
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("NilKey", func(t *testing.T) {
		_, err := pkicmp.NewSignatureCredentials(nil, signerCert)
		require.Error(t, err)
		var pe *pkicmp.ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, pkicmp.ReasonMissingSigner, pe.Reason)
	})

	t.Run("NilCert", func(t *testing.T) {
		_, err := pkicmp.NewSignatureCredentials(signerKey, nil)
		require.Error(t, err)
	})

	t.Run("KeyCertMismatch", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, err := pkicmp.NewSignatureCredentials(otherKey, signerCert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})
}

func TestProtectWithCredentials(t *testing.T) {
	t.Run("MAC", func(t *testing.T) {
		creds, _ := pkicmp.NewMACCredentials([]byte("secret"))
		msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})

		err := creds.Protect(msg)
		require.NoError(t, err)
		assert.NotEmpty(t, msg.Protection)
		assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}, msg.Header.ProtectionAlg.Algorithm)
	})

	t.Run("Signature", func(t *testing.T) {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caCert := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "CA"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
		caCert, _ = x509.ParseCertificate(caDER)

		signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signerTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "Signer"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			SubjectKeyId: []byte{0xAA},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		signerDER, _ := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
		signerCert, _ := x509.ParseCertificate(signerDER)

		creds, _ := pkicmp.NewSignatureCredentials(signerKey, signerCert)
		msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{})

		err := creds.Protect(msg)
		require.NoError(t, err)
		assert.NotEmpty(t, msg.Protection)
		assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, msg.Header.ProtectionAlg.Algorithm)
	})
}
