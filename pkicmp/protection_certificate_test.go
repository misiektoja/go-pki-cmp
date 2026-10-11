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

// RFC 9810 §4.5 extended key usages for CMP entities.
var oidKPCMCRA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 28}

type protectionCertOptions struct {
	commonName  string
	keyUsage    x509.KeyUsage
	setKeyUsage bool
	unknownEKU  []asn1.ObjectIdentifier
	knownEKU    []x509.ExtKeyUsage
}

// issueProtectionCert mints a CMP protection certificate under a fresh anchor.
func issueProtectionCert(t *testing.T, opts protectionCertOptions) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Protection Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: opts.commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		UnknownExtKeyUsage:    opts.unknownEKU,
		ExtKeyUsage:           opts.knownEKU,
	}
	if opts.setKeyUsage {
		template.KeyUsage = opts.keyUsage
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return key, cert, pool
}

// protectedPKIConf returns a parsed, signature-protected message from the given certificate.
func protectedPKIConf(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate) *pkicmp.PKIMessage {
	t.Helper()
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject),
	})
	creds, err := pkicmp.NewSignatureCredentials(key, cert)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))

	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(encoded)
	require.NoError(t, err)
	return parsed
}

// crypto/x509 demands serverAuth when VerifyOptions.KeyUsages is empty, which
// no CMP specification asks for. RFC 9810 §4.5 defines id-kp-cmcRA as a CMP
// extended key usage, so such a certificate must verify.
func TestProtectionCertificateWithCMPExtKeyUsageVerifies(t *testing.T) {
	key, cert, pool := issueProtectionCert(t, protectionCertOptions{
		commonName:  "cmcRA Responder",
		keyUsage:    x509.KeyUsageDigitalSignature,
		setKeyUsage: true,
		unknownEKU:  []asn1.ObjectIdentifier{oidKPCMCRA},
	})

	parsed := protectedPKIConf(t, key, cert)
	result, err := parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:  pool,
		ExtraCerts: parsed.ExtraCerts,
	})
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, result.ProtectionCertificate.Raw)
}

func TestProtectionCertificateWithClientAuthOnlyVerifies(t *testing.T) {
	key, cert, pool := issueProtectionCert(t, protectionCertOptions{
		commonName:  "clientAuth Responder",
		keyUsage:    x509.KeyUsageDigitalSignature,
		setKeyUsage: true,
		knownEKU:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	parsed := protectedPKIConf(t, key, cert)
	_, err := parsed.Verify(pkicmp.VerifyOptions{TrustPool: pool, ExtraCerts: parsed.ExtraCerts})
	require.NoError(t, err)
}

// Nokia NCM 26.7 protects responses with its issuing CA certificate, whose
// keyUsage omits digitalSignature, so the RFC 9483 §3.5 rule stays opt-in.
func TestProtectionCertificateWithoutDigitalSignatureVerifiesByDefault(t *testing.T) {
	key, cert, pool := issueProtectionCert(t, protectionCertOptions{
		commonName:  "CertSign Only Responder",
		keyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		setKeyUsage: true,
	})

	parsed := protectedPKIConf(t, key, cert)
	_, err := parsed.Verify(pkicmp.VerifyOptions{TrustPool: pool, ExtraCerts: parsed.ExtraCerts})
	require.NoError(t, err)
}

func TestProtectionCertificateWithoutDigitalSignatureRejectedWhenRequired(t *testing.T) {
	key, cert, pool := issueProtectionCert(t, protectionCertOptions{
		commonName:  "CertSign Only Responder",
		keyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		setKeyUsage: true,
	})

	parsed := protectedPKIConf(t, key, cert)
	_, err := parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:                       pool,
		ExtraCerts:                      parsed.ExtraCerts,
		RequireDigitalSignatureKeyUsage: true,
	})
	require.Error(t, err)

	var verr *pkicmp.VerificationError
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, pkicmp.ReasonKeyUsageNotPermitted, verr.Reason)
}

// The requirement is conditional on the extension being present, so a
// certificate without keyUsage stays acceptable even under the strict setting.
func TestProtectionCertificateWithoutKeyUsageExtensionVerifiesWhenRequired(t *testing.T) {
	key, cert, pool := issueProtectionCert(t, protectionCertOptions{commonName: "No KeyUsage Responder"})
	require.Zero(t, cert.KeyUsage)

	parsed := protectedPKIConf(t, key, cert)
	_, err := parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:                       pool,
		ExtraCerts:                      parsed.ExtraCerts,
		RequireDigitalSignatureKeyUsage: true,
	})
	require.NoError(t, err)
}
