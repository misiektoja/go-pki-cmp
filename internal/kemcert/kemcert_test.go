package kemcert_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestCreateCertificate(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	spki, err := pkicmp.MarshalPublicKey(kem.EncapsulationKey())
	require.NoError(t, err)

	for name, signer := range map[string]crypto.Signer{"ECDSA": ecKey, "RSA": rsaKey} {
		t.Run(name, func(t *testing.T) {
			caTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "KEM test CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, signer.Public(), signer)
			require.NoError(t, err)
			ca, err := x509.ParseCertificate(caDER)
			require.NoError(t, err)

			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(7),
				Subject:      pkix.Name{CommonName: "ML-KEM end entity"},
				NotBefore:    time.Now().Add(-time.Minute),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageKeyEncipherment,
			}
			der, err := kemcert.CreateCertificate(tmpl, ca, spki, signer)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			assert.Equal(t, spki, cert.RawSubjectPublicKeyInfo)
			assert.Nil(t, cert.PublicKey, "crypto/x509 does not know ML-KEM")
			assert.Equal(t, x509.KeyUsageKeyEncipherment, cert.KeyUsage)
			require.NoError(t, cert.CheckSignatureFrom(ca))
			pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			assert.True(t, pkicmp.PublicKeysEqual(pub, kem.EncapsulationKey()))
		})
	}
}
