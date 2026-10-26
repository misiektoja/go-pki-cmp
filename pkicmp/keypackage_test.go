package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// newKGACertificate self-signs a certificate for key with the given extended key usages. crypto/x509 adds a subjectKeyIdentifier to a CA certificate even when ski is false.
func newKGACertificate(t *testing.T, key crypto.Signer, ski bool, isCA bool, ekus ...asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "KGA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		UnknownExtKeyUsage:    ekus,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if ski {
		tmpl.SubjectKeyId = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return mustParseCertificate(t, der)
}

// mustParseCertificate parses a DER certificate.
func mustParseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// testOneAsymmetricKey returns a PKCS #8 key as the OneAsymmetricKey a key package carries.
func testOneAsymmetricKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

// TestKeyPackageRoundTrip signs a key package in both content forms with each signer family and parses it back.
func TestKeyPackageRoundTrip(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	cases := []struct {
		name   string
		key    crypto.Signer
		ski    bool
		digest asn1.ObjectIdentifier
	}{
		{"ECDSA P-384 with SKI", ecKey, true, oidSHA384},
		{"ECDSA P-384 by issuer and serial", ecKey, false, oidSHA384},
		{"RSA", rsaKey, true, oidSHA256},
		{"Ed25519", edKey, true, oidSHA512},
		{"ML-DSA-44", mlKey, true, oidSHA512},
	}
	forms := []struct {
		name        string
		form        KeyPackageContent
		contentType asn1.ObjectIdentifier
	}{
		{"id-data", KeyPackageData, oidData},
		{"AsymmetricKeyPackage", KeyPackageAsymmetricKeyPackage, oidAsymmetricKeyPackage},
	}
	for _, tc := range cases {
		for _, f := range forms {
			t.Run(tc.name+" "+f.name, func(t *testing.T) {
				cert := newKGACertificate(t, tc.key, tc.ski, false, OIDExtKeyUsageCMKGA)
				chain := newKGACertificate(t, tc.key, true, true)
				privateKey := testOneAsymmetricKey(t)

				der, err := NewKeyPackage(privateKey, f.form, tc.key, cert, chain)
				require.NoError(t, err)
				version, digest, contentType, sidTag := signedDataFields(t, der)
				// RFC 5652 §5.1: version 1 only for id-data signed by issuer and serial number.
				wantVersion := int64(3)
				if f.form == KeyPackageData && !tc.ski {
					wantVersion = 1
				}
				assert.Equal(t, wantVersion, version, "SignedData version")
				assert.Equal(t, tc.digest, digest)
				assert.Equal(t, f.contentType, contentType)
				if tc.ski {
					assert.Equal(t, cbasn1.Tag(0).ContextSpecific(), sidTag)
				} else {
					assert.Equal(t, cbasn1.SEQUENCE, sidTag)
				}

				pkg, err := ParseKeyPackage(der, KeyPackageOptions{})
				require.NoError(t, err)
				assert.Equal(t, privateKey, pkg.PrivateKey)
				assert.Equal(t, f.form, pkg.Content)
				assert.True(t, pkg.Signer.Equal(cert))
				require.Len(t, pkg.Certificates, 2)
				assert.True(t, pkg.Certificates[0].Equal(cert), "the KGA certificate comes first")
				assert.True(t, pkg.Certificates[1].Equal(chain))
			})
		}
	}

	_, err = NewKeyPackage(testOneAsymmetricKey(t), KeyPackageContent(9), ecKey, newKGACertificate(t, ecKey, true, false))
	assert.ErrorContains(t, err, "unknown key package content")
}

// signedDataFields returns the version, the digest algorithm, the content type and the sid tag of a SignedData with one SignerInfo.
func signedDataFields(t *testing.T, der []byte) (int64, asn1.ObjectIdentifier, asn1.ObjectIdentifier, cbasn1.Tag) {
	t.Helper()
	s := cryptobyte.String(der)
	var sd, digests, digest, eci, infos, info cryptobyte.String
	var version, siVersion int64
	var oid, contentType asn1.ObjectIdentifier
	var sidTag cbasn1.Tag
	require.True(t, s.ReadASN1(&sd, cbasn1.SEQUENCE) && sd.ReadASN1Integer(&version))
	require.True(t, sd.ReadASN1(&digests, cbasn1.SET) && digests.ReadASN1(&digest, cbasn1.SEQUENCE))
	require.True(t, digest.ReadASN1ObjectIdentifier(&oid))
	require.True(t, sd.ReadASN1(&eci, cbasn1.SEQUENCE) && eci.ReadASN1ObjectIdentifier(&contentType))
	require.True(t, sd.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed()))
	require.True(t, sd.ReadASN1(&infos, cbasn1.SET) && infos.ReadASN1(&info, cbasn1.SEQUENCE))
	require.True(t, info.ReadASN1Integer(&siVersion))
	var sid cryptobyte.String
	require.True(t, info.ReadAnyASN1(&sid, &sidTag))
	if sidTag == cbasn1.SEQUENCE {
		assert.Equal(t, int64(1), siVersion, "SignerInfo version")
	} else {
		assert.Equal(t, int64(3), siVersion, "SignerInfo version")
	}
	return version, oid, contentType, sidTag
}

// TestParseKeyPackageOpenSSL parses the id-data packages OpenSSL writes, signed by issuer and serial number or by key identifier.
func TestParseKeyPackageOpenSSL(t *testing.T) {
	sec1, err := os.ReadFile("testdata/keypackage/sec1.der")
	require.NoError(t, err)
	certPEM, err := os.ReadFile("testdata/keypackage/kga.crt")
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	kga := mustParseCertificate(t, block.Bytes)
	assert.True(t, IsKeyGenerationAuthority(kga))

	for _, name := range []string{"issuer-serial.der", "keyid.der"} {
		t.Run(name, func(t *testing.T) {
			der, err := os.ReadFile("testdata/keypackage/" + name)
			require.NoError(t, err)
			pkg, err := ParseKeyPackage(signedDataFromContentInfo(t, der), KeyPackageOptions{})
			require.NoError(t, err)
			assert.Equal(t, sec1, pkg.PrivateKey)
			assert.True(t, pkg.Signer.Equal(kga))
		})
	}
}

// signedDataFromContentInfo returns the SignedData inside a DER ContentInfo.
func signedDataFromContentInfo(t *testing.T, der []byte) []byte {
	t.Helper()
	s := cryptobyte.String(der)
	var ci, explicit, sd cryptobyte.String
	require.True(t, s.ReadASN1(&ci, cbasn1.SEQUENCE) && ci.SkipASN1(cbasn1.OBJECT_IDENTIFIER))
	require.True(t, ci.ReadASN1(&explicit, cbasn1.Tag(0).ContextSpecific().Constructed()))
	require.True(t, explicit.ReadASN1Element(&sd, cbasn1.SEQUENCE))
	return sd
}

// TestParseKeyPackageRejectsTampering refuses a changed key, a missing signer and a second key.
func TestParseKeyPackageRejectsTampering(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := newKGACertificate(t, key, true, false, OIDExtKeyUsageCMKGA)
	privateKey := testOneAsymmetricKey(t)
	der, err := NewKeyPackage(privateKey, KeyPackageData, key, cert)
	require.NoError(t, err)

	t.Run("changed key", func(t *testing.T) {
		tampered := append([]byte(nil), der...)
		i := indexOf(t, tampered, privateKey)
		tampered[i+len(privateKey)-1] ^= 1
		_, err := ParseKeyPackage(tampered, KeyPackageOptions{})
		var verr *VerificationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, err.Error(), "message-digest")
	})
	t.Run("changed signature", func(t *testing.T) {
		tampered := append([]byte(nil), der...)
		tampered[len(tampered)-1] ^= 1
		_, err := ParseKeyPackage(tampered, KeyPackageOptions{})
		var verr *VerificationError
		require.ErrorAs(t, err, &verr)
		assert.Equal(t, ReasonSignatureFailed, verr.Reason)
	})
	t.Run("signer certificate missing", func(t *testing.T) {
		tampered := append([]byte(nil), der...)
		// The last copy of the key identifier is the SignerInfo sid, not the certificate extension.
		i := bytes.LastIndex(tampered, cert.SubjectKeyId)
		require.Positive(t, i)
		tampered[i] ^= 0xff
		_, err := ParseKeyPackage(tampered, KeyPackageOptions{})
		assert.ErrorContains(t, err, "signer certificate")
	})
	t.Run("two keys", func(t *testing.T) {
		two, err := NewKeyPackage(append(append([]byte(nil), privateKey...), privateKey...), KeyPackageAsymmetricKeyPackage, key, cert)
		require.NoError(t, err)
		_, err = ParseKeyPackage(two, KeyPackageOptions{})
		assert.ErrorContains(t, err, "exactly one key")
	})
}

// indexOf returns the offset of sub in b.
func indexOf(t *testing.T, b, sub []byte) int {
	t.Helper()
	i := bytes.Index(b, sub)
	require.GreaterOrEqual(t, i, 0)
	return i
}

// TestIsKeyGenerationAuthority accepts the cmKGA extended key usage and a CA certificate.
func TestIsKeyGenerationAuthority(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.True(t, IsKeyGenerationAuthority(newKGACertificate(t, key, true, false, OIDExtKeyUsageCMKGA)))
	assert.True(t, IsKeyGenerationAuthority(newKGACertificate(t, key, true, true)))
	assert.False(t, IsKeyGenerationAuthority(newKGACertificate(t, key, true, false)))
	assert.False(t, IsKeyGenerationAuthority(newKGACertificate(t, key, true, false, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})))
}

// TestRequestsCentralKeyGeneration reads both template forms of RFC 9483 §4.1.6 after a marshal round trip.
func TestRequestsCentralKeyGeneration(t *testing.T) {
	ecAlg := AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := MarshalPublicKey(ecKey.Public())
	require.NoError(t, err)

	cases := []struct {
		name      string
		publicKey []byte
		want      bool
		algorithm *AlgorithmIdentifier
	}{
		{"no public key", nil, true, nil},
		{"zero-length key", CentralKeyGenerationPublicKey(ecAlg), true, &ecAlg},
		{"real key", spki, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b cryptobyte.Builder
			(&CertTemplate{PublicKey: tc.publicKey}).marshal(nil, &b)
			s := cryptobyte.String(b.BytesOrPanic())
			var tmpl CertTemplate
			require.NoError(t, tmpl.unmarshal(&s))

			algorithm, ok := tmpl.RequestsCentralKeyGeneration()
			assert.Equal(t, tc.want, ok)
			if tc.algorithm == nil {
				assert.Nil(t, algorithm)
				return
			}
			require.NotNil(t, algorithm)
			assert.Equal(t, tc.algorithm.Algorithm, algorithm.Algorithm)
			assert.Equal(t, tc.algorithm.Parameters, algorithm.Parameters)
		})
	}
}

// TestEncryptedPrivateKeyRoundTrip marshals an EnvelopedData private key, which needs CMP version 3.
func TestEncryptedPrivateKeyRoundTrip(t *testing.T) {
	envelope := []byte{0x30, 0x03, 0x02, 0x01, 0x03}
	ckp := CertifiedKeyPair{CertOrEncCert: CertOrEncCert{Certificate: &CMPCertificate{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}}}
	assert.Nil(t, ckp.EncryptedPrivateKey())
	ckp.SetEncryptedPrivateKey(envelope)

	mctx := &marshalContext{MinRequiredPVNO: PVNO2}
	var b cryptobyte.Builder
	ckp.marshal(mctx, &b)
	assert.Equal(t, PVNO3, mctx.MinRequiredPVNO)

	s := cryptobyte.String(b.BytesOrPanic())
	var got CertifiedKeyPair
	require.NoError(t, got.unmarshal(&s))
	assert.Equal(t, envelope, got.EncryptedPrivateKey())

	legacy := CertifiedKeyPair{PrivateKey: &encryptedKey{encryptedValue: &encryptedValue{Raw: envelope}}}
	assert.Nil(t, legacy.EncryptedPrivateKey(), "EncryptedValue is not an EnvelopedData")
}
