package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestOneAsymmetricKey adds the public key to a PKCS #8 key and keeps a key that has one.
func TestOneAsymmetricKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	spki, err := pkicmp.MarshalPublicKey(&key.PublicKey)
	require.NoError(t, err)

	v2, err := oneAsymmetricKey(pkcs8, spki)
	require.NoError(t, err)
	s := cryptobyte.String(v2)
	var seq, publicKey, spkiSeq, bits cryptobyte.String
	var version int64
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1Integer(&version))
	assert.Equal(t, int64(1), version, "OneAsymmetricKey v2")
	require.True(t, seq.SkipASN1(cbasn1.SEQUENCE) && seq.SkipASN1(cbasn1.OCTET_STRING))
	require.True(t, seq.ReadASN1(&publicKey, cbasn1.Tag(1).ContextSpecific()) && seq.Empty())
	in := cryptobyte.String(spki)
	require.True(t, in.ReadASN1(&spkiSeq, cbasn1.SEQUENCE) && spkiSeq.SkipASN1(cbasn1.SEQUENCE) && spkiSeq.ReadASN1(&bits, cbasn1.BIT_STRING))
	assert.Equal(t, []byte(bits), []byte(publicKey))

	parsed, err := x509.ParsePKCS8PrivateKey(v2)
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed), "crypto/x509 reads the version 2 key")

	again, err := oneAsymmetricKey(v2, spki)
	require.NoError(t, err)
	assert.Equal(t, v2, again)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edSPKI, err := pkicmp.MarshalPublicKey(edKey.Public())
	require.NoError(t, err)
	_, err = oneAsymmetricKey(pkcs8, edSPKI)
	assert.ErrorContains(t, err, "different algorithms")
	_, err = oneAsymmetricKey([]byte{0x30, 0x00}, spki)
	assert.Error(t, err)
}

// TestKeyRecipient picks the shared secret or the protection key by key
// identifier or by issuer and serial. It refuses a key that cannot decrypt.
func TestKeyRecipient(t *testing.T) {
	s := &Server{}
	recipient, rid, err := s.keyRecipient(&SenderIdentity{MACVerified: true, secret: []byte("secret")})
	require.NoError(t, err)
	assert.Equal(t, cms.PWRIKEKPassword("secret"), recipient)
	assert.Equal(t, cms.RecipientID{}, rid)
	s.cfg.kgaAESKeyWrap = true
	recipient, _, err = s.keyRecipient(&SenderIdentity{MACVerified: true, secret: []byte("secret")})
	require.NoError(t, err)
	assert.Equal(t, cms.Password("secret"), recipient)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := func(key crypto.Signer, ski []byte) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "ee"}, SubjectKeyId: ski,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	withSKI := certificate(ecKey, []byte{5, 6, 7})
	_, rid, err = s.keyRecipient(&SenderIdentity{Certificate: withSKI})
	require.NoError(t, err)
	assert.Equal(t, []byte{5, 6, 7}, rid.SubjectKeyID)

	withoutSKI := certificate(ecKey, nil)
	_, rid, err = s.keyRecipient(&SenderIdentity{Certificate: withoutSKI})
	require.NoError(t, err)
	assert.Equal(t, cms.IssuerAndSerial(withoutSKI), rid)

	_, _, err = s.keyRecipient(&SenderIdentity{Certificate: certificate(edKey, nil)})
	var srvErr *Error
	require.ErrorAs(t, err, &srvErr)
	assert.Equal(t, pkicmp.FailBadAlg, srvErr.FailureInfo)
}
