package slhdsasig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// slhdsaKey generates a key of the fastest SLH-DSA parameter set.
func slhdsaKey(t *testing.T) *slhdsa.PrivateKey {
	t.Helper()
	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(t, err)
	return &key
}

// ecdsaKey generates an ECDSA P-256 key.
func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// template returns a certificate template valid for one hour around now, for a
// CA when ca is set.
func template(name string, ca bool) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		tmpl.SubjectKeyId = []byte(name)
	}
	return tmpl
}

// sign creates a certificate for pub with tmpl, signed by the SLH-DSA key of
// parent, or self-signed when parent is tmpl.
func sign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, priv *slhdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
	oid, ok := slhdsasig.OID(priv.ID)
	require.True(t, ok)
	der, err := kemcert.CreateSLHDSACertificate(tmpl, parent, spki, oid, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestIdentifiers checks that every parameter set maps to its RFC 9909 identifier and back.
func TestIdentifiers(t *testing.T) {
	ids := []slhdsa.ID{
		slhdsa.SHA2_128s, slhdsa.SHA2_128f, slhdsa.SHA2_192s, slhdsa.SHA2_192f, slhdsa.SHA2_256s, slhdsa.SHA2_256f,
		slhdsa.SHAKE_128s, slhdsa.SHAKE_128f, slhdsa.SHAKE_192s, slhdsa.SHAKE_192f, slhdsa.SHAKE_256s, slhdsa.SHAKE_256f,
	}
	for i, id := range ids {
		oid, ok := slhdsasig.OID(id)
		require.True(t, ok, id.String())
		require.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20 + i}, oid, id.String())
		back, ok := slhdsasig.FromOID(oid)
		require.True(t, ok)
		require.Equal(t, id, back)
	}
	_, ok := slhdsasig.FromOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19})
	require.False(t, ok, "ML-DSA-87 is not an SLH-DSA identifier")
}

// TestKey checks which public key values count as SLH-DSA keys.
func TestKey(t *testing.T) {
	priv := slhdsaKey(t)
	pub := priv.Public().(slhdsa.PublicKey)
	for _, candidate := range []crypto.PublicKey{pub, &pub} {
		got, ok := slhdsasig.Key(candidate)
		require.True(t, ok)
		require.True(t, got.Equal(pub))
	}
	_, ok := slhdsasig.Key((*slhdsa.PublicKey)(nil))
	require.False(t, ok)
	_, ok = slhdsasig.Key(ecdsaKey(t).Public())
	require.False(t, ok)
}

// TestVerify checks pure SLH-DSA signatures with an empty context.
func TestVerify(t *testing.T) {
	priv := slhdsaKey(t)
	data := []byte("to be signed")
	signature, err := priv.Sign(rand.Reader, data, crypto.Hash(0))
	require.NoError(t, err)
	require.NoError(t, slhdsasig.Verify(priv.ID, priv.Public(), data, signature))
	require.Error(t, slhdsasig.Verify(slhdsa.SHAKE_128f, priv.Public(), data, signature), "parameter set differs from the key")
	require.Error(t, slhdsasig.Verify(priv.ID, ecdsaKey(t).Public(), data, signature), "not an SLH-DSA key")
	require.Error(t, slhdsasig.Verify(priv.ID, priv.Public(), []byte("other data"), signature))
	require.Error(t, slhdsasig.Verify(priv.ID, slhdsaKey(t).Public(), data, signature), "other key")
}

// TestPublicKey checks the parsing of SubjectPublicKeyInfo structures.
func TestPublicKey(t *testing.T) {
	priv := slhdsaKey(t)
	spki, err := pkicmp.MarshalPublicKey(priv.Public())
	require.NoError(t, err)
	pub, ok, err := slhdsasig.PublicKey(spki)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, pub.Equal(priv.Public()))

	classical, err := x509.MarshalPKIXPublicKey(ecdsaKey(t).Public())
	require.NoError(t, err)
	_, ok, err = slhdsasig.PublicKey(classical)
	require.NoError(t, err)
	require.False(t, ok)

	oid, _ := slhdsasig.OID(priv.ID)
	raw, err := pub.MarshalBinary()
	require.NoError(t, err)
	malformed := map[string]func(b *cryptobyte.Builder){
		"parameters present": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid); b.AddASN1NULL() })
			b.AddASN1BitString(raw)
		},
		"short key": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid) })
			b.AddASN1BitString(raw[1:])
		},
	}
	for name, body := range malformed {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, body)
		der, err := b.Bytes()
		require.NoError(t, err)
		_, ok, err := slhdsasig.PublicKey(der)
		require.True(t, ok, name)
		require.Error(t, err, name)
	}
}

// TestCheckSignatureFrom covers certificates issued by SLH-DSA and classical parents.
func TestCheckSignatureFrom(t *testing.T) {
	rootKey := slhdsaKey(t)
	rootTmpl := template("Root", true)
	root := sign(t, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	require.NoError(t, slhdsasig.CheckSignatureFrom(root, root))

	leaf := sign(t, template("Leaf", false), root, ecdsaKey(t).Public(), rootKey)
	require.NoError(t, slhdsasig.CheckSignatureFrom(leaf, root))

	t.Run("tampered signature", func(t *testing.T) {
		tampered := *leaf
		tampered.Signature = append([]byte(nil), leaf.Signature...)
		tampered.Signature[0] ^= 1
		require.Error(t, slhdsasig.CheckSignatureFrom(&tampered, root))
	})
	t.Run("other SLH-DSA key", func(t *testing.T) {
		otherKey := slhdsaKey(t)
		other := sign(t, rootTmpl, rootTmpl, otherKey.Public(), otherKey)
		require.Error(t, slhdsasig.CheckSignatureFrom(leaf, other))
	})
	t.Run("parent without certificate signing", func(t *testing.T) {
		tmpl := template("Signer", true)
		tmpl.KeyUsage = x509.KeyUsageCRLSign
		key := slhdsaKey(t)
		parent := sign(t, tmpl, tmpl, key.Public(), key)
		child := sign(t, template("Leaf", false), parent, ecdsaKey(t).Public(), key)
		require.ErrorAs(t, slhdsasig.CheckSignatureFrom(child, parent), new(x509.ConstraintViolationError))
	})
	t.Run("parent is not a CA", func(t *testing.T) {
		tmpl := template("Device", false)
		key := slhdsaKey(t)
		parent := sign(t, tmpl, tmpl, key.Public(), key)
		child := sign(t, template("Leaf", false), parent, ecdsaKey(t).Public(), key)
		require.ErrorAs(t, slhdsasig.CheckSignatureFrom(child, parent), new(x509.ConstraintViolationError))
	})
	t.Run("classical parent", func(t *testing.T) {
		key := ecdsaKey(t)
		tmpl := template("Classical", true)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		require.NoError(t, err)
		parent, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		der, err = x509.CreateCertificate(rand.Reader, template("Leaf", false), parent, ecdsaKey(t).Public(), key)
		require.NoError(t, err)
		child, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		require.NoError(t, slhdsasig.CheckSignatureFrom(child, parent))
		require.Error(t, slhdsasig.CheckSignatureFrom(leaf, parent), "an SLH-DSA signature under a classical parent")
		require.Error(t, slhdsasig.CheckSignatureFrom(child, root), "a classical signature under an SLH-DSA parent")
	})
}

// TestSignatureID checks that the outer signature algorithm is read from a
// signed structure and that SLH-DSA parameters must be absent.
func TestSignatureID(t *testing.T) {
	key := slhdsaKey(t)
	tmpl := template("Root", true)
	cert := sign(t, tmpl, tmpl, key.Public(), key)
	id, ok, err := slhdsasig.SignatureID(cert.Raw)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, key.ID, id)

	_, ok, err = slhdsasig.SignatureID([]byte{0x30, 0x00})
	require.NoError(t, err)
	require.False(t, ok)

	oid, _ := slhdsasig.OID(key.ID)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(cert.RawTBSCertificate)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid); b.AddASN1NULL() })
		b.AddASN1BitString(cert.Signature)
	})
	withParameters, err := b.Bytes()
	require.NoError(t, err)
	_, _, err = slhdsasig.SignatureID(withParameters)
	require.Error(t, err)
}
