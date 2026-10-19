package certpath

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
)

// slhdsaKey generates a key of the fastest SLH-DSA parameter set.
func slhdsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(t, err)
	return key
}

// spki encodes a public key as a SubjectPublicKeyInfo, writing SLH-DSA keys
// with absent parameters as RFC 9909 §4 requires.
func spki(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	key, ok := slhdsasig.Key(pub)
	if !ok {
		der, err := x509.MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
		return der
	}
	oid, ok := slhdsasig.OID(key.ID)
	require.True(t, ok)
	raw, err := key.MarshalBinary()
	require.NoError(t, err)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid) })
		b.AddASN1BitString(raw)
	})
	der, err := b.Bytes()
	require.NoError(t, err)
	return der
}

// issueSLHDSA certifies key with tmpl, signed by an issuer with an SLH-DSA key
// or self-signed with key when issuer is nil.
func issueSLHDSA(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, issuer *party) *party {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	if tmpl.IsCA {
		tmpl.SubjectKeyId = serial.Bytes()
	}
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	pub, _ := slhdsasig.Key(signer.Public())
	oid, ok := slhdsasig.OID(pub.ID)
	require.True(t, ok, "the issuer key is SLH-DSA")
	der, err := kemcert.CreateSLHDSACertificate(tmpl, parent, spki(t, key.Public()), oid, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &party{cert: cert, key: key}
}

// issueSLHDSASubject certifies the SLH-DSA key of a CA with tmpl, signed by a
// classical issuer.
func issueSLHDSASubject(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, issuer *party) *party {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	tmpl.SubjectKeyId = serial.Bytes()
	der, err := kemcert.CreateCertificate(tmpl, issuer.cert, spki(t, key.Public()), issuer.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &party{cert: cert, key: key}
}

// TestVerifySLHDSAPaths covers paths with links that SLH-DSA keys signed.
func TestVerifySLHDSAPaths(t *testing.T) {
	t.Run("SLH-DSA root", func(t *testing.T) {
		root := issueSLHDSA(t, caTemplate("Root"), slhdsaKey(t), nil)
		leaf := issueSLHDSA(t, leafTemplate(), ecdsaKey(t), root)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()))
		// A CertPool cannot return the anchor, so the root must also be a candidate.
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), nil, time.Now()), errUntrusted)
	})
	t.Run("SLH-DSA intermediate below classical root", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), ecdsaKey(t), nil)
		inter := issueSLHDSASubject(t, caTemplate("Intermediate"), slhdsaKey(t), root)
		leaf := issueSLHDSA(t, leafTemplate(), ecdsaKey(t), inter)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert}, time.Now()))
	})
	t.Run("other SLH-DSA key with the same name", func(t *testing.T) {
		root := issueSLHDSA(t, caTemplate("Root"), slhdsaKey(t), nil)
		impostor := issueSLHDSA(t, caTemplate("Root"), slhdsaKey(t), nil)
		leaf := issueSLHDSA(t, leafTemplate(), ecdsaKey(t), impostor)
		candidates := []*x509.Certificate{impostor.cert, root.cert}
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), candidates, time.Now()), errUntrusted)
	})
	t.Run("SLH-DSA issuer is not a CA", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		root := issueSLHDSA(t, tmpl, slhdsaKey(t), nil)
		leaf := issueSLHDSA(t, leafTemplate(), ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()), errUntrusted)
	})
}
