package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
)

// newRolloverRoot returns a self-signed root CA whose key is key, which may be an SLH-DSA key.
func newRolloverRoot(t *testing.T, key crypto.Signer) genmTestCA {
	t.Helper()
	return genmTestCA{cert: signRolloverCert(t, key.Public(), nil, key), key: key}
}

// signRolloverCert issues a root CA certificate for pub, signed by signer under
// parent or self-signed when parent is nil. Every root keeps the name "Root",
// as in RFC 4210 §4.4. Either key may be an SLH-DSA key, which crypto/x509 can
// neither certify nor sign with.
func signRolloverCert(t *testing.T, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, err := MarshalPublicKey(pub)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	// The identifier depends only on the key, so a link certificate shares it with the root of its key.
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski[:20],
	}
	if parent == nil {
		parent = tmpl
	}
	var der []byte
	if key, ok := slhdsaPublicKey(signer.Public()); ok {
		oid, known := SLHDSAAlgorithmOID(key.ID)
		require.True(t, known)
		der, err = kemcert.CreateSLHDSACertificate(tmpl, parent, spki, oid, signer)
	} else {
		der, err = kemcert.CreateCertificate(tmpl, parent, spki, signer)
	}
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newRolloverKey returns a key for a root of the given kind, an ECDSA P-256 key
// when id is zero and an SLH-DSA key of parameter set id otherwise.
func newRolloverKey(t *testing.T, id slhdsa.ID) crypto.Signer {
	t.Helper()
	if id == 0 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	return newSLHDSAKey(t, id)
}

// TestRootCAKeyUpdateSLHDSA verifies root CA key updates (RFC 9483 §4.3.2)
// in which the old root, the new root or both have SLH-DSA keys, so that the
// link certificates carry SLH-DSA keys or signatures (RFC 4210 §4.4).
func TestRootCAKeyUpdateSLHDSA(t *testing.T) {
	rollovers := []struct {
		name     string
		old, new slhdsa.ID
	}{
		{"ECDSA to SLH-DSA", 0, slhdsa.SHA2_128f},
		{"SLH-DSA to SLH-DSA", slhdsa.SHA2_128f, slhdsa.SHAKE_128f},
		{"SLH-DSA to ECDSA", slhdsa.SHA2_128f, 0},
	}
	for _, r := range rollovers {
		t.Run(r.name, func(t *testing.T) {
			oldRoot := newRolloverRoot(t, newRolloverKey(t, r.old))
			newRoot := newRolloverRoot(t, newRolloverKey(t, r.new))
			update := &RootCAKeyUpdate{
				NewWithNew: newRoot.cert,
				NewWithOld: signRolloverCert(t, newRoot.key.Public(), oldRoot.cert, oldRoot.key),
				OldWithNew: signRolloverCert(t, oldRoot.key.Public(), newRoot.cert, newRoot.key),
			}

			item, err := NewRootCAKeyUpdateInfo(update)
			require.NoError(t, err)
			parsed, err := ParseRootCAKeyUpdateInfo(item)
			require.NoError(t, err)
			assert.True(t, parsed.NewWithNew.Equal(update.NewWithNew))
			assert.True(t, parsed.NewWithOld.Equal(update.NewWithOld))
			assert.True(t, parsed.OldWithNew.Equal(update.OldWithNew))
			require.NoError(t, parsed.Verify(oldRoot.cert))
			require.NoError(t, parsed.Verify(nil), "newWithNew alone is self-signed")
			partial := *parsed
			partial.OldWithNew = nil
			require.NoError(t, partial.Verify(oldRoot.cert), "oldWithNew is optional")

			// The other root has an SLH-DSA key, so a forged link certificate
			// carries a well-formed SLH-DSA signature by the wrong key.
			other := newRolloverRoot(t, newRolloverKey(t, slhdsa.SHA2_128f))
			failures := []struct {
				name   string
				change func(u *RootCAKeyUpdate)
				old    *x509.Certificate
			}{
				{"WrongOldRoot", func(*RootCAKeyUpdate) {}, other.cert},
				{"NewWithOldSignedByOther", func(u *RootCAKeyUpdate) {
					u.NewWithOld = signRolloverCert(t, newRoot.key.Public(), other.cert, other.key)
				}, oldRoot.cert},
				{"NewWithOldForOtherKey", func(u *RootCAKeyUpdate) {
					u.NewWithOld = signRolloverCert(t, other.key.Public(), oldRoot.cert, oldRoot.key)
				}, oldRoot.cert},
				{"NewWithOldSignatureTampered", func(u *RootCAKeyUpdate) {
					tampered := *u.NewWithOld
					tampered.Signature = append([]byte(nil), u.NewWithOld.Signature...)
					tampered.Signature[len(tampered.Signature)/2] ^= 1
					u.NewWithOld = &tampered
				}, oldRoot.cert},
				{"NewWithNewNotSelfSigned", func(u *RootCAKeyUpdate) {
					u.NewWithNew = signRolloverCert(t, newRoot.key.Public(), other.cert, other.key)
				}, oldRoot.cert},
				{"OldWithNewSignedByOther", func(u *RootCAKeyUpdate) {
					u.OldWithNew = signRolloverCert(t, oldRoot.key.Public(), other.cert, other.key)
				}, oldRoot.cert},
			}
			for _, f := range failures {
				t.Run(f.name, func(t *testing.T) {
					u := *parsed
					f.change(&u)
					assert.Error(t, u.Verify(f.old))
				})
			}
		})
	}
}
