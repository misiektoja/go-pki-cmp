package server_test

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
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// newRolloverKey returns an ECDSA P-256 key when id is zero and an SLH-DSA key of parameter set id otherwise.
func newRolloverKey(t *testing.T, id slhdsa.ID) crypto.Signer {
	t.Helper()
	if id == 0 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	return newSLHDSAKey(t, id)
}

// signRolloverCert issues a root CA certificate for pub, signed by signer under
// parent or self-signed when parent is nil. Every root keeps the name "Root",
// as in RFC 4210 §4.4. Either key may be an SLH-DSA key, which crypto/x509 can
// neither certify nor sign with.
func signRolloverCert(t *testing.T, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
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
	if key, ok := signer.Public().(slhdsa.PublicKey); ok {
		oid, known := pkicmp.SLHDSAAlgorithmOID(key.ID)
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

// TestRootCAUpdateWithSLHDSARoots answers root CA key update requests (RFC
// 9483 §4.3.2) for rollovers in which the old root, the new root or both have
// SLH-DSA keys. The request names an SLH-DSA old root in two of them. The
// server checks the update before sending it, so a link certificate whose
// SLH-DSA signature does not verify becomes systemFailure.
func TestRootCAUpdateWithSLHDSARoots(t *testing.T) {
	f := newRevocationFixture(t)
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
			oldKey, newKey := newRolloverKey(t, r.old), newRolloverKey(t, r.new)
			oldRoot := signRolloverCert(t, oldKey.Public(), nil, oldKey)
			newRoot := signRolloverCert(t, newKey.Public(), nil, newKey)
			update := &pkicmp.RootCAKeyUpdate{
				NewWithNew: newRoot,
				NewWithOld: signRolloverCert(t, newKey.Public(), oldRoot, oldKey),
				OldWithNew: signRolloverCert(t, oldKey.Public(), newRoot, newKey),
			}
			ca := &generalCA{update: update}
			ts := f.serve(t, ca, server.LightweightPolicy())

			items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.NewRootCACertInfo(oldRoot))))
			require.Len(t, items, 1)
			got, err := pkicmp.ParseRootCAKeyUpdateInfo(items[0])
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.True(t, got.NewWithNew.Equal(update.NewWithNew))
			assert.True(t, got.NewWithOld.Equal(update.NewWithOld))
			assert.True(t, got.OldWithNew.Equal(update.OldWithNew))
			require.NoError(t, got.Verify(oldRoot))
			assert.True(t, ca.oldRoot.Equal(oldRoot), "the CA receives the root the request names")

			// The other root has an SLH-DSA key, so each forged link certificate
			// carries a well-formed SLH-DSA signature by the wrong key.
			otherKey := newRolloverKey(t, slhdsa.SHA2_128f)
			other := signRolloverCert(t, otherKey.Public(), nil, otherKey)
			forged := map[string]*pkicmp.RootCAKeyUpdate{
				"NewWithOldSignedByOther": {
					NewWithNew: newRoot,
					NewWithOld: signRolloverCert(t, newKey.Public(), other, otherKey),
				},
				"OldWithNewSignedByOther": {
					NewWithNew: newRoot,
					NewWithOld: update.NewWithOld,
					OldWithNew: signRolloverCert(t, oldKey.Public(), other, otherKey),
				},
				"NewWithNewNotSelfSigned": {
					NewWithNew: signRolloverCert(t, newKey.Public(), other, otherKey),
					NewWithOld: update.NewWithOld,
				},
			}
			for name, u := range forged {
				t.Run(name, func(t *testing.T) {
					ts := f.serve(t, &generalCA{update: u}, server.LightweightPolicy())
					resp := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.NewRootCACertInfo(oldRoot)))
					require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
					si := statusInfoOf(t, resp)
					assert.Equal(t, pkicmp.StatusRejection, si.Status)
					assert.Equal(t, pkicmp.FailSystemFailure, si.FailInfo)
				})
			}
		})
	}
}
