package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
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
	_, key, err := slhdsa.GenerateKey(rand.Reader, id)
	require.NoError(t, err)
	return key
}

// signWithKey creates the certificate tmpl describes for pub, signed by signer
// under parent. Either key may be an SLH-DSA key, which crypto/x509 can neither
// certify nor sign with.
func signWithKey(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
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

// signRolloverRoot issues a root CA certificate for pub, signed by signer
// under parent or self-signed when parent is nil. Every root keeps the same
// name, as in RFC 4210 §4.4, and may sign CMP responses.
func signRolloverRoot(t *testing.T, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
	// The identifier depends only on the key, so a link certificate shares it with the root of its key.
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski[:20],
	}
	if parent == nil {
		parent = tmpl
	}
	return signWithKey(t, tmpl, parent, pub, signer)
}

// TestGetRootCAUpdateSLHDSA fetches root CA key updates (RFC 9483 §4.3.2) in
// which the old root, the new root or both have SLH-DSA keys. The old root
// certifies the device and signs the responses, so with an SLH-DSA old root the
// client also verifies an SLH-DSA signed genp. Updates whose SLH-DSA link
// certificates do not verify against the old root are refused.
func TestGetRootCAUpdateSLHDSA(t *testing.T) {
	ctx := context.Background()
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
			oldRoot := signRolloverRoot(t, oldKey.Public(), nil, oldKey)
			newRoot := signRolloverRoot(t, newKey.Public(), nil, newKey)
			update := &pkicmp.RootCAKeyUpdate{
				NewWithNew: newRoot,
				NewWithOld: signRolloverRoot(t, newKey.Public(), oldRoot, oldKey),
				OldWithNew: signRolloverRoot(t, oldKey.Public(), newRoot, newKey),
			}

			deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			device := signWithKey(t, &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "Device"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
			}, oldRoot, deviceKey.Public(), oldKey)
			backend := &supportCA{issued: []*x509.Certificate{device}, update: update}
			srv := server.NewCAServer(backend, server.LightweightPolicy(), server.WithSigner(oldKey, oldRoot), server.WithCertificateLookup(backend))
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			defer ts.Close()

			trusted := x509.NewCertPool()
			trusted.AddCert(oldRoot)
			creds, err := pkicmp.NewSignatureCredentials(deviceKey, device, oldRoot)
			require.NoError(t, err)
			got, err := client.NewClient(ts.URL, client.WithTrustedCAs(trusted)).GetRootCAUpdate(ctx, oldRoot, creds)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.True(t, got.NewWithNew.Equal(update.NewWithNew))
			assert.True(t, got.NewWithOld.Equal(update.NewWithOld))
			assert.True(t, got.OldWithNew.Equal(update.OldWithNew))

			// The server refuses to send an update it cannot verify, so the
			// forged ones come from a mock server. The other root has an
			// SLH-DSA key, so each forged link certificate carries a
			// well-formed SLH-DSA signature by the wrong key.
			otherKey := newRolloverKey(t, slhdsa.SHA2_128f)
			other := signRolloverRoot(t, otherKey.Public(), nil, otherKey)
			forged := map[string]*pkicmp.RootCAKeyUpdate{
				"NewWithOldSignedByOther": {
					NewWithNew: newRoot,
					NewWithOld: signRolloverRoot(t, newKey.Public(), other, otherKey),
				},
				"OldWithNewSignedByOther": {
					NewWithNew: newRoot,
					NewWithOld: update.NewWithOld,
					OldWithNew: signRolloverRoot(t, oldKey.Public(), other, otherKey),
				},
				"NewWithNewNotSelfSigned": {
					NewWithNew: signRolloverRoot(t, newKey.Public(), other, otherKey),
					NewWithOld: update.NewWithOld,
				},
			}
			for name, u := range forged {
				t.Run(name, func(t *testing.T) {
					item, err := pkicmp.NewRootCAKeyUpdateInfo(u)
					require.NoError(t, err)
					ts, _ := rrMockServer(t, func(int32, *pkicmp.PKIMessage) *pkicmp.PKIBody { return genpBody(item) })
					_, err = client.NewClient(ts.URL).GetRootCAUpdate(ctx, oldRoot, macCreds(t))
					var clientErr *client.Error
					require.ErrorAs(t, err, &clientErr)
					assert.Equal(t, "verify root CA update", clientErr.Op)
				})
			}
		})
	}
}
