package certpath

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// oversizedRSAKey is a signer whose public key is an RSA modulus of about one
// million bits. Nothing signs with it: the certificate that carries it is
// issued by another party.
type oversizedRSAKey struct{ pub *rsa.PublicKey }

func (k oversizedRSAKey) Public() crypto.PublicKey { return k.pub }

func (oversizedRSAKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("oversized key never signs")
}

// newOversizedRSAKey returns a key with a random modulus of bits bits.
func newOversizedRSAKey(t *testing.T, bits int) oversizedRSAKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	require.NoError(t, err)
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	return oversizedRSAKey{pub: &rsa.PublicKey{N: n, E: 65537}}
}

// A candidate issuer with an oversized RSA key is never used, so a peer cannot
// make the verifier spend seconds per signature check with a crafted extraCerts.
func TestVerifyIgnoresOversizedRSACandidate(t *testing.T) {
	root := issue(t, caTemplate("Root"), ecdsaKey(t), nil)
	// The leaf carries an RSA signature, so a candidate issuer with an RSA key
	// and the right name is one crypto/x509 would otherwise verify it with.
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	inter := issue(t, caTemplate("Inter"), interKey, root)
	leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
	impostor := issue(t, caTemplate("Inter"), newOversizedRSAKey(t, 1<<20), root)
	roots := pool(root.cert)

	start := time.Now()
	require.Error(t, Verify(leaf.cert, roots, []*x509.Certificate{impostor.cert}, time.Now()))
	require.Less(t, time.Since(start), 3*time.Second, "the impostor's key must not be used")

	require.NoError(t, Verify(leaf.cert, roots, []*x509.Certificate{impostor.cert, inter.cert}, time.Now()))
}
