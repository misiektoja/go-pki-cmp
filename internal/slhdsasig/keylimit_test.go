package slhdsasig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/internal/keylimit"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
)

// A parent certificate with an oversized RSA key is refused before its key is
// used, whichever algorithm signed the child.
func TestCheckSignatureFromRefusesOversizedRSAParent(t *testing.T) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 32768))
	require.NoError(t, err)
	n.SetBit(n, 32767, 1)
	n.SetBit(n, 0, 1)
	issuerKey := ecdsaKey(t)
	issuer := template("Issuer", true)
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	parentDER, err := x509.CreateCertificate(rand.Reader, template("Oversized", true), issuerCert, &rsa.PublicKey{N: n, E: 65537}, issuerKey)
	require.NoError(t, err)
	parent, err := x509.ParseCertificate(parentDER)
	require.NoError(t, err)

	require.ErrorIs(t, slhdsasig.CheckSignatureFrom(issuerCert, parent), keylimit.ErrRSAKeyTooLarge)
}
