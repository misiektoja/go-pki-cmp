package server_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// unsignableRSAKey carries an RSA public key of about one million bits and
// signs with random bytes, which stands in for the proof a peer attaches to a
// key it never needs to hold.
type unsignableRSAKey struct{ pub *rsa.PublicKey }

func (k unsignableRSAKey) Public() crypto.PublicKey { return k.pub }

func (k unsignableRSAKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig := make([]byte, k.pub.Size())
	_, err := rand.Read(sig)
	return sig, err
}

// newUnsignableRSAKey returns a key with a random modulus of bits bits.
func newUnsignableRSAKey(t *testing.T, bits int) unsignableRSAKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	require.NoError(t, err)
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	return unsignableRSAKey{pub: &rsa.PublicKey{N: n, E: 65537}}
}

// csrWithKey returns a PKCS #10 request for key's public key with a random
// signature, built by hand because crypto/x509 checks the signature it creates.
func csrWithKey(t *testing.T, key unsignableRSAKey) *x509.CertificateRequest {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key.pub)
	require.NoError(t, err)
	subject, err := asn1.Marshal(pkix.Name{CommonName: "device"}.ToRDNSequence())
	require.NoError(t, err)
	sig, err := key.Sign(nil, nil, nil)
	require.NoError(t, err)
	type tbs struct {
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	der, err := asn1.Marshal(struct {
		TBS                tbs
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBS:                tbs{Subject: asn1.RawValue{FullBytes: subject}, PublicKey: asn1.RawValue{FullBytes: spki}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// A request for an RSA key above pkicmp.MaxRSAModulusBits is refused before
// its proof of possession is checked. Checking a proof made with a key of one
// million bits would otherwise cost about ten seconds of CPU per request.
func TestOversizedRSAKeyIsRefusedBeforeProofOfPossession(t *testing.T) {
	secret := []byte("rsa-secret")
	srv := server.NewCAServer(&generalCA{}, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()
	key := newUnsignableRSAKey(t, 1<<20)

	assertRefusedQuickly := func(t *testing.T, msg *pkicmp.PKIMessage) {
		t.Helper()
		protectMAC(msg, secret)
		start := time.Now()
		resp := postCMP(t, ts, msg)
		require.Less(t, time.Since(start), 3*time.Second, "the key must be refused without a public key operation")
		si := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.StatusRejection, si.Status)
		assert.Contains(t, strings.Join(si.StatusString, " "), "RSA modulus larger than 16384 bits")
	}

	t.Run("CRMF", func(t *testing.T) {
		spki, err := x509.MarshalPKIXPublicKey(key.pub)
		require.NoError(t, err)
		req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
			Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "device"}),
			PublicKey: spki,
		}}}
		require.NoError(t, req.GeneratePOP(key))
		assertRefusedQuickly(t, pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), macMessageOpts()))
	})

	t.Run("PKCS10", func(t *testing.T) {
		assertRefusedQuickly(t, pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(csrWithKey(t, key)), macMessageOpts()))
	})
}
