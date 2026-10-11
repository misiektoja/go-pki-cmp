package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- builds deprecated SHA-1 signatures that the client must refuse by default
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// sha1SignatureProtector signs each response with ecdsa-with-SHA1, as an RFC 4210 era CA may.
func sha1SignatureProtector(t *testing.T, key *ecdsa.PrivateKey) func(*pkicmp.PKIMessage) {
	return func(msg *pkicmp.PKIMessage) {
		msg.Header.ProtectionAlg = &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}}
		msg.Protection = []byte{0}
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)
		data, err := parsed.ProtectedData()
		require.NoError(t, err)
		digest := sha1.Sum(data) // #nosec G401 -- the point of the test
		msg.Protection, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
		require.NoError(t, err)
	}
}

// Responses signed with SHA-1 fail verification unless WithSHA1Signatures is set.
func TestSHA1SignedResponse(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=legacy-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	cmpSigner := &certyaml.Certificate{Subject: "cn=legacy-cmp-signer", Issuer: ca}
	cmpSignerCert, err := cmpSigner.X509Certificate()
	require.NoError(t, err)
	signerKey, err := cmpSigner.PrivateKey()
	require.NoError(t, err)
	ecKey, ok := signerKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "the test signs with an ECDSA key")
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(&caCert)

	enroll := func(t *testing.T, opts ...client.Option) error {
		exchange := &enrollmentExchange{
			issuer:              ca,
			sender:              pkix.Name{CommonName: "legacy-cmp-signer"},
			extraCertsOnIP:      []*x509.Certificate{&cmpSignerCert},
			extraCertsOnPKIConf: []*x509.Certificate{&cmpSignerCert},
			protect:             sha1SignatureProtector(t, ecKey),
		}
		server := exchange.start(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		creds, err := pkicmp.NewMACCredentials([]byte("secret"))
		require.NoError(t, err)
		c := client.NewClient(server.URL, append([]client.Option{client.WithTrustedCAs(trustedCAs)}, opts...)...)
		result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
		if err == nil {
			require.NotNil(t, result.Certificate)
		}
		return err
	}

	t.Run("refused by default", func(t *testing.T) {
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, enroll(t), &ve)
		assert.Equal(t, pkicmp.ReasonUnsupportedAlgorithm, ve.Reason)
	})

	t.Run("accepted with WithSHA1Signatures", func(t *testing.T) {
		assert.NoError(t, enroll(t, client.WithSHA1Signatures()))
	})
}
