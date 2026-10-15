package server_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// The client of this module enrolls every key the server can encrypt for with both indirect methods.
func TestClientIndirectPOP(t *testing.T) {
	secret := []byte("client-indirect-pop")
	keys := popKeys(t)
	// An *ecdh.PrivateKey on a NIST curve is accepted as well as an *ecdsa.PrivateKey.
	p256 := keys[3].priv.(*ecdsa.PrivateKey)
	exchanger, err := p256.ECDH()
	require.NoError(t, err)
	keys = append(keys, popKey{name: "ecdh.PrivateKey P-256", pub: keys[3].pub, priv: exchanger, agreement: true})

	for _, method := range []client.IndirectPOP{client.EncryptedCertificate, client.ChallengeResponse} {
		for _, key := range keys {
			t.Run(method.String()+"/"+key.name, func(t *testing.T) {
				ca := newPOPCA(t)
				ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
					server.WithSecretLookup(&staticMACLookup{secret: secret}),
					server.WithEncryptedCertificatePOP(),
					server.WithChallengeResponsePOP(),
				))
				defer ts.Close()

				creds, err := pkicmp.NewMACCredentials(secret)
				require.NoError(t, err)
				c := client.NewClient(ts.URL)
				result, err := c.SendIRWithIndirectPOP(context.Background(), key.priv, method, creds,
					client.WithSender(testSender),
					client.WithSenderKID([]byte(testSender.String())),
					client.WithTemplateSubject(pkix.Name{CommonName: "client " + key.name}),
				)
				require.NoError(t, err)
				pub, err := pkicmp.ParsePublicKey(result.Certificate.RawSubjectPublicKeyInfo)
				require.NoError(t, err)
				assert.True(t, pkicmp.PublicKeysEqual(pub, key.pub))

				want := server.POPEncryptedCertificate
				if method == client.ChallengeResponse {
					want = server.POPChallengeResponse
				}
				methods, confirmations := ca.recorded()
				assert.Equal(t, []server.POPMethod{want}, methods)
				assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, want}}, confirmations)
			})
		}
	}
}

// Polling continues a challenged request from the popdecr.
func TestClientChallengeResponseAfterPolling(t *testing.T) {
	secret := []byte("client-challenge-poll")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	ca.delay = true
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithChallengeResponsePOP(),
	))
	defer ts.Close()

	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	c := client.NewClient(ts.URL)
	result, err := c.SendIRWithIndirectPOP(context.Background(), key.priv, client.ChallengeResponse, creds,
		client.WithSender(testSender),
		client.WithSenderKID([]byte(testSender.String())),
		client.WithTemplateSubject(pkix.Name{CommonName: "client polling"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	_, confirmations := ca.recorded()
	assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPChallengeResponse}}, confirmations)
}

// The client refuses keys the cms package cannot decrypt with before it sends anything.
func TestClientIndirectPOPUnsupportedKey(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(nil)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("unused"))
	require.NoError(t, err)
	c := client.NewClient("http://127.0.0.1:1")
	for name, key := range map[string]any{"X25519": x25519, "string": "not a key"} {
		_, err := c.SendIRWithIndirectPOP(context.Background(), key, client.EncryptedCertificate, creds)
		assert.ErrorContains(t, err, "indirect proof of possession", name)
	}
	_, err = c.SendIRWithIndirectPOP(context.Background(), popKeys(t)[0].priv, client.IndirectPOP(9), creds)
	assert.ErrorContains(t, err, "unknown indirect proof of possession")
}
