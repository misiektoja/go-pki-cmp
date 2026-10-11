package client_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/client"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// The client bounds the iteration count of a MAC-protected response
// separately from the count it sends.
func TestClientMACIterationLimits(t *testing.T) {
	secret := []byte("client-iteration-secret")
	count := pkicmp.DefaultMaxMACIterationCount + 1
	backend := &confirmingCA{ca: &certyaml.Certificate{Subject: "cn=issuing-ca"}}
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) {
			return secret, nil
		})),
		server.WithMACIterationLimits(0, count),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credentials, err := pkicmp.NewMACCredentials(secret, pkicmp.WithMACIterationCount(count), pkicmp.WithMACIterationLimits(0, count))
	require.NoError(t, err)
	enroll := func(c *client.Client) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		_, err = c.SendIR(t.Context(), key, credentials, client.WithSenderKID([]byte("device")), client.WithTemplateSubject(pkix.Name{CommonName: "device.example.test"}))
		return err
	}

	t.Run("DefaultLimitsRejectEchoedCount", func(t *testing.T) {
		err := enroll(client.NewClient(ts.URL))
		var ce *client.Error
		require.ErrorAs(t, err, &ce)
		var pe *pkicmp.ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})

	t.Run("RaisedLimitsAcceptEchoedCount", func(t *testing.T) {
		require.NoError(t, enroll(client.NewClient(ts.URL, client.WithMACIterationLimits(0, count))))
	})
}
