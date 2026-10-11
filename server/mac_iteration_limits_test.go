package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// irWithMAC returns an ir for a fresh key, MAC-protected with the given credential options.
func irWithMAC(t *testing.T, secret []byte, opts ...pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "iteration-limits")}), macMessageOpts())
	msg.Header.SenderKID = []byte(testSender.String())
	creds, err := pkicmp.NewMACCredentials(secret, opts...)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	return msg
}

// A request whose iteration count falls outside the configured range is
// refused before it reaches the CA.
func TestServerMACIterationLimits(t *testing.T) {
	secret := []byte("server-iteration-secret")
	for _, tc := range []struct {
		name     string
		min, max int
		count    int
	}{
		{"AboveMaximum", 0, 1000, 1001},
		{"BelowMinimum", 100, 0, 99},
		{"AboveDefaultMaximum", 0, 0, pkicmp.DefaultMaxMACIterationCount + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, ca := newConfirmingServer(t, secret, server.WithMACIterationLimits(tc.min, tc.max))
			opts := []pkicmp.MACCredentialOption{pkicmp.WithPBM(), pkicmp.WithMACIterationCount(tc.count), pkicmp.WithMACIterationLimits(1, tc.count)}
			resp := postCMP(t, ts, irWithMAC(t, secret, opts...))
			require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
			info := statusInfoOf(t, resp)
			assert.Equal(t, pkicmp.FailBadMessageCheck, info.FailInfo)
			require.Len(t, info.StatusString, 1)
			assert.Contains(t, info.StatusString[0], "MAC protection parameters not accepted")
			assert.False(t, ca.called)
		})
	}

	t.Run("WithinRange", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret, server.WithMACIterationLimits(100, 1000))
		resp := postCMP(t, ts, irWithMAC(t, secret, pkicmp.WithMACIterationCount(100)))
		require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
		assert.True(t, ca.called)
	})
}

// A server that accepts a count above the default maximum echoes it in every
// response, including after the transaction is restored from a snapshot.
func TestServerEchoesRaisedMACIterationCount(t *testing.T) {
	count := pkicmp.DefaultMaxMACIterationCount + 1
	for _, pbm := range []bool{false, true} {
		name := "PBMAC1"
		if pbm {
			name = "PasswordBasedMac"
		}
		t.Run(name, func(t *testing.T) {
			ca := &certyaml.Certificate{Subject: "CN=Iteration CA"}
			cert, err := ca.X509Certificate()
			require.NoError(t, err)
			signer, err := ca.PrivateKey()
			require.NoError(t, err)
			issuer := &confirmingCA{ca: ca}
			secret := []byte("raised-iteration-secret")
			fresh := func() *server.Server {
				return server.NewCAServer(issuer, server.LightweightPolicy(),
					server.WithSigner(signer, &cert),
					server.WithSecretLookup(&staticMACLookup{secret: secret}),
					server.WithMACIterationLimits(0, count),
				)
			}

			// Each message reaches a new server restored from the previous
			// snapshot, so the pkiconf is protected from saved parameters.
			var mu sync.Mutex
			var snapshot []byte
			var failure error
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				current := fresh()
				if len(snapshot) > 0 {
					if err := current.RestoreTransactions(snapshot, nil); err != nil {
						failure = err
						http.Error(w, "restore failed", http.StatusInternalServerError)
						return
					}
				}
				current.ServeHTTP(w, r)
				snapshot, failure = current.SnapshotTransactions()
			}))
			defer host.Close()

			opts := []pkicmp.MACCredentialOption{pkicmp.WithMACIterationCount(count), pkicmp.WithMACIterationLimits(0, count)}
			if pbm {
				opts = append(opts, pkicmp.WithPBM())
			}
			credentials, err := pkicmp.NewMACCredentials(secret, opts...)
			require.NoError(t, err)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// The client verifies every response with the same range, so a
			// response that did not echo the count would fail here.
			c := client.NewClient(host.URL, client.WithMACIterationLimits(count, count))
			result, err := c.SendIR(t.Context(), key, credentials, client.WithSenderKID([]byte("device")), client.WithTemplateSubject(pkix.Name{CommonName: "device.example.test"}))
			require.NoError(t, err)
			require.NotNil(t, result.Certificate)

			mu.Lock()
			defer mu.Unlock()
			require.NoError(t, failure)
			assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, issuer.statuses)
		})
	}
}
