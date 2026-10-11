package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// TestSnapshotResumesCertificateConfirmation rebuilds the server between messages for both supported MAC suites.
func TestSnapshotResumesCertificateConfirmation(t *testing.T) {
	for _, pbm := range []bool{false, true} {
		name := "PBMAC1"
		if pbm {
			name = "PBM"
		}
		t.Run(name, func(t *testing.T) {
			ca := &certyaml.Certificate{Subject: "CN=Recovery CA"}
			cert, err := ca.X509Certificate()
			require.NoError(t, err)
			signer, err := ca.PrivateKey()
			require.NoError(t, err)
			issuer := &recordingCA{ca: ca}
			secret := []byte("snapshot-test-secret")
			fresh := func() *server.Server {
				return server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSigner(signer, &cert), server.WithSecretLookup(&staticMACLookup{secret: secret}))
			}
			var mu sync.Mutex
			var snapshot []byte
			var failure error
			requests := 0
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				current := fresh()
				if len(snapshot) > 0 {
					if err := current.RestoreTransactions(snapshot, nil); err != nil {
						failure = err
						http.Error(w, "restore failed", 500)
						return
					}
				}
				current.ServeHTTP(w, r)
				requests++
				snapshot, failure = current.SnapshotTransactions()
			}))
			defer host.Close()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			var options []pkicmp.MACCredentialOption
			if pbm {
				options = append(options, pkicmp.WithPBM())
			}
			credentials, err := pkicmp.NewMACCredentials(secret, options...)
			require.NoError(t, err)
			result, err := client.NewClient(host.URL).SendIR(t.Context(), key, credentials, client.WithSenderKID([]byte("device")), client.WithTemplateSubject(pkix.Name{CommonName: "device.example.test"}))
			require.NoError(t, err)
			require.NotNil(t, result.Certificate)
			mu.Lock()
			defer mu.Unlock()
			require.NoError(t, failure)
			require.Equal(t, 2, requests)
			require.NotContains(t, string(snapshot), string(secret))
			require.NoError(t, fresh().RestoreTransactions(snapshot, nil))
			var invalid map[string]any
			require.NoError(t, json.Unmarshal(snapshot, &invalid))
			invalid["Version"] = 999
			corrupt, err := json.Marshal(invalid)
			require.NoError(t, err)
			require.Error(t, fresh().RestoreTransactions(corrupt, nil))
			otherCA := &certyaml.Certificate{Subject: "CN=Other CA"}
			otherCert, err := otherCA.X509Certificate()
			require.NoError(t, err)
			otherKey, err := otherCA.PrivateKey()
			require.NoError(t, err)
			other := server.NewCAServer(issuer, nil, server.WithSigner(otherKey, &otherCert))
			require.Error(t, other.RestoreTransactions(snapshot, nil))
		})
	}
}
