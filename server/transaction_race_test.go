package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// The documented deployment runs CleanupExpired from a background goroutine
// while the handler serves requests, so every transaction state transition has
// to publish a fresh entry rather than mutate one that a reader already holds.
// Meaningful only under -race, which CI enables.
func TestCleanupExpiredConcurrentWithImplicitConfirm(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	secret := []byte("cleanup-race-secret")

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler,
		server.WithSigner(caKey, &caCert),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithImplicitConfirm(),
		// Retained entries accumulate for the whole run, so the reaper sweeps a
		// large table and overlaps the handler completing the newest entry.
		server.WithConfirmWaitTime(500*time.Millisecond),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// enrollOnce runs one implicit-confirm enrollment and reports whether the server granted it.
	enrollOnce := func(t *testing.T) bool {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		msg := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "cleanup-race")}),
			macMessageOpts(),
		)
		msg.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{pkicmp.ImplicitConfirmInfoValue()}
		protectMAC(msg, secret)

		resp := postCMP(t, ts, msg)
		for _, gi := range resp.Header.GeneralInfo {
			if gi.InfoType.Equal(pkicmp.ImplicitConfirmInfoValue().InfoType) {
				return true
			}
		}
		return false
	}

	// setCompleted is only reached when implicit confirm is granted.
	require.True(t, enrollOnce(t), "implicit confirm must be granted for this test to exercise setCompleted")

	stop := make(chan struct{})
	var reapers sync.WaitGroup
	for range 4 {
		reapers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					srv.CleanupExpired()
				}
			}
		})
	}

	var clients sync.WaitGroup
	for range 16 {
		clients.Go(func() {
			for range 40 {
				enrollOnce(t)
			}
		})
	}
	clients.Wait()
	close(stop)
	reapers.Wait()
}
