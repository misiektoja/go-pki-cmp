package server_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// RFC 9483 §4.1.1: a certConf that misses confirmWaitTime is handled like a
// rejection. It is refused before CleanupExpired runs, the CA hears once that
// the certificate expired and the transaction is gone.
func TestCertConfAfterConfirmWaitTimeIsRefused(t *testing.T) {
	secret := []byte("late-certconf-secret")
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	srv := server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithConfirmWaitTime(50*time.Millisecond))
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	ip, cert := enrollForCertConf(t, ts, secret, false)
	time.Sleep(100 * time.Millisecond)

	status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false)))
	assert.Equal(t, pkicmp.FailBadRequest, status.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"certConf after confirmWaitTime"}, status.StatusString)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmExpired}, ca.statuses)

	srv.CleanupExpired()
	status = errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false)))
	assert.Equal(t, pkicmp.PKIFreeText{"unknown transaction"}, status.StatusString)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmExpired}, ca.statuses, "the CA hears of the expiry once")
}

// A certConf within confirmWaitTime confirms the certificate as before.
func TestCertConfWithinConfirmWaitTimeConfirms(t *testing.T) {
	secret := []byte("timely-certconf-secret")
	ts, ca := newConfirmingServer(t, secret, server.WithConfirmWaitTime(time.Minute))
	ip, cert := enrollForCertConf(t, ts, secret, false)
	resp := sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false))
	assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
}
