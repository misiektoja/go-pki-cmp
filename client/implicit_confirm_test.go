package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// requestsImplicitConfirm reports whether the header of req carries id-it-implicitConfirm.
func requestsImplicitConfirm(req *pkicmp.PKIMessage) bool {
	oid := pkicmp.ImplicitConfirmInfoValue().InfoType
	return slices.ContainsFunc(req.Header.GeneralInfo, func(item pkicmp.InfoTypeAndValue) bool { return item.InfoType.Equal(oid) })
}

// WithImplicitConfirm puts the item first in generalInfo, and a grant ends the transaction without certConf.
func TestImplicitConfirmGranted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	var requested atomic.Bool
	var profileAfter atomic.Bool
	rec := &confirmRecorder{grant: true, issue: func(req *pkicmp.PKIMessage) []byte {
		requested.Store(requestsImplicitConfirm(req))
		info := req.Header.GeneralInfo
		profileAfter.Store(len(info) == 2 && info[0].InfoType.Equal(pkicmp.ImplicitConfirmInfoValue().InfoType) && req.Header.CertProfile() == "device")
		return issueFor(t, ca, requestedPublicKey(req)).Raw
	}}
	ts := rec.serve(t)

	result, err := sendIR(t, ts.URL, &caCert, client.WithImplicitConfirm(), client.WithCertProfile("device"))
	require.NoError(t, err)
	assert.True(t, requested.Load(), "the request must carry id-it-implicitConfirm")
	assert.True(t, profileAfter.Load(), "implicitConfirm must come before the certProfile")
	assert.True(t, result.ImplicitConfirm)
	assert.NotNil(t, result.Certificate)
	assert.Empty(t, rec.recorded(), "no certConf after a grant")
}

// Without a grant the client confirms as usual.
func TestImplicitConfirmNotGranted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	rec := &confirmRecorder{issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestedPublicKey(req)).Raw }}
	ts := rec.serve(t)

	result, err := sendIR(t, ts.URL, &caCert, client.WithImplicitConfirm())
	require.NoError(t, err)
	assert.False(t, result.ImplicitConfirm)
	require.Len(t, rec.recorded(), 1, "the certificate must be confirmed")
	assert.Nil(t, rec.recorded()[0].StatusInfo)
}

// A grant the request did not ask for is honored, because the CA has closed the transaction.
func TestImplicitConfirmUnrequestedGrant(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	var requested atomic.Bool
	rec := &confirmRecorder{grant: true, issue: func(req *pkicmp.PKIMessage) []byte {
		requested.Store(requestsImplicitConfirm(req))
		return issueFor(t, ca, requestedPublicKey(req)).Raw
	}}
	ts := rec.serve(t)

	result, err := sendIR(t, ts.URL, &caCert)
	require.NoError(t, err)
	assert.False(t, requested.Load(), "the request must not ask for implicit confirmation by default")
	assert.True(t, result.ImplicitConfirm)
	assert.Empty(t, rec.recorded())
}

// RFC 9483 §3.6.1: a certificate refused after a grant is not reported in certConf.
func TestImplicitConfirmRejectionSendsNoCertConf(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	other := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherCert, err := other.X509Certificate()
	require.NoError(t, err)

	rec := &confirmRecorder{grant: true, issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestedPublicKey(req)).Raw }}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &otherCert, client.WithImplicitConfirm())
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.NotContains(t, err.Error(), "rejection not confirmed")
	assert.Empty(t, rec.recorded(), "no certConf after a grant")
}

// Against the server package, a granting server and a requesting client end the transaction
// with the response, and a server that does not grant still gets its certConf.
func TestImplicitConfirmWithServer(t *testing.T) {
	secrets := server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("secret"), nil }))
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	t.Run("granted", func(t *testing.T) {
		backend := &confirmingCA{ca: ca}
		srv := server.NewCAServer(backend, server.LightweightPolicy(), secrets, server.WithImplicitConfirm())
		require.NoError(t, srv.Err())
		ts := httptest.NewServer(srv)
		defer ts.Close()

		result, err := sendIR(t, ts.URL, &caCert, client.WithImplicitConfirm())
		require.NoError(t, err)
		assert.True(t, result.ImplicitConfirm)
		backend.mu.Lock()
		defer backend.mu.Unlock()
		assert.Equal(t, []server.ConfirmStatus{server.ConfirmImplicit}, backend.statuses, "the server must close the transaction on the grant, not on a certConf")
	})

	t.Run("not granted", func(t *testing.T) {
		backend := &confirmingCA{ca: ca}
		srv := server.NewCAServer(backend, server.LightweightPolicy(), secrets)
		require.NoError(t, srv.Err())
		ts := httptest.NewServer(srv)
		defer ts.Close()

		result, err := sendIR(t, ts.URL, &caCert, client.WithImplicitConfirm())
		require.NoError(t, err)
		assert.False(t, result.ImplicitConfirm)
		backend.mu.Lock()
		defer backend.mu.Unlock()
		assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, backend.statuses)
	})
}

// A revocation request ignores WithImplicitConfirm.
func TestImplicitConfirmIgnoredByRR(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := issueFor(t, ca, &key.PublicKey)

	var requested atomic.Bool
	rec := &confirmRecorder{issue: func(req *pkicmp.PKIMessage) []byte {
		requested.Store(requestsImplicitConfirm(req))
		return cert.Raw
	}}
	// The recorder answers every request with an ip, which SendRR refuses, after the header was seen.
	ts := rec.serve(t)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(&caCert)
	c := client.NewClient(ts.URL, client.WithTrustedCAs(pool))
	err = c.SendRR(context.Background(), cert, pkicmp.CRLReasonUnspecified, creds, client.WithImplicitConfirm())
	require.Error(t, err)
	assert.False(t, requested.Load(), "an rr must not carry id-it-implicitConfirm")
}
