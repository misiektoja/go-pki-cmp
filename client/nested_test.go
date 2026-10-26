package client_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// nestedRecorder passes requests to next and records each by its body type,
// with the type of the request inside a nested message in parentheses. It
// checks that a nested message carries raCert first and copies the
// transactionID and nonces of the request inside.
type nestedRecorder struct {
	t      *testing.T
	next   http.Handler
	raCert *x509.Certificate
	mu     sync.Mutex
	seen   []string
}

// ServeHTTP records the request and passes it on unchanged.
func (r *nestedRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	msg, err := pkicmp.ParsePKIMessage(body)
	if err != nil {
		r.t.Errorf("parse request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := msg.Body.Type.String()
	if msg.Body.Type == pkicmp.BodyTypeNested {
		inner, err := msg.Body.Nested()
		if err != nil || len(inner) != 1 {
			r.t.Errorf("nested message carries %d messages: %v", len(inner), err)
		} else {
			name += "(" + inner[0].Body.Type.String() + ")"
			h := inner[0].Header
			if !bytes.Equal(msg.Header.TransactionID, h.TransactionID) || !bytes.Equal(msg.Header.SenderNonce, h.SenderNonce) ||
				!bytes.Equal(msg.Header.RecipNonce, h.RecipNonce) {
				r.t.Errorf("the nested %s does not copy the transactionID and nonces of the request", name)
			}
		}
		if len(msg.ExtraCerts) == 0 || !bytes.Equal(msg.ExtraCerts[0].Raw, r.raCert.Raw) {
			r.t.Errorf("the nested %s does not carry the RA certificate first", name)
		}
	}
	r.mu.Lock()
	r.seen = append(r.seen, name)
	r.mu.Unlock()
	r.next.ServeHTTP(w, req)
}

// requests returns the recorded requests.
func (r *nestedRecorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

// serveRA serves ca for requests MAC-protected with "secret" that the
// registration authority with raCert forwards, as far as authorize allows. It
// records the requests that arrive.
func serveRA(t *testing.T, ca server.CA, issuer *certyaml.Certificate, raCert *x509.Certificate, authorize server.RAAuthorizerFunc) (string, *nestedRecorder) {
	t.Helper()
	caCert, err := issuer.X509Certificate()
	require.NoError(t, err)
	caKey, err := issuer.PrivateKey()
	require.NoError(t, err)
	lookup := server.CertificateLookupFunc(func(_, _ pkix.Name, kid []byte) (*x509.Certificate, error) {
		if bytes.Equal(kid, raCert.SubjectKeyId) {
			return raCert, nil
		}
		return nil, errors.New("unknown key")
	})
	srv := server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSigner(caKey, &caCert),
		server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("secret"), nil })),
		server.WithCertificateLookup(lookup),
		server.WithRAAuthorizer(authorize),
	)
	require.NoError(t, srv.Err())
	rec := &nestedRecorder{t: t, next: srv, raCert: raCert}
	ts := httptest.NewServer(rec)
	t.Cleanup(ts.Close)
	return ts.URL, rec
}

// A registration authority wraps every request of a delayed enrollment in a
// nested message: the ir, each pollReq and the certConf. The CA verifies both
// protections and authorizes the RA for each of them.
func TestRegistrationAuthorityForwardsTransaction(t *testing.T) {
	ca := newDelayedCA(func(check int) bool { return check >= 2 })
	// Any certificate of the test CA serves as the RA certificate, since the authorizer below names it.
	raKey, raCert := issueKGA(t, ca.ca)
	var mu sync.Mutex
	var forwarded []pkicmp.BodyType
	url, rec := serveRA(t, ca, ca.ca, raCert, func(_ context.Context, ra *server.SenderIdentity, req *pkicmp.PKIMessage, sender *server.SenderIdentity) error {
		if !ra.Certificate.Equal(raCert) || !sender.MACVerified {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}
		}
		mu.Lock()
		forwarded = append(forwarded, req.Body.Type)
		mu.Unlock()
		return nil
	})
	raCreds, err := pkicmp.NewSignatureCredentials(raKey, raCert)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	res, err := newPendingClient(t, url, ca, client.WithRegistrationAuthority(raCreds)).SendIR(context.Background(), key, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "forwarded"}),
	)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(res.Certificate.PublicKey))
	assert.Equal(t, []string{"nested(ir)", "nested(pollReq)", "nested(pollReq)", "nested(certConf)"}, rec.requests())
	mu.Lock()
	assert.Equal(t, []pkicmp.BodyType{pkicmp.BodyTypeIR, pkicmp.BodyTypePollReq, pkicmp.BodyTypePollReq, pkicmp.BodyTypeCertConf}, forwarded)
	mu.Unlock()
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
}

// A CA that does not accept the registration authority refuses the request
// with an error response that the client verifies and reports.
func TestRegistrationAuthorityRefused(t *testing.T) {
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	raKey, raCert := issueKGA(t, ca.ca)
	url, rec := serveRA(t, ca, ca.ca, raCert, func(context.Context, *server.SenderIdentity, *pkicmp.PKIMessage, *server.SenderIdentity) error {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not an RA"}
	})
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(&caCert)
	raCreds, err := pkicmp.NewSignatureCredentials(raKey, raCert)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	c := client.NewClient(url, client.WithTrustedCAs(pool), client.WithRegistrationAuthority(raCreds))
	_, err = c.SendIR(context.Background(), key, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "refused"}),
	)
	require.True(t, pkicmp.HasFailure(err, pkicmp.FailNotAuthorized), "got %v", err)
	assert.Equal(t, []string{"nested(ir)"}, rec.requests())
}
