package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// delayedCA answers every certificate request with status waiting and issues
// it on the poll at which release returns true, as a CA with an approval
// queue does.
type delayedCA struct {
	confirmingCA
	release func(check int) bool

	lock      sync.Mutex
	templates map[string]*x509.Certificate
	checks    int
}

// newDelayedCA returns a delayedCA that issues from a test CA once release returns true.
func newDelayedCA(release func(check int) bool) *delayedCA {
	return &delayedCA{
		ca:        &certyaml.Certificate{Subject: "CN=Test CA"},
		release:   release,
		templates: map[string]*x509.Certificate{},
	}
}

// IssueCertificate keeps the request and answers that it waits.
func (c *delayedCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	ref := fmt.Sprintf("request-%d", len(c.templates)+1)
	c.templates[ref] = tmpl
	return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: ref}}, nil
}

// CheckPending issues the request once release allows it and keeps it waiting otherwise.
func (c *delayedCA) CheckPending(ctx context.Context, pollRef string, sender *server.SenderIdentity) (*server.Response, error) {
	c.lock.Lock()
	c.checks++
	release := c.release(c.checks)
	tmpl := c.templates[pollRef]
	c.lock.Unlock()
	if tmpl == nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "unknown request"}
	}
	if !release {
		return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef}}, nil
	}
	return c.confirmingCA.IssueCertificate(ctx, server.RequestIR, tmpl, sender)
}

// checkCount returns how often the CA was asked about a waiting request.
func (c *delayedCA) checkCount() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.checks
}

// confirmed returns the confirmation outcomes the CA received.
func (c *delayedCA) confirmed() []server.ConfirmStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.statuses)
}

// bodyCounter passes requests to next and counts them by body type.
type bodyCounter struct {
	next   http.Handler
	mu     sync.Mutex
	counts map[pkicmp.BodyType]int
}

// ServeHTTP counts the request and passes it on unchanged.
func (b *bodyCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		if msg, err := pkicmp.ParsePKIMessage(body); err == nil {
			b.mu.Lock()
			b.counts[msg.Body.Type]++
			b.mu.Unlock()
		}
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	b.next.ServeHTTP(w, r)
}

// count returns how many requests of type t arrived and resets the count.
func (b *bodyCounter) count(t pkicmp.BodyType) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := b.counts[t]
	b.counts[t] = 0
	return n
}

// serveDelayedCA serves ca for requests MAC-protected with "secret" and counts them.
func serveDelayedCA(t *testing.T, ca *delayedCA) (*httptest.Server, *bodyCounter) {
	t.Helper()
	secrets := server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("secret"), nil }))
	srv := server.NewCAServer(ca, server.LightweightPolicy(), secrets)
	require.NoError(t, srv.Err())
	counter := &bodyCounter{next: srv, counts: map[pkicmp.BodyType]int{}}
	ts := httptest.NewServer(counter)
	t.Cleanup(ts.Close)
	return ts, counter
}

// newPendingClient returns a client that trusts the CA of ca and accepts its one-second checkAfter.
func newPendingClient(t *testing.T, url string, ca *delayedCA, opts ...client.Option) *client.Client {
	t.Helper()
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(&caCert)
	return client.NewClient(url, append([]client.Option{client.WithTrustedCAs(pool)}, opts...)...)
}

// macCredentials returns credentials for the shared secret "secret".
func macCredentials(t *testing.T) pkicmp.Credentials {
	t.Helper()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	return creds
}

// deferIR sends an ir for key under WithDeferredPolling and returns the pending state.
func deferIR(t *testing.T, c *client.Client, key *ecdsa.PrivateKey, opts ...client.RequestOption) *client.PendingEnrollment {
	t.Helper()
	opts = append([]client.RequestOption{
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "deferred"}),
		client.WithDeferredPolling(),
	}, opts...)
	result, err := c.SendIR(context.Background(), key, macCredentials(t), opts...)
	require.NoError(t, err)
	require.NotNil(t, result.Pending, "a waiting answer must return the pending state")
	assert.Nil(t, result.Certificate)
	return result.Pending
}

// WithDeferredPolling stops at the waiting ip, and the state resumes the transaction in another client.
func TestDeferredPollingResume(t *testing.T) {
	ca := newDelayedCA(func(int) bool { return true })
	ts, counter := serveDelayedCA(t, ca)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pending := deferIR(t, newPendingClient(t, ts.URL, ca), key)
	assert.Equal(t, pkicmp.BodyTypeIR, pending.RequestType)
	assert.Equal(t, pkicmp.PVNO2, pending.PVNO)
	assert.Len(t, pending.TransactionID, 16)
	assert.Equal(t, []byte("test"), pending.SenderKID)
	assert.Equal(t, int64(0), pending.CertReqID)
	assert.NotEmpty(t, pending.RequestNonce)
	assert.NotEmpty(t, pending.ResponseNonce)
	assert.Zero(t, pending.IndirectPOP)
	assert.True(t, pending.NextPoll.IsZero(), "a waiting ip names no time")
	assert.Zero(t, counter.count(pkicmp.BodyTypePollReq), "the client must not poll")
	assert.Zero(t, ca.checkCount())

	// The state travels as JSON, as it would to another process.
	data, err := json.Marshal(pending)
	require.NoError(t, err)
	var restored client.PendingEnrollment
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Equal(t, *pending, restored)

	result, err := newPendingClient(t, ts.URL, ca).ResumeEnrollment(context.Background(), &restored, macCredentials(t))
	require.NoError(t, err)
	assert.Nil(t, result.Pending)
	assert.Equal(t, "deferred", result.Certificate.Subject.CommonName)
	assert.True(t, pkicmp.PublicKeysEqual(result.Certificate.PublicKey, &key.PublicKey))
	assert.Equal(t, 1, counter.count(pkicmp.BodyTypePollReq))
	assert.Equal(t, 1, counter.count(pkicmp.BodyTypeCertConf))
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
}

// Resuming under WithDeferredPolling sends one pollReq and returns the state with the nonce of the pollRep.
func TestDeferredPollingResumeOnce(t *testing.T) {
	ca := newDelayedCA(func(check int) bool { return check >= 2 })
	ts, counter := serveDelayedCA(t, ca)
	c := newPendingClient(t, ts.URL, ca)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	first := deferIR(t, c, key)

	once, err := c.ResumeEnrollment(context.Background(), first, macCredentials(t), client.WithDeferredPolling())
	require.NoError(t, err)
	require.NotNil(t, once.Pending)
	assert.Nil(t, once.Certificate)
	second := once.Pending
	assert.Equal(t, first.TransactionID, second.TransactionID)
	assert.Equal(t, first.RequestNonce, second.RequestNonce)
	assert.NotEqual(t, first.ResponseNonce, second.ResponseNonce, "the next pollReq repeats the nonce of the pollRep")
	assert.WithinDuration(t, time.Now().Add(time.Second), second.NextPoll, 500*time.Millisecond)
	assert.Equal(t, 1, counter.count(pkicmp.BodyTypePollReq))
	assert.Equal(t, 1, ca.checkCount())

	// The CA expects the nonce of its pollRep, so the first state no longer works.
	_, err = c.ResumeEnrollment(context.Background(), first, macCredentials(t))
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailBadRecipientNonce), "got %v", err)
	counter.count(pkicmp.BodyTypePollReq)

	// The first pollReq waits for the time the CA asked for, so one is enough.
	result, err := c.ResumeEnrollment(context.Background(), second, macCredentials(t))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.Equal(t, 1, counter.count(pkicmp.BodyTypePollReq))
	assert.Equal(t, 2, ca.checkCount())
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
}

// Polling that stops while the CA still waits returns a PendingError that resumes the transaction.
func TestPendingErrorResumes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  []client.Option
		ctx   func() (context.Context, context.CancelFunc)
		cause func(t *testing.T, err error)
	}{
		{
			name: "Deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 1500*time.Millisecond)
			},
			cause: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			},
		},
		{
			name: "MaxPolls",
			opts: []client.Option{client.WithMaxPolls(1)},
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			cause: func(t *testing.T, err error) {
				var ce *client.Error
				require.ErrorAs(t, err, &ce)
				assert.Contains(t, ce.Op, "polling exceeded max retries")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var release atomic.Bool
			ca := newDelayedCA(func(int) bool { return release.Load() })
			ts, _ := serveDelayedCA(t, ca)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			ctx, cancel := tc.ctx()
			defer cancel()
			_, err = newPendingClient(t, ts.URL, ca, tc.opts...).SendIR(ctx, key, macCredentials(t),
				client.WithSenderKID([]byte("test")), client.WithTemplateSubject(pkix.Name{CommonName: "stopped"}))
			var pendingErr *client.PendingError
			require.ErrorAs(t, err, &pendingErr)
			tc.cause(t, err)
			require.NotNil(t, pendingErr.Pending)
			assert.False(t, pendingErr.Pending.NextPoll.IsZero(), "the state keeps the time of the last pollRep")

			release.Store(true)
			result, err := newPendingClient(t, ts.URL, ca).ResumeEnrollment(context.Background(), pendingErr.Pending, macCredentials(t))
			require.NoError(t, err)
			assert.Equal(t, "stopped", result.Certificate.Subject.CommonName)
			assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
		})
	}
}

// A p10cr is answered with certReqId -1, which the resumed transaction polls and confirms with.
func TestDeferredPollingP10CR(t *testing.T) {
	ca := newDelayedCA(func(int) bool { return true })
	ts, _ := serveDelayedCA(t, ca)
	c := newPendingClient(t, ts.URL, ca)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "deferred-p10cr"}}, key)
	require.NoError(t, err)

	result, err := c.SendP10CR(context.Background(), csr, macCredentials(t), client.WithSenderKID([]byte("test")), client.WithDeferredPolling())
	require.NoError(t, err)
	require.NotNil(t, result.Pending)
	assert.Equal(t, pkicmp.BodyTypeP10CR, result.Pending.RequestType)
	assert.Equal(t, int64(-1), result.Pending.CertReqID)

	resumed, err := c.ResumeEnrollment(context.Background(), result.Pending, macCredentials(t))
	require.NoError(t, err)
	assert.Equal(t, "deferred-p10cr", resumed.Certificate.Subject.CommonName)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.confirmed())
}

// A CA that issues at once is not affected by WithDeferredPolling.
func TestDeferredPollingImmediateIssue(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	rec := &confirmRecorder{issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestedPublicKey(req)).Raw }}
	ts := rec.serve(t)

	result, err := sendIR(t, ts.URL, &caCert, client.WithDeferredPolling())
	require.NoError(t, err)
	assert.Nil(t, result.Pending)
	assert.NotNil(t, result.Certificate)
	assert.Len(t, rec.recorded(), 1)
}

// A broken state or a resume with the wrong method is refused before anything is sent.
func TestResumeEnrollmentRefusesBadState(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("nothing must be sent for a refused state")
	}))
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey, err := pkicmp.MarshalPublicKey(&key.PublicKey)
	require.NoError(t, err)
	name := pkicmp.NewDirectoryNameFromRawDER([]byte{0x30, 0x00}).Raw
	valid := func() *client.PendingEnrollment {
		return &client.PendingEnrollment{
			RequestType:   pkicmp.BodyTypeIR,
			PVNO:          pkicmp.PVNO2,
			TransactionID: []byte("transaction-0001"),
			Sender:        name,
			Recipient:     name,
			RequestNonce:  []byte("request-nonce-01"),
			ResponseNonce: []byte("response-nonce-1"),
			PublicKey:     publicKey,
		}
	}

	for _, tc := range []struct {
		name   string
		change func(p *client.PendingEnrollment)
		want   string
	}{
		{"RequestType", func(p *client.PendingEnrollment) { p.RequestType = pkicmp.BodyTypeRR }, "is not ir, cr, kur or p10cr"},
		{"PVNO", func(p *client.PendingEnrollment) { p.PVNO = 1 }, "unsupported protocol version"},
		{"TransactionID", func(p *client.PendingEnrollment) { p.TransactionID = nil }, "no transaction ID"},
		{"ResponseNonce", func(p *client.PendingEnrollment) { p.ResponseNonce = nil }, "no request or response nonce"},
		{"RequestNonce", func(p *client.PendingEnrollment) { p.RequestNonce = nil }, "no request or response nonce"},
		{"NegativeCertReqID", func(p *client.PendingEnrollment) { p.CertReqID = -1 }, "certReqId -1 is negative"},
		{"P10CRCertReqID", func(p *client.PendingEnrollment) { p.RequestType, p.CertReqID = pkicmp.BodyTypeP10CR, 3 }, "cannot answer a p10cr"},
		{"Sender", func(p *client.PendingEnrollment) { p.Sender = []byte{0x30, 0x00} }, "sender: not a GeneralName"},
		{"RecipientTrailingData", func(p *client.PendingEnrollment) { p.Recipient = append(slices.Clone(name), 0) }, "recipient: trailing data"},
		{"PublicKey", func(p *client.PendingEnrollment) { p.PublicKey = []byte{1} }, "public key"},
		{"ServerCertificate", func(p *client.PendingEnrollment) { p.ServerCertificate = []byte{1} }, "server certificate"},
		{"IndirectPOP", func(p *client.PendingEnrollment) { p.IndirectPOP = 9 }, "unknown indirect proof of possession"},
		{"EncryptedCertificate", func(p *client.PendingEnrollment) { p.IndirectPOP = client.EncryptedCertificate }, "ResumeEnrollmentWithIndirectPOP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.change(p)
			_, err := client.NewClient(ts.URL).ResumeEnrollment(context.Background(), p, macCredentials(t))
			var ce *client.Error
			require.ErrorAs(t, err, &ce)
			assert.Equal(t, "resume enrollment", ce.Op)
			assert.ErrorContains(t, err, tc.want)
		})
	}

	c := client.NewClient(ts.URL)
	_, err = c.ResumeEnrollment(context.Background(), nil, macCredentials(t))
	assert.ErrorContains(t, err, "no pending enrollment")
	_, err = c.ResumeEnrollment(context.Background(), valid(), nil)
	assert.ErrorContains(t, err, "no credentials provided")
	_, err = c.ResumeEnrollmentWithIndirectPOP(context.Background(), valid(), key, macCredentials(t))
	assert.ErrorContains(t, err, "resume it with ResumeEnrollment")
}
