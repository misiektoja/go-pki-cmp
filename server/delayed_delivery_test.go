package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// approvalCA holds every certificate request for a decision and issues it once approved, as a CA with an operator queue does.
type approvalCA struct {
	confirmingCA
	mu sync.Mutex
	// decide returns "approve", "reject" or "" to keep waiting for the nth check of a request.
	decide    func(check int) string
	kinds     map[string]server.RequestType
	templates map[string]*x509.Certificate
	checks    int
	expired   []string
}

// newApprovalCA returns a CA that applies decide on every poll.
func newApprovalCA(decide func(check int) string) *approvalCA {
	return &approvalCA{
		ca:        &certyaml.Certificate{Subject: "CN=Test CA"},
		decide:    decide,
		kinds:     map[string]server.RequestType{},
		templates: map[string]*x509.Certificate{},
	}
}

// IssueCertificate keeps the request and answers that it waits for approval.
func (c *approvalCA) IssueCertificate(_ context.Context, kind server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pollRef := fmt.Sprintf("request-%d", len(c.templates)+1)
	c.kinds[pollRef], c.templates[pollRef] = kind, tmpl
	return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef, Reason: "waiting for approval"}}, nil
}

// CheckPending issues an approved request, rejects a rejected one and keeps any other waiting.
func (c *approvalCA) CheckPending(ctx context.Context, pollRef string, sender *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	c.checks++
	decision := c.decide(c.checks)
	kind, tmpl := c.kinds[pollRef], c.templates[pollRef]
	c.mu.Unlock()
	switch {
	case tmpl == nil:
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "unknown request"}
	case decision == "approve":
		return c.confirmingCA.IssueCertificate(ctx, kind, tmpl, sender)
	case decision == "reject":
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "rejected by an operator"}
	default:
		return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef, Reason: "still waiting"}}, nil
	}
}

// ExpireWaiting records a request whose client stopped polling.
func (c *approvalCA) ExpireWaiting(_ context.Context, pollRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expired = append(c.expired, pollRef)
}

// checkCount returns how often the CA was asked about a waiting request.
func (c *approvalCA) checkCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checks
}

// newApprovalServer serves ca with MAC authentication and returns the server for cleanup calls.
func newApprovalServer(t *testing.T, ca *approvalCA, secret []byte, opts ...server.Option) (*server.Server, *httptest.Server) {
	t.Helper()
	opts = append(opts, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	srv := server.NewCAServer(ca, server.LightweightPolicy(), opts...)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, ts
}

// sendWaitingIR posts an ir, with implicit confirmation requested when implicit is set, and returns its waiting ip.
func sendWaitingIR(t *testing.T, ts *httptest.Server, secret []byte, implicit bool) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	req := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "delayed-ir")}), macMessageOpts())
	if implicit {
		req.Header.GeneralInfo = append(req.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	protectMAC(req, secret)
	resp := postCMP(t, ts, req)
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
	require.Equal(t, pkicmp.StatusWaiting, statusInfoOf(t, resp).Status)
	return resp
}

// sendPollReq polls with certReqID in the transaction of last, the previous response.
func sendPollReq(t *testing.T, ts *httptest.Server, secret []byte, last *pkicmp.PKIMessage, certReqID int64) *pkicmp.PKIMessage {
	t.Helper()
	content := pkicmp.PollReqContent{certReqID}
	poll := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&content), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: last.Header.TransactionID,
		RecipNonce:    last.Header.SenderNonce,
	})
	protectMAC(poll, secret)
	return postCMP(t, ts, poll)
}

// hasImplicitConfirm reports whether a response grants implicit confirmation.
func hasImplicitConfirm(msg *pkicmp.PKIMessage) bool {
	for _, info := range msg.Header.GeneralInfo {
		if info.InfoType.Equal(pkicmp.ImplicitConfirmInfoValue().InfoType) {
			return true
		}
	}
	return false
}

// pollRepItem returns the single item of a pollRep.
func pollRepItem(t *testing.T, msg *pkicmp.PKIMessage) pkicmp.PollRepItem {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypePollRep, msg.Body.Type, "expected pollRep, got %s", msg.Body.Type)
	rep, err := msg.Body.PollRep()
	require.NoError(t, err)
	require.Len(t, *rep, 1)
	return (*rep)[0]
}

// RFC 9483 §4.4: a request held for approval answers waiting, polls until the CA decides and then confirms as usual.
func TestDelayedEnrollmentApproved(t *testing.T) {
	secret := []byte("delayed-approved")
	ca := newApprovalCA(func(check int) string {
		if check < 2 {
			return ""
		}
		return "approve"
	})
	_, ts := newApprovalServer(t, ca, secret)

	waiting := sendWaitingIR(t, ts, secret, false)
	assert.Equal(t, pkicmp.PKIFreeText{"waiting for approval"}, statusInfoOf(t, waiting).StatusString, "the CA's reason travels with the waiting status")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	c := client.NewClient(ts.URL, client.WithCheckAfterLimits(time.Millisecond, 1100*time.Millisecond))
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "approved"}),
		client.WithSender(testSender),
		client.WithSenderKID([]byte(testSender.String())),
	)
	require.NoError(t, err)
	assert.Equal(t, "approved", result.Certificate.Subject.CommonName)
	assert.Equal(t, 2, ca.checkCount())
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
}

// RFC 9810 §5.3.22: a request rejected while waiting gets the ip it would have got at once, and the transaction ends.
func TestDelayedEnrollmentRejected(t *testing.T) {
	secret := []byte("delayed-rejected")
	ca := newApprovalCA(func(int) string { return "reject" })
	_, ts := newApprovalServer(t, ca, secret)

	waiting := sendWaitingIR(t, ts, secret, false)
	final := sendPollReq(t, ts, secret, waiting, 0)
	require.Equal(t, pkicmp.BodyTypeIP, final.Body.Type)
	rep, err := final.Body.IP()
	require.NoError(t, err)
	require.Len(t, rep.Response, 1)
	assert.Equal(t, int64(0), rep.Response[0].CertReqID)
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
	assert.Equal(t, pkicmp.FailNotAuthorized, rep.Response[0].Status.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"rejected by an operator"}, rep.Response[0].Status.StatusString)
	assert.Nil(t, rep.Response[0].CertifiedKeyPair)

	again := sendPollReq(t, ts, secret, final, 0)
	assert.Equal(t, pkicmp.BodyTypeError, again.Body.Type, "a decided request no longer waits")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	c := client.NewClient(ts.URL, client.WithCheckAfterLimits(time.Millisecond, time.Second))
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "rejected"}),
		client.WithSender(testSender),
		client.WithSenderKID([]byte(testSender.String())),
	)
	require.Error(t, err)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailNotAuthorized), "got %v", err)
}

// A pollReq names the waiting request by its certReqId or by -1 for the whole message, and the final response keeps the request's certReqId.
func TestPollReqCertReqID(t *testing.T) {
	secret := []byte("delayed-certreqid")

	t.Run("OtherIDRefused", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "approve" })
		_, ts := newApprovalServer(t, ca, secret)
		waiting := sendWaitingIR(t, ts, secret, false)
		resp := sendPollReq(t, ts, secret, waiting, 5)
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadRequest, statusInfoOf(t, resp).FailInfo)
		assert.Zero(t, ca.checkCount(), "the CA is not asked about another request")

		final := sendPollReq(t, ts, secret, waiting, -1)
		require.Equal(t, pkicmp.BodyTypeIP, final.Body.Type)
		rep, err := final.Body.IP()
		require.NoError(t, err)
		assert.Equal(t, int64(0), rep.Response[0].CertReqID)
		cert := issuedCertificate(t, final)
		conf := sendCertConf(t, ts, final, secret, certStatus(t, cert, 0, false))
		assert.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
	})

	t.Run("P10CRPolledWithZero", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "approve" })
		_, ts := newApprovalServer(t, ca, secret)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "delayed-p10cr"}}, key)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		req := pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(csr), macMessageOpts())
		protectMAC(req, secret)
		waiting := postCMP(t, ts, req)
		require.Equal(t, pkicmp.StatusWaiting, statusInfoOf(t, waiting).Status)

		final := sendPollReq(t, ts, secret, waiting, 0)
		require.Equal(t, pkicmp.BodyTypeCP, final.Body.Type)
		rep, err := final.Body.CP()
		require.NoError(t, err)
		assert.Equal(t, int64(-1), rep.Response[0].CertReqID)
	})
}

// RFC 9483 §4.4: polling before checkAfter costs a round trip and leaves the request waiting.
func TestEarlyPollGetsPollRep(t *testing.T) {
	secret := []byte("delayed-early")
	ca := newApprovalCA(func(int) string { return "" })
	_, ts := newApprovalServer(t, ca, secret)

	waiting := sendWaitingIR(t, ts, secret, false)
	first := sendPollReq(t, ts, secret, waiting, 0)
	item := pollRepItem(t, first)
	assert.Equal(t, int64(1), item.CheckAfter)
	assert.Equal(t, int64(0), item.CertReqID)
	assert.Equal(t, pkicmp.PKIFreeText{"still waiting"}, item.Reason)

	early := sendPollReq(t, ts, secret, first, -1)
	item = pollRepItem(t, early)
	assert.Equal(t, int64(1), item.CheckAfter, "the time left is rounded up to a whole second")
	assert.Equal(t, int64(-1), item.CertReqID, "the pollRep repeats the certReqId of the pollReq")
	assert.Equal(t, 1, ca.checkCount(), "an early poll does not reach the CA")

	time.Sleep(time.Second)
	assert.Equal(t, pkicmp.BodyTypePollRep, sendPollReq(t, ts, secret, early, 0).Body.Type)
	assert.Equal(t, 2, ca.checkCount())
}

// Implicit confirmation follows the delayed request, since the pollReq that collects the certificate does not repeat it.
func TestImplicitConfirmAfterPolling(t *testing.T) {
	secret := []byte("delayed-implicit")
	ca := newApprovalCA(func(int) string { return "approve" })
	_, ts := newApprovalServer(t, ca, secret, server.WithImplicitConfirm())

	waiting := sendWaitingIR(t, ts, secret, true)
	assert.False(t, hasImplicitConfirm(waiting), "nothing to confirm yet")

	final := sendPollReq(t, ts, secret, waiting, 0)
	require.Equal(t, pkicmp.StatusAccepted, statusInfoOf(t, final).Status)
	assert.True(t, hasImplicitConfirm(final))
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmImplicit}, ca.statuses)
}

// The waiting lifetime governs waiting requests apart from the confirmation wait, and the CA hears about each one removed.
func TestWaitingLifetime(t *testing.T) {
	secret := []byte("delayed-lifetime")

	t.Run("ConfirmWaitDoesNotApply", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "" })
		srv, ts := newApprovalServer(t, ca, secret, server.WithConfirmWaitTime(time.Millisecond))
		waiting := sendWaitingIR(t, ts, secret, false)
		time.Sleep(5 * time.Millisecond)
		srv.CleanupExpired()
		assert.Equal(t, pkicmp.BodyTypePollRep, sendPollReq(t, ts, secret, waiting, 0).Body.Type)
		assert.Empty(t, ca.expired)
	})

	t.Run("IdleRequestExpires", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "" })
		srv, ts := newApprovalServer(t, ca, secret, server.WithWaitingLifetime(time.Millisecond))
		waiting := sendWaitingIR(t, ts, secret, false)
		time.Sleep(5 * time.Millisecond)
		srv.CleanupExpired()
		assert.Equal(t, []string{"request-1"}, ca.expired)
		resp := sendPollReq(t, ts, secret, waiting, 0)
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Zero(t, ca.checkCount())
	})
}

// delayingRevoker holds every revocation for a decision and revokes it once approved.
type delayingRevoker struct {
	*revokingCA
	decision string
	mu       sync.Mutex
	pending  map[string]*server.RevocationRequest
}

// RevokeCertificate keeps the request and answers that it waits.
func (c *delayingRevoker) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pollRef := fmt.Sprintf("revocation-%d", len(c.pending)+1)
	c.pending[pollRef] = req
	return &server.WaitingError{CheckAfter: time.Second, PollRef: pollRef}
}

// CheckPending revokes or rejects the delayed request according to the decision.
func (c *delayingRevoker) CheckPending(ctx context.Context, pollRef string, sender *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	req := c.pending[pollRef]
	c.mu.Unlock()
	switch {
	case req == nil:
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	case c.decision == "reject":
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "rejected by an operator"}
	default:
		return nil, c.revokingCA.RevokeCertificate(ctx, req, sender)
	}
}

// RFC 9483 §4.4: a delayed revocation answers with an error message with status waiting, then an rp after polling.
func TestDelayedRevocation(t *testing.T) {
	for _, decision := range []string{"approve", "reject"} {
		t.Run(decision, func(t *testing.T) {
			f := newRevocationFixture(t)
			ca := &delayingRevoker{revokingCA: f.backend, decision: decision, pending: map[string]*server.RevocationRequest{}}
			ts := f.serve(t, ca, server.LightweightPolicy())

			first := postCMP(t, ts, signedRR(t, f.ee, pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonKeyCompromise)}, pkicmp.MessageOptions{}))
			require.Equal(t, pkicmp.BodyTypeError, first.Body.Type)
			assert.Equal(t, pkicmp.StatusWaiting, statusInfoOf(t, first).Status)
			assert.Empty(t, f.backend.revoked)

			creds, err := pkicmp.NewSignatureCredentials(f.ee.key, f.ee.cert)
			require.NoError(t, err)
			c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(f.caCert)), client.WithCheckAfterLimits(time.Millisecond, time.Second))
			err = c.SendRR(context.Background(), f.ee.cert, pkicmp.CRLReasonKeyCompromise, creds)
			if decision == "reject" {
				require.Error(t, err)
				assert.True(t, pkicmp.HasFailure(err, pkicmp.FailNotAuthorized), "got %v", err)
				assert.Empty(t, f.backend.revoked)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, pkicmp.CRLReasonKeyCompromise, f.backend.revoked[f.ee.cert.SerialNumber.String()])
		})
	}
}
