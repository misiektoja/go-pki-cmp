//go:build integration

package certifier

import (
	"context"
	"crypto/x509"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// heldRequest is a certificate request that waits for a decision.
type heldRequest struct {
	kind server.RequestType
	tmpl *x509.Certificate
}

// heldCA holds every certificate request and issues it when the client
// polls, as a CA does once an operator approves the request.
type heldCA struct {
	*recordingCA
	mu   sync.Mutex
	held map[string]heldRequest
	// checks counts the polls that reached the CA.
	checks int
}

// newHeldCA returns a heldCA around a new mockserver CA.
func newHeldCA(t *testing.T) *heldCA {
	t.Helper()
	return &heldCA{recordingCA: newCA(t), held: map[string]heldRequest{}}
}

// IssueCertificate keeps the request and tells the client to poll after a second.
func (c *heldCA) IssueCertificate(_ context.Context, kind server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pollRef := fmt.Sprintf("held-%d", len(c.held)+1)
	c.held[pollRef] = heldRequest{kind: kind, tmpl: tmpl}
	return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: time.Second, PollRef: pollRef, Reason: "waiting for approval"}}, nil
}

// CheckPending issues the held request.
func (c *heldCA) CheckPending(ctx context.Context, pollRef string, sender *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	c.checks++
	req, ok := c.held[pollRef]
	c.mu.Unlock()
	if !ok {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "unknown request"}
	}
	return c.recordingCA.IssueCertificate(ctx, req.kind, req.tmpl, sender)
}

// checkCount returns how many polls reached the CA.
func (c *heldCA) checkCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checks
}

// cmpclient polls by itself after a waiting answer, but its pollReq carries no
// recipNonce. The server refuses such a poll unless WithOptionalPollReqRecipNonce
// is set. The strict profile always refuses it.
func TestCmpclientPolling(t *testing.T) {
	c := clients(t)
	// enroll sends a shared-secret ir that the CA holds and returns the client output.
	enroll := func(t *testing.T, ts *testServer, dir string) string {
		_, keyPEM := newECKey(t)
		c.put(t, dir, "ec.key", keyPEM)
		return cmpclient(t, c, ts, dir, "enroll", append([]string{"--type", "ir", "--subject", "CN=cmpclient-poll", "--private", "ec.key"}, macArgs...)...)
	}

	t.Run("RefusedByDefault", func(t *testing.T) {
		ca := newHeldCA(t)
		ts := serveCA(t, c, ca, ca.recordingCA, server.WithPoposkInputVariants())
		dir := c.workdir(t)
		out := enroll(t, ts, dir)
		assert.Contains(t, out, "missing recipNonce")
		assert.Nil(t, c.get(t, dir, "enroll/cert-0.pem"))
		assert.Zero(t, ca.checkCount(), "the refused poll did not reach the CA")
	})
	t.Run("AcceptedWithOption", func(t *testing.T) {
		ca := newHeldCA(t)
		ts := serveCA(t, c, ca, ca.recordingCA, server.WithPoposkInputVariants(), server.WithOptionalPollReqRecipNonce())
		dir := c.workdir(t)
		enroll(t, ts, dir)
		data := c.get(t, dir, "enroll/cert-0.pem")
		require.NotNil(t, data, "the client saved no certificate")
		cert := parseCertificate(t, data)
		status, ok := ca.confirmation(cert)
		require.True(t, ok, "the server reported no confirmation")
		assert.Equal(t, server.ConfirmAccepted, status)
		assert.Equal(t, 1, ca.checkCount())
	})
}

// pendingTransaction matches the line ssh-cmpclient prints after a waiting answer.
var pendingTransaction = regexp.MustCompile(`Poll again with transaction ID ([0-9A-Fa-f]+) certReqId (\d+)`)

// ssh-cmpclient stops after a waiting answer and collects the result with a
// separate POLL, whose pollReq carries no recipNonce. The server refuses it
// unless WithOptionalPollReqRecipNonce is set.
func TestSSHCmpclientPolling(t *testing.T) {
	c := clients(t)
	skipWithoutSSHClient(t, c)
	// poll enrolls with INITIALIZE, which the CA holds, then polls once and returns the POLL output.
	poll := func(t *testing.T, ts *testServer, dir string) string {
		out := sshCmpclient(t, c, ts, dir, "INITIALIZE", "-P", "generate://pkcs8@ec:256/a", "-o", "a", "-p", pskReference+":"+pskSecret, "-s", "CN=ssh-poll")
		pending := pendingTransaction.FindStringSubmatch(out)
		require.NotNil(t, pending, "ssh-cmpclient reported no pending transaction")
		time.Sleep(time.Second)
		return sshCmpclient(t, c, ts, dir, "POLL", "-p", pskReference+":"+pskSecret, "-I", pending[1]+":"+pending[2], "-o", "a")
	}

	t.Run("RefusedByDefault", func(t *testing.T) {
		ca := newHeldCA(t)
		ts := serveCA(t, c, ca, ca.recordingCA)
		dir := c.workdir(t)
		out := poll(t, ts, dir)
		assert.Contains(t, out, "missing recipNonce")
		assert.Nil(t, c.get(t, dir, "a-0.crt"))
		assert.Zero(t, ca.checkCount())
	})
	t.Run("AcceptedWithOption", func(t *testing.T) {
		ca := newHeldCA(t)
		ts := serveCA(t, c, ca, ca.recordingCA, server.WithOptionalPollReqRecipNonce())
		dir := c.workdir(t)
		poll(t, ts, dir)
		requireIssued(t, c, ts, dir, "a-0.crt", sshKey(t, c, dir, "a"))
		assert.Equal(t, 1, ca.checkCount())
	})
}
