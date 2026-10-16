package server_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// sendPollReqWithNonce polls for the waiting request in the transaction of
// last with recipNonce set to nonce. A nil nonce leaves the field out.
func sendPollReqWithNonce(t *testing.T, ts *httptest.Server, secret []byte, last *pkicmp.PKIMessage, nonce []byte) *pkicmp.PKIMessage {
	t.Helper()
	content := pkicmp.PollReqContent{0}
	poll := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&content), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: last.Header.TransactionID,
		RecipNonce:    nonce,
	})
	protectMAC(poll, secret)
	return postCMP(t, ts, poll)
}

// A pollReq without recipNonce is refused by default and accepted with
// WithOptionalPollReqRecipNonce. A recipNonce that is present must match
// either way.
func TestPollReqOptionalRecipNonce(t *testing.T) {
	secret := []byte("pollreq-recipnonce")

	t.Run("MissingRejectedByDefault", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "approve" })
		_, ts := newApprovalServer(t, ca, secret)
		waiting := sendWaitingIR(t, ts, secret, false)
		resp := sendPollReqWithNonce(t, ts, secret, waiting, nil)
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		info := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"missing recipNonce"}, info.StatusString)
		assert.Zero(t, ca.checkCount(), "the CA is not asked")
	})

	// The device polls without recipNonce until the CA decides and then
	// confirms with the nonce of the final response as usual.
	t.Run("MissingAcceptedWithOption", func(t *testing.T) {
		ca := newApprovalCA(func(check int) string {
			if check < 2 {
				return ""
			}
			return "approve"
		})
		_, ts := newApprovalServer(t, ca, secret, server.WithOptionalPollReqRecipNonce())
		waiting := sendWaitingIR(t, ts, secret, false)

		still := sendPollReqWithNonce(t, ts, secret, waiting, nil)
		assert.Equal(t, pkicmp.PKIFreeText{"still waiting"}, pollRepItem(t, still).Reason)

		time.Sleep(time.Second)
		final := sendPollReqWithNonce(t, ts, secret, still, nil)
		require.Equal(t, pkicmp.BodyTypeIP, final.Body.Type)
		require.Equal(t, pkicmp.StatusAccepted, statusInfoOf(t, final).Status)
		conf := sendCertConf(t, ts, final, secret, certStatus(t, issuedCertificate(t, final), 0, false))
		assert.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
		assert.Equal(t, 2, ca.checkCount())
		assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
	})

	t.Run("MissingRejectedUnderStrictProfile", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "approve" })
		_, ts := newApprovalServer(t, ca, secret, server.WithOptionalPollReqRecipNonce(), server.WithStrictProfileValidation())
		waiting := sendWaitingIR(t, ts, secret, false)
		resp := sendPollReqWithNonce(t, ts, secret, waiting, nil)
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		info := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"missing recipNonce"}, info.StatusString)
		assert.Zero(t, ca.checkCount())
	})

	t.Run("MismatchRejectedWithOption", func(t *testing.T) {
		ca := newApprovalCA(func(int) string { return "approve" })
		_, ts := newApprovalServer(t, ca, secret, server.WithOptionalPollReqRecipNonce())
		waiting := sendWaitingIR(t, ts, secret, false)
		resp := sendPollReqWithNonce(t, ts, secret, waiting, []byte("not-the-response-sender-nonce"))
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		info := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"recipNonce mismatch"}, info.StatusString)
		assert.Zero(t, ca.checkCount())
	})
}
