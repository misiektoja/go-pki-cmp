package server_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// pollWithSenderNonce polls in the transaction of last with senderNonce nonce.
func pollWithSenderNonce(t *testing.T, ts *httptest.Server, secret []byte, last *pkicmp.PKIMessage, nonce []byte) *pkicmp.PKIMessage {
	t.Helper()
	content := pkicmp.PollReqContent{0}
	poll := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&content), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: last.Header.TransactionID,
		RecipNonce:    last.Header.SenderNonce,
	})
	poll.Header.SenderNonce = bytes.Clone(nonce)
	protectMAC(poll, secret)
	return postCMP(t, ts, poll)
}

// RFC 9483 §3.1: under WithStrictProfileValidation a pollReq whose senderNonce
// repeats the last request or response of the transaction is refused, and the
// request keeps waiting.
func TestStrictPollReqRefusesReusedSenderNonce(t *testing.T) {
	secret := []byte("strict-pollreq-nonce")
	tests := []struct {
		name string
		// firstPoll polls once before, so the refused pollReq answers a pollRep instead of the ip.
		firstPoll bool
		// nonce returns the senderNonce to repeat from the response the pollReq answers.
		nonce func(last *pkicmp.PKIMessage) []byte
	}{
		{name: "the ir's", nonce: func(ip *pkicmp.PKIMessage) []byte { return ip.Header.RecipNonce }},
		{name: "the ip's", nonce: func(ip *pkicmp.PKIMessage) []byte { return ip.Header.SenderNonce }},
		{
			name:      "the previous pollReq's",
			firstPoll: true,
			nonce:     func(pollRep *pkicmp.PKIMessage) []byte { return pollRep.Header.RecipNonce },
		},
		{
			name:      "the pollRep's",
			firstPoll: true,
			nonce:     func(pollRep *pkicmp.PKIMessage) []byte { return pollRep.Header.SenderNonce },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := newApprovalCA(func(int) string { return "" })
			_, ts := newApprovalServer(t, ca, secret, server.WithStrictProfileValidation())
			last := sendWaitingIR(t, ts, secret, false)
			if tc.firstPoll {
				last = sendPollReq(t, ts, secret, last, 0)
				require.Equal(t, pkicmp.BodyTypePollRep, last.Body.Type)
			}

			status := errorStatus(t, pollWithSenderNonce(t, ts, secret, last, tc.nonce(last)))
			assert.Equal(t, pkicmp.FailBadSenderNonce, status.FailInfo)
			assert.Equal(t, pkicmp.PKIFreeText{"senderNonce reused"}, status.StatusString)

			again := sendPollReq(t, ts, secret, last, 0)
			assert.Equal(t, pkicmp.BodyTypePollRep, again.Body.Type, "the request still waits")
		})
	}
}

// Without WithStrictProfileValidation a repeated senderNonce in a pollReq is accepted.
func TestPollReqReusedSenderNonceAccepted(t *testing.T) {
	secret := []byte("default-pollreq-nonce")
	ca := newApprovalCA(func(int) string { return "" })
	_, ts := newApprovalServer(t, ca, secret)
	ip := sendWaitingIR(t, ts, secret, false)
	resp := pollWithSenderNonce(t, ts, secret, ip, ip.Header.RecipNonce)
	assert.Equal(t, pkicmp.BodyTypePollRep, resp.Body.Type)
}

// RFC 9483 §3.1: under WithStrictProfileValidation a popdecr whose senderNonce
// repeats the ir or the popdecc is refused before the CA sees the request.
func TestStrictPopDecRRefusesReusedSenderNonce(t *testing.T) {
	secret := []byte("strict-popdecr-nonce")
	kem := popKeys(t)[0]
	for _, tc := range []struct {
		name  string
		nonce func(popdecc *pkicmp.PKIMessage) []byte
	}{
		{name: "the ir's", nonce: func(popdecc *pkicmp.PKIMessage) []byte { return popdecc.Header.RecipNonce }},
		{name: "the popdecc's", nonce: func(popdecc *pkicmp.PKIMessage) []byte { return popdecc.Header.SenderNonce }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newPOPCA(t)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithChallengeResponsePOP(),
				server.WithStrictProfileValidation(),
			))
			defer ts.Close()

			popdecc := exchange(t, ts, indirectPOPRequest(t, kem, pkicmp.SubsequentMessageChallengeResp, false), secret)
			popdecr := answerChallenge(t, popdecc, kem)
			popdecr.Header.SenderNonce = bytes.Clone(tc.nonce(popdecc))
			status := errorStatus(t, exchange(t, ts, popdecr, secret))
			assert.Equal(t, pkicmp.FailBadSenderNonce, status.FailInfo)
			assert.Equal(t, pkicmp.PKIFreeText{"senderNonce reused"}, status.StatusString)
			methods, _ := ca.recorded()
			assert.Empty(t, methods)

			requirePlaintextCertificate(t, exchange(t, ts, answerChallenge(t, popdecc, kem), secret))
		})
	}
}

// A waiting request restored from a snapshot still refuses a pollReq that
// repeats the senderNonce of the request.
func TestStrictPollReqNonceSurvivesSnapshot(t *testing.T) {
	secret := []byte("strict-pollreq-snapshot")
	ca := newApprovalCA(func(int) string { return "" })
	first, ts1 := newApprovalServer(t, ca, secret, server.WithStrictProfileValidation())
	ip := sendWaitingIR(t, ts1, secret, false)
	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)

	second, ts2 := newApprovalServer(t, ca, secret, server.WithStrictProfileValidation())
	require.NoError(t, second.RestoreTransactions(snapshot, nil))
	status := errorStatus(t, pollWithSenderNonce(t, ts2, secret, ip, ip.Header.RecipNonce))
	assert.Equal(t, pkicmp.FailBadSenderNonce, status.FailInfo)
}
