package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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

// messageLog passes requests to next and keeps every request it receives.
type messageLog struct {
	next     http.Handler
	mu       sync.Mutex
	messages []*pkicmp.PKIMessage
}

// ServeHTTP records the request and passes it on unchanged.
func (l *messageLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		if msg, err := pkicmp.ParsePKIMessage(body); err == nil {
			l.mu.Lock()
			l.messages = append(l.messages, msg)
			l.mu.Unlock()
		}
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	l.next.ServeHTTP(w, r)
}

// last returns the last request of type t, nil when none arrived.
func (l *messageLog) last(t pkicmp.BodyType) *pkicmp.PKIMessage {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, msg := range slices.Backward(l.messages) {
		if msg.Body.Type == t {
			return msg
		}
	}
	return nil
}

// faultServer serves a server package CA for requests MAC-protected with "secret" and logs the requests.
func faultServer(t *testing.T, opts ...server.Option) (*httptest.Server, *confirmingCA, *messageLog) {
	t.Helper()
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.ca.PrivateKey()
	require.NoError(t, err)
	// Error messages are signed (RFC 9810 §5.3.21), also those that answer an unprotected request.
	base := make([]server.Option, 0, 2+len(opts))
	base = append(base,
		server.WithSecretLookup(server.SecretLookupFunc(func(pkix.Name, []byte) ([]byte, error) { return []byte("secret"), nil })),
		server.WithSigner(caKey, &caCert),
	)
	srv := server.NewCAServer(ca, server.LightweightPolicy(), append(base, opts...)...)
	require.NoError(t, srv.Err())
	log := &messageLog{next: srv}
	ts := httptest.NewServer(log)
	t.Cleanup(ts.Close)
	return ts, ca, log
}

// enrollWithFault sends an ir to the CA of ts that ca issues from, with the request options.
func enrollWithFault(t *testing.T, ts *httptest.Server, ca *confirmingCA, opts ...client.RequestOption) (*client.EnrollResult, error) {
	t.Helper()
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	return sendIR(t, ts.URL, &caCert, opts...)
}

// onBody returns a mutator that applies change to messages of type t only.
func onBody(t pkicmp.BodyType, change func(msg, answered *pkicmp.PKIMessage) error) client.MessageMutator {
	return func(msg, answered *pkicmp.PKIMessage) error {
		if msg.Body.Type != t {
			return nil
		}
		return change(msg, answered)
	}
}

// changeCertStatus returns a mutator that changes the CertStatus of a certConf.
func changeCertStatus(change func(*pkicmp.CertStatus)) client.MessageMutator {
	return onBody(pkicmp.BodyTypeCertConf, func(msg, _ *pkicmp.PKIMessage) error {
		conf, err := msg.Body.CertConf()
		if err != nil {
			return err
		}
		change(&(*conf)[0])
		msg.Body = pkicmp.NewCertConfBody(conf)
		return nil
	})
}

// confirmationFailure checks that err is a ConfirmationError whose CA status carries failInfo and a text containing text.
func confirmationFailure(t *testing.T, err error, failInfo pkicmp.PKIFailureInfo, text string) {
	t.Helper()
	var ce *client.ConfirmationError
	require.ErrorAs(t, err, &ce, "the certificate was issued, so the failure is one of the confirmation")
	require.NotNil(t, ce.Certificate)
	var se *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, failInfo, se.FailInfo)
	assert.Contains(t, se.StatusString, text)
}

// RFC 9483 §3.6.1: a certConf that rejects the certificate gets pkiConf. The CA hears the rejection.
func TestWithCertConfStatusRejects(t *testing.T) {
	ts, ca, log := faultServer(t)
	reject := &pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, StatusString: pkicmp.PKIFreeText{"refused by the test"}}
	result, err := enrollWithFault(t, ts, ca, client.WithCertConfStatus(reject))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate, "the CA answered pkiConf, so the certificate is returned")

	conf, err := log.last(pkicmp.BodyTypeCertConf).Body.CertConf()
	require.NoError(t, err)
	require.Len(t, *conf, 1)
	assert.Equal(t, reject, (*conf)[0].StatusInfo)
	expected, err := pkicmp.NewCertStatus(result.Certificate, 0)
	require.NoError(t, err)
	assert.Equal(t, expected.CertHash, (*conf)[0].CertHash, "the rejection names the certificate")
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, ca.statuses)
}

// Without WithCertConfStatus the certConf leaves statusInfo out, which accepts the certificate.
func TestCertConfStatusDefaultAccepts(t *testing.T) {
	ts, ca, log := faultServer(t)
	_, err := enrollWithFault(t, ts, ca, client.WithCertConfStatus(nil))
	require.NoError(t, err)
	conf, err := log.last(pkicmp.BodyTypeCertConf).Body.CertConf()
	require.NoError(t, err)
	assert.Nil(t, (*conf)[0].StatusInfo)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
}

// RFC 9483 §4.1.1 and §5.1.2: a certConf with a wrong certHash or certReqId names no issued
// certificate, so the CA refuses it with badCertId and does not confirm the certificate.
func TestWithMessageMutatorCertStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pkicmp.CertStatus)
		text   string
	}{
		{"certHash", func(s *pkicmp.CertStatus) { s.CertHash[0] ^= 0xff }, "certHash mismatch"},
		{"certReqId", func(s *pkicmp.CertStatus) { s.CertReqID = 1 }, "certReqId does not match the issued certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, ca, _ := faultServer(t)
			_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(changeCertStatus(tc.change)))
			confirmationFailure(t, err, pkicmp.FailBadCertId, tc.text)
			assert.Empty(t, ca.statuses)
		})
	}
}

// RFC 9483 §3.5: a certConf whose recipNonce is not the senderNonce of the ip is refused with
// badRecipientNonce.
func TestWithMessageMutatorStaleRecipNonce(t *testing.T) {
	ts, ca, _ := faultServer(t)
	stale := onBody(pkicmp.BodyTypeCertConf, func(msg, answered *pkicmp.PKIMessage) error {
		require.Equal(t, answered.Header.SenderNonce, msg.Header.RecipNonce, "the mutator sees the header as built")
		msg.Header.RecipNonce = make([]byte, 16)
		return nil
	})
	_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(stale))
	confirmationFailure(t, err, pkicmp.FailBadRecipientNonce, "recipNonce mismatch")
	assert.Empty(t, ca.statuses)
}

// RFC 9483 §3.5: a certConf for a transactionID the CA does not hold is refused with badRequest.
// The client checks the answer against the transactionID it sent, which the CA repeats.
func TestWithMessageMutatorWrongTransactionID(t *testing.T) {
	ts, ca, _ := faultServer(t)
	wrong := onBody(pkicmp.BodyTypeCertConf, func(msg, _ *pkicmp.PKIMessage) error {
		msg.Header.TransactionID = []byte("another-transact")
		return nil
	})
	_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(wrong))
	confirmationFailure(t, err, pkicmp.FailBadRequest, "unknown transaction")
	assert.Empty(t, ca.statuses)
}

// RFC 9483 §3.1 asks for a fresh senderNonce in every message. The server checks a repeated one in
// certConf only under strict profile validation.
func TestWithMessageMutatorReusedSenderNonce(t *testing.T) {
	reuse := func() client.MessageMutator {
		var first []byte
		return func(msg, answered *pkicmp.PKIMessage) error {
			if answered == nil {
				first = msg.Header.SenderNonce
				return nil
			}
			msg.Header.SenderNonce = first
			return nil
		}
	}

	ts, ca, log := faultServer(t)
	_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(reuse()))
	require.NoError(t, err)
	assert.Equal(t, log.last(pkicmp.BodyTypeIR).Header.SenderNonce, log.last(pkicmp.BodyTypeCertConf).Header.SenderNonce)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)

	ts, ca, _ = faultServer(t, server.WithStrictProfileValidation())
	_, err = enrollWithFault(t, ts, ca, client.WithSender(pkix.Name{CommonName: "test"}), client.WithMessageMutator(reuse()))
	confirmationFailure(t, err, pkicmp.FailBadSenderNonce, "senderNonce reused")
	assert.Empty(t, ca.statuses)
}

// RFC 9483 §3.5: a certConf without protection is refused.
func TestWithProtectedMessageMutatorRemovesProtection(t *testing.T) {
	ts, ca, log := faultServer(t)
	strip := onBody(pkicmp.BodyTypeCertConf, func(msg, _ *pkicmp.PKIMessage) error {
		require.NotNil(t, msg.Header.ProtectionAlg, "the mutator runs after the protection")
		msg.Header.ProtectionAlg = nil
		msg.Protection = nil
		return nil
	})
	_, err := enrollWithFault(t, ts, ca, client.WithProtectedMessageMutator(strip))
	confirmationFailure(t, err, pkicmp.FailBadMessageCheck, "message not protected")
	assert.Nil(t, log.last(pkicmp.BodyTypeCertConf).Header.ProtectionAlg)
	assert.Empty(t, ca.statuses)
}

// A change after protection breaks the protection, which the CA refuses.
func TestWithProtectedMessageMutatorBreaksProtection(t *testing.T) {
	ts, ca, _ := faultServer(t)
	_, err := enrollWithFault(t, ts, ca, client.WithProtectedMessageMutator(changeCertStatus(func(s *pkicmp.CertStatus) {
		s.CertHash[0] ^= 0xff
	})))
	var se *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, pkicmp.FailBadMessageCheck, se.FailInfo)
}

// RFC 9483 §4.1.1: a certConf after the confirmWaitTime of the ip is refused. The CA hears that the
// certificate expired. The mutator finds the deadline in the response it answers.
func TestWithMessageMutatorLateCertConf(t *testing.T) {
	ts, ca, _ := faultServer(t, server.WithConfirmWaitTime(time.Second))
	late := onBody(pkicmp.BodyTypeCertConf, func(msg, answered *pkicmp.PKIMessage) error {
		var deadline time.Time
		for _, item := range answered.Header.GeneralInfo {
			if d, err := pkicmp.ParseConfirmWaitTime(item); err == nil {
				deadline = d
			}
		}
		require.False(t, deadline.IsZero(), "the ip carries confirmWaitTime")
		// GeneralizedTime keeps whole seconds, so the wait covers the truncated part.
		time.Sleep(time.Until(deadline.Add(2 * time.Second)))
		msg.Header.MessageTime = time.Now()
		return nil
	})
	_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(late))
	confirmationFailure(t, err, pkicmp.FailBadRequest, "certConf after confirmWaitTime")
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmExpired}, ca.statuses)
}

// The mutators see every message of a polled enrollment with the response it answers. They run in
// the order of the options.
func TestMessageMutatorsSeeEveryMessage(t *testing.T) {
	ca := newDelayedCA(func(check int) bool { return check >= 2 })
	ts, _ := serveDelayedCA(t, ca)
	c := newPendingClient(t, ts.URL, ca, client.WithCheckAfterLimits(0, time.Second))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var seen []string
	record := func(tag string) client.MessageMutator {
		return func(msg, answered *pkicmp.PKIMessage) error {
			answer := "none"
			if answered != nil {
				answer = answered.Body.Type.String()
			}
			seen = append(seen, tag+" "+msg.Body.Type.String()+"<"+answer)
			return nil
		}
	}
	_, err = c.SendIR(context.Background(), key, macCredentials(t),
		client.WithSenderKID([]byte("test")),
		client.WithTemplateSubject(pkix.Name{CommonName: "mutated"}),
		client.WithMessageMutator(record("a")),
		client.WithMessageMutator(record("b")),
		client.WithProtectedMessageMutator(record("p")))
	require.NoError(t, err)
	assert.Equal(t, []string{
		"a ir<none", "b ir<none", "p ir<none",
		"a pollReq<ip", "b pollReq<ip", "p pollReq<ip",
		"a pollReq<pollRep", "b pollReq<pollRep", "p pollReq<pollRep",
		"a certConf<ip", "b certConf<ip", "p certConf<ip",
	}, seen)
}

// RFC 9483 §3.5: a pollReq whose recipNonce or transactionID does not continue the transaction is
// refused, which ends the enrollment without a certificate.
func TestWithMessageMutatorPollReq(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*pkicmp.PKIMessage)
		failInfo pkicmp.PKIFailureInfo
		text     string
	}{
		{"recipNonce", func(m *pkicmp.PKIMessage) { m.Header.RecipNonce = make([]byte, 16) }, pkicmp.FailBadRecipientNonce, "recipNonce mismatch"},
		{"transactionID", func(m *pkicmp.PKIMessage) { m.Header.TransactionID = []byte("another-transact") }, pkicmp.FailBadRequest, "no pending certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newDelayedCA(func(int) bool { return true })
			ts, _ := serveDelayedCA(t, ca)
			c := newPendingClient(t, ts.URL, ca, client.WithCheckAfterLimits(0, time.Second))
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			_, err = c.SendIR(context.Background(), key, macCredentials(t),
				client.WithSenderKID([]byte("test")),
				client.WithTemplateSubject(pkix.Name{CommonName: "mutated"}),
				client.WithMessageMutator(onBody(pkicmp.BodyTypePollReq, func(msg, _ *pkicmp.PKIMessage) error {
					tc.change(msg)
					return nil
				})))
			var se *pkicmp.PKIStatusError
			require.ErrorAs(t, err, &se)
			assert.Equal(t, tc.failInfo, se.FailInfo)
			assert.Equal(t, tc.text, se.StatusString)
			var ce *client.ConfirmationError
			assert.False(t, errors.As(err, &ce), "no certificate was issued")
			assert.Zero(t, ca.checkCount(), "the CA is not asked about a refused pollReq")
		})
	}
}

// The popdecr that answers a challenge passes through the mutators with the popdecc it answers.
func TestMessageMutatorSeesPopDecR(t *testing.T) {
	secret := []byte("secret")
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	n := big.NewInt(42)
	sha256 := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	ts, _ := challengeServer(t, secret, func(_ *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge {
		return pkicmp.Challenge{OWF: sha256, Witness: pkicmp.ChallengeWitness(crypto.SHA256, n), EncryptedRand: encryptedRand(t, n, sender, kem.EncapsulationKey())}
	})
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)

	var seen []string
	record := func(msg, answered *pkicmp.PKIMessage) error {
		if answered != nil {
			seen = append(seen, msg.Body.Type.String()+"<"+answered.Body.Type.String())
		}
		return nil
	}
	// The server challenges every message, so the enrollment fails after the popdecr.
	_, err = client.NewClient(ts.URL).SendIRWithIndirectPOP(context.Background(), kem, client.ChallengeResponse, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "mutated"}), client.WithMessageMutator(record))
	require.Error(t, err)
	assert.Equal(t, []string{"popdecr<popdecc"}, seen)
}

// A mutator error stops the operation before the message is sent.
func TestMessageMutatorErrorStops(t *testing.T) {
	ts, ca, log := faultServer(t)
	stop := errors.New("stop here")
	_, err := enrollWithFault(t, ts, ca, client.WithMessageMutator(onBody(pkicmp.BodyTypeCertConf, func(*pkicmp.PKIMessage, *pkicmp.PKIMessage) error {
		return stop
	})))
	require.ErrorIs(t, err, stop)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "change certConf", ce.Op)
	assert.Nil(t, log.last(pkicmp.BodyTypeCertConf), "the certConf is not sent")

	_, err = enrollWithFault(t, ts, ca, client.WithMessageMutator(func(*pkicmp.PKIMessage, *pkicmp.PKIMessage) error { return stop }))
	require.ErrorIs(t, err, stop)
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "change request", ce.Op)
}

// The mutators also change revocation requests.
func TestMessageMutatorRevocation(t *testing.T) {
	ts, ca, log := faultServer(t)
	result, err := enrollWithFault(t, ts, ca)
	require.NoError(t, err)
	caCert, err := ca.ca.X509Certificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(&caCert)
	err = client.NewClient(ts.URL, client.WithTrustedCAs(pool)).SendRR(context.Background(), result.Certificate,
		pkicmp.CRLReasonKeyCompromise, macCredentials(t), client.WithSenderKID([]byte("test")),
		client.WithProtectedMessageMutator(func(msg, _ *pkicmp.PKIMessage) error {
			msg.Header.ProtectionAlg = nil
			msg.Protection = nil
			return nil
		}))
	var se *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, pkicmp.FailBadMessageCheck, se.FailInfo)
	assert.Nil(t, log.last(pkicmp.BodyTypeRR).Header.ProtectionAlg)
}
