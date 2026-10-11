package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

func TestPolling(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("poll-secret")

	pollCount := 0
	// The deferred certificate must be issued for the key the request carried,
	// so the requested key is captured here and used once polling completes.
	var requestedKey crypto.PublicKey
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			requestedKey = req.PublicKey
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 1 * time.Second, Reason: "processing"},
			}, nil
		},
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			pollCount++
			if pollCount < 2 {
				return &certResponse{
					Waiting: &server.WaitingResponse{CheckAfter: 0},
				}, nil
			}
			serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
			caCertX509, _ := ca.X509Certificate()
			caKey, _ := ca.PrivateKey()
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: "polled-cert"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, &caCertX509, requestedKey, caKey)
			cert, _ := x509.ParseCertificate(certDER)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "poll-test"}),
		client.WithSender(pkix.Name{CommonName: "poll-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "polled-cert", result.Certificate.Subject.CommonName)
	assert.Equal(t, 2, pollCount)
}

func TestCertConf(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("conf-secret")

	var confirmCalled bool
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(ctx context.Context, confirm *certConfirmation) error {
			confirmCalled = true
			assert.NotEmpty(t, confirm.Accepted)
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "conf-test"}),
		client.WithSender(pkix.Name{CommonName: "conf-test"}),
	)
	require.NoError(t, err)
	assert.True(t, confirmCalled)
}

func TestCertConfRejection(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("conf-rej-secret")

	var confirmCalled bool
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(ctx context.Context, confirm *certConfirmation) error {
			confirmCalled = true
			assert.NotEmpty(t, confirm.Rejected)
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certReqMsg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "test"}),
				PublicKey: pubDER,
			},
		},
	}
	_ = certReqMsg.GeneratePOP(key)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsg}), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	// Send empty certConf (rejection per RFC 9810 §5.3.18).
	emptyConf := pkicmp.CertConfirmContent{}
	confMsg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&emptyConf), macMessageOpts())
	confMsg.Header.TransactionID = msg.Header.TransactionID
	confMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	protectMAC(confMsg, secret)
	confDER, _ := confMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(confDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	confResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])
	assert.Equal(t, pkicmp.BodyTypePKIConf, confResp.Body.Type)
	assert.True(t, confirmCalled)
}

func TestCertConfWithBadHash(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("bad-hash-secret")

	var confirmCalled bool
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(ctx context.Context, confirm *certConfirmation) error {
			confirmCalled = true
			assert.NotEmpty(t, confirm.Rejected)
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certReqMsg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "test"}),
				PublicKey: pubDER,
			},
		},
	}
	_ = certReqMsg.GeneratePOP(key)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsg}), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	badHash := []byte("wrong-hash-value-that-does-not-match")
	certStatus := pkicmp.CertStatus{CertHash: badHash, CertReqID: 0}
	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{certStatus}),
		macMessageOpts(),
	)
	confMsg.Header.TransactionID = msg.Header.TransactionID
	confMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	protectMAC(confMsg, secret)
	confDER, _ := confMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(confDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	confResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])

	// Server should reject certConf with bad hash.
	assert.Equal(t, pkicmp.BodyTypeError, confResp.Body.Type)
	errContent, _ := confResp.Body.Error()
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadCertId)
	assert.False(t, confirmCalled)
}

func TestCertConfWithRejectionStatus(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("rej-status-secret")

	var confirmCalled bool
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(ctx context.Context, confirm *certConfirmation) error {
			confirmCalled = true
			assert.NotEmpty(t, confirm.Rejected)
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certReqMsg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "test"}),
				PublicKey: pubDER,
			},
		},
	}
	_ = certReqMsg.GeneratePOP(key)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsg}), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	ip, err := respMsg.Body.IP()
	require.NoError(t, err)
	require.NotNil(t, ip.Response[0].CertifiedKeyPair)
	issuedCert := ip.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate
	parsedCert, _ := issuedCert.Parse()
	h := crypto.SHA256.New()
	h.Write(parsedCert.Raw)
	certHash := h.Sum(nil)

	rejStatus := pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection}
	certStatus := pkicmp.CertStatus{CertHash: certHash, CertReqID: 0, StatusInfo: &rejStatus}
	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{certStatus}),
		macMessageOpts(),
	)
	confMsg.Header.TransactionID = msg.Header.TransactionID
	confMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	protectMAC(confMsg, secret)
	confDER, _ := confMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(confDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	confResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])
	assert.Equal(t, pkicmp.BodyTypePKIConf, confResp.Body.Type)
	assert.True(t, confirmCalled)
}

func TestPollRequestHandlerError(t *testing.T) {
	secret := []byte("poll-err-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 0},
			}, nil
		},
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemFailure, StatusText: "poll failed"}
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "poll-err-test"}),
		client.WithSender(pkix.Name{CommonName: "poll-err-test"}),
	)
	require.Error(t, err)
}

func TestPollReqWithoutPriorRequest(t *testing.T) {
	secret := []byte("poll-no-prior")

	handler := &mockHandler{
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			assert.Equal(t, requestType(0), poll.OriginalRequest)
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	pollReq := pkicmp.PollReqContent{0}
	msg := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&pollReq), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestPollReqEmptyContent(t *testing.T) {
	secret := []byte("poll-empty")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 0},
			}, nil
		},
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			assert.Equal(t, int64(0), poll.CertReqID)
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	emptyPoll := pkicmp.PollReqContent{}
	msg := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&emptyPoll), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestPollReqWithReason(t *testing.T) {
	secret := []byte("poll-reason")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 1 * time.Second, Reason: "manual approval needed"},
			}, nil
		},
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 2 * time.Second, Reason: "still waiting"},
			}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER}}},
	}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&msgs), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	pollReq := pkicmp.PollReqContent{0}
	pollMsg := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&pollReq), macMessageOpts())
	pollMsg.Header.TransactionID = msg.Header.TransactionID
	pollMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	protectMAC(pollMsg, secret)
	pollDER, _ := pollMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(pollDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	pollResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])
	assert.Equal(t, pkicmp.BodyTypePollRep, pollResp.Body.Type)
	pollRep, _ := pollResp.Body.PollRep()
	require.Len(t, *pollRep, 1)
	assert.Equal(t, int64(2), (*pollRep)[0].CheckAfter)
	assert.Contains(t, (*pollRep)[0].Reason[0], "still waiting")
}

func TestPollReqWithCertReady(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("poll-ready")

	var requestedKey crypto.PublicKey
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			requestedKey = req.PublicKey
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 0},
			}, nil
		},
		handlePollRequest: func(ctx context.Context, poll *pollRequest) (*certResponse, error) {
			serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
			caCertX509, _ := ca.X509Certificate()
			caKey, _ := ca.PrivateKey()
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: "poll-ready-cert"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, &caCertX509, requestedKey, caKey)
			cert, _ := x509.ParseCertificate(certDER)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "poll-ready-test"}),
		client.WithSender(pkix.Name{CommonName: "poll-ready-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "poll-ready-cert", result.Certificate.Subject.CommonName)
}

func TestCertConfWithDifferentCredentials(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret1 := []byte("secret-1")
	secret2 := []byte("secret-2")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	// Server accepts both secrets.
	srv := server.New(handler, server.WithSecretLookup(&multiMACLookup{
		secrets: map[string][]byte{"kid1": secret1, "kid2": secret2},
	}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Send IR with secret1.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certReqMsg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "test"}),
				PublicKey: pubDER,
			},
		},
	}
	_ = certReqMsg.GeneratePOP(key)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsg}), pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "kid1"}),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
	})
	msg.Header.SenderKID = []byte("kid1")
	{
		_mc, _ := pkicmp.NewMACCredentials(secret1)
		_ = _mc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	// Send certConf with secret2 (different credentials) — should be rejected.
	emptyConf := pkicmp.CertConfirmContent{}
	confMsg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&emptyConf), pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "kid2"}),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
	})
	confMsg.Header.TransactionID = msg.Header.TransactionID
	confMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	confMsg.Header.SenderKID = []byte("kid2")
	{
		_mc, _ := pkicmp.NewMACCredentials(secret2)
		_ = _mc.Protect(confMsg)
	}
	confDER, _ := confMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(confDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	confResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])

	// RFC 9483 §3.2: certConf MUST use the same credentials — should be rejected.
	// With composite key, different credentials means "unknown transaction".
	assert.Equal(t, pkicmp.BodyTypeError, confResp.Body.Type)
	errContent, _ := confResp.Body.Error()
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadRequest)
}

func TestPollReqWithDifferentCredentials(t *testing.T) {
	secret1 := []byte("poll-secret-1")
	secret2 := []byte("poll-secret-2")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{
				Waiting: &server.WaitingResponse{CheckAfter: 1 * time.Second},
			}, nil
		},
	}

	// Server accepts both secrets.
	srv := server.New(handler, server.WithSecretLookup(&multiMACLookup{
		secrets: map[string][]byte{"kid1": secret1, "kid2": secret2},
	}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Send IR with secret1.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER}}},
	}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&msgs), pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "kid1"}),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
	})
	msg.Header.SenderKID = []byte("kid1")
	{
		_mc, _ := pkicmp.NewMACCredentials(secret1)
		_ = _mc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	resp.Body.Close()
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])

	// Send pollReq with secret2 (different credentials) — should be rejected.
	pollReq := pkicmp.PollReqContent{0}
	pollMsg := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&pollReq), pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "kid2"}),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
	})
	pollMsg.Header.TransactionID = msg.Header.TransactionID
	pollMsg.Header.RecipNonce = respMsg.Header.SenderNonce
	pollMsg.Header.SenderKID = []byte("kid2")
	{
		_mc, _ := pkicmp.NewMACCredentials(secret2)
		_ = _mc.Protect(pollMsg)
	}
	pollDER, _ := pollMsg.MarshalBinary()

	resp2, _ := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(pollDER)))
	var buf2 [65536]byte
	n2, _ := resp2.Body.Read(buf2[:])
	resp2.Body.Close()
	pollResp, _ := pkicmp.ParsePKIMessage(buf2[:n2])

	// RFC 9483 §3.2: pollReq MUST use the same credentials — should be rejected.
	// With composite key, different credentials means "no pending certificate".
	assert.Equal(t, pkicmp.BodyTypeError, pollResp.Body.Type)
	errContent, _ := pollResp.Body.Error()
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadRequest)
}

// multiMACLookup supports multiple secrets keyed by senderKID.
type multiMACLookup struct {
	secrets map[string][]byte
}

func (m *multiMACLookup) LookupSecret(_ pkix.Name, senderKID []byte) ([]byte, error) {
	if secret, ok := m.secrets[string(senderKID)]; ok {
		return secret, nil
	}
	return nil, nil
}

// A CA that cannot record a confirmation must not have the client told the
// certificate was confirmed, and the transaction must survive for a retry.
func TestCertConfHandlerErrorIsReported(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("conf-error-secret")

	confirmAttempts := 0
	failConfirm := true
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(_ context.Context, _ *certConfirmation) error {
			confirmAttempts++
			if failConfirm {
				return &server.Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailSystemUnavail,
					StatusText:  "audit store unavailable",
				}
			}
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certReqMsg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "test"}),
				PublicKey: pubDER,
			},
		},
	}
	require.NoError(t, certReqMsg.GeneratePOP(key))
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsg}), macMessageOpts())
	protectMAC(msg, secret)
	ipResp := postCMP(t, ts, msg)
	require.Equal(t, pkicmp.BodyTypeIP, ipResp.Body.Type)

	ip, err := ipResp.Body.IP()
	require.NoError(t, err)
	issued, err := ip.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
	require.NoError(t, err)
	hash := sha256.Sum256(issued.Raw)

	sendCertConf := func() *pkicmp.PKIMessage {
		conf := pkicmp.CertConfirmContent{{CertHash: hash[:], CertReqID: 0}}
		confMsg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&conf), macMessageOpts())
		confMsg.Header.TransactionID = msg.Header.TransactionID
		confMsg.Header.RecipNonce = ipResp.Header.SenderNonce
		protectMAC(confMsg, secret)
		return postCMP(t, ts, confMsg)
	}

	// The CA refused to record it, so the client must not get pkiConf.
	failed := sendCertConf()
	require.Equal(t, pkicmp.BodyTypeError, failed.Body.Type)
	errorContent, err := failed.Body.Error()
	require.NoError(t, err)
	assert.NotZero(t, errorContent.PKIStatusInfo.FailInfo&pkicmp.FailSystemUnavail)
	assert.Equal(t, 1, confirmAttempts)

	// The transaction was kept, so the same certConf succeeds on retry.
	failConfirm = false
	assert.Equal(t, pkicmp.BodyTypePKIConf, sendCertConf().Body.Type)
	assert.Equal(t, 2, confirmAttempts)
}

// An Ed25519-signing CA must complete the certConf round trip. RFC 9481 §3
// pairs EdDSA with SHA-512 for certHash, so client and server have to agree.
func TestCertConfWithEd25519CA(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Ed25519 CA", KeyType: certyaml.KeyTypeEd25519}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	require.Equal(t, x509.PureEd25519, caCert.SignatureAlgorithm)
	secret := []byte("ed25519-conf-secret")

	var confirmed bool
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(_ context.Context, confirm *certConfirmation) error {
			confirmed = true
			assert.NotEmpty(t, confirm.Accepted)
			return nil
		},
	}

	ts := httptest.NewServer(server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret})))
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	_, err = client.NewClient(ts.URL).SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "ed25519-test"}),
		client.WithSender(pkix.Name{CommonName: "ed25519-test"}),
	)
	require.NoError(t, err)
	assert.True(t, confirmed, "certConf must reach the CA")
}

// TestCertConfExplicitHash validates the declared digest before recording confirmation.
func TestCertConfExplicitHash(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Explicit hash CA", KeyType: certyaml.KeyTypeEd25519}
	secret := []byte("explicit-confirmation-secret")
	confirmed := 0
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req)}, nil
		},
		handleCertConfirm: func(_ context.Context, _ *certConfirmation) error { confirmed++; return nil },
	}
	ts := httptest.NewServer(server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret})))
	defer ts.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(pkix.Name{CommonName: "device"}), PublicKey: pub}}}
	require.NoError(t, request.GeneratePOP(key))
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{request}), macMessageOpts())
	protectMAC(msg, secret)
	response := postCMP(t, ts, msg)
	require.Equal(t, pkicmp.BodyTypeIP, response.Body.Type)
	ip, err := response.Body.IP()
	require.NoError(t, err)
	cert, err := ip.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
	require.NoError(t, err)
	digest := sha256.Sum256(cert.Raw)
	for _, test := range []struct {
		hash     []byte
		oid      asn1.ObjectIdentifier
		accepted bool
	}{
		{digest[:], asn1.ObjectIdentifier{1, 2, 3}, false},
		{[]byte("wrong"), asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, false},
		{digest[:], asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, true},
	} {
		conf := pkicmp.CertConfirmContent{{CertReqID: 0, CertHash: test.hash, HashAlg: &pkicmp.AlgorithmIdentifier{Algorithm: test.oid}}}
		confirm := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&conf), macMessageOpts())
		confirm.Header.TransactionID = msg.Header.TransactionID
		confirm.Header.RecipNonce = response.Header.SenderNonce
		protectMAC(confirm, secret)
		result := postCMP(t, ts, confirm)
		if test.accepted {
			require.Equal(t, pkicmp.BodyTypePKIConf, result.Body.Type)
		} else {
			require.Equal(t, pkicmp.BodyTypeError, result.Body.Type)
			require.Zero(t, confirmed)
		}
	}
	require.Equal(t, 1, confirmed)
}
