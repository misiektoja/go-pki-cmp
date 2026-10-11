package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

func TestUnprotectedMessage(t *testing.T) {
	secret := []byte("unprot-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, _ := respMsg.Body.Error()
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadMessageCheck)
}

func TestMACNotConfigured(t *testing.T) {
	srv := server.New(&mockHandler{})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestSignatureNotConfigured(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: ca}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	srv := server.New(&mockHandler{})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	{
		_sc, _ := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
		_ = _sc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, _ := respMsg.Body.Error()
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
}

func TestBadMACVerification(t *testing.T) {
	secret := []byte("server-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials([]byte("wrong-secret"))
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "bad-mac-test"}),
		client.WithSender(pkix.Name{CommonName: "bad-mac-test"}),
	)
	require.Error(t, err)
}

func TestSignatureVerificationWithBadSigner(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Trusted CA"}

	untrustedCA := &certyaml.Certificate{Subject: "CN=Untrusted CA"}
	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: untrustedCA}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	srv := server.New(&mockHandler{}, server.WithCertificateLookup(&failingCertLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	{
		_sc, _ := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
		_ = _sc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	_ = ca
}

func TestMACLookupReturnsEmptySecret(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&emptySecretLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestMACLookupReturnsError(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&failingLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestPBMAC1Protection(t *testing.T) {
	secret := []byte("pbmac1-secret")

	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req)}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds := &pbmac1Creds{secret: secret}

	c := client.NewClient(ts.URL)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "pbmac1-test"}),
		client.WithSender(pkix.Name{CommonName: "pbmac1-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "CN=pbmac1-test", result.Certificate.Subject.String())
}

// pbmac1Creds explicitly uses PBMAC1 protection for testing.
// PBMAC1 is now the default, so this just wraps NewMACCredentials.
type pbmac1Creds struct {
	secret []byte
}

func (c *pbmac1Creds) Protect(msg *pkicmp.PKIMessage) error {
	mc, err := pkicmp.NewMACCredentials(c.secret)
	if err != nil {
		return err
	}
	return mc.Protect(msg)
}

func (c *pbmac1Creds) SharedSecret() []byte {
	return c.secret
}

// A signer key that does not match its certificate must be reported and must not
// leave the server issuing certificates it cannot protect.
func TestSignerMismatchIsRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("signer-mismatch-secret")

	issued := 0
	handler := &mockHandler{handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
		issued++
		return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
	}}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := server.New(handler,
		server.WithSigner(otherKey, &caCert),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	)
	require.Error(t, srv.Err(), "New must report the mismatched signer")

	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	message := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "signer-mismatch")}),
		macMessageOpts(),
	)
	protectMAC(message, secret)
	response := postCMP(t, ts, message)

	require.Equal(t, pkicmp.BodyTypeError, response.Body.Type)
	errorContent, err := response.Body.Error()
	require.NoError(t, err)
	assert.NotZero(t, errorContent.PKIStatusInfo.FailInfo&pkicmp.FailSystemFailure)
	assert.Zero(t, issued, "no certificate may be issued while protection is broken")
}

// An error raised after a shared secret authenticated the request must be
// MAC-protected, so a client with no trust anchor can still verify it
// (RFC 9483 §3.1).
func TestErrorResponseToMACClientUsesMAC(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("mac-error-secret")

	handler := &mockHandler{handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
		return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
	}}
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	ts := httptest.NewServer(server.New(handler,
		server.WithSigner(caKey, &caCert),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	))
	defer ts.Close()

	newIR := func(transactionID []byte) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		options := macMessageOpts()
		options.TransactionID = transactionID
		message := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "mac-error")}),
			options,
		)
		protectMAC(message, secret)
		return message
	}

	transactionID := []byte("0123456789abcdef")
	require.Equal(t, pkicmp.BodyTypeIP, postCMP(t, ts, newIR(transactionID)).Body.Type)

	// Reusing the transactionID is rejected only after the MAC verified.
	response := postCMP(t, ts, newIR(transactionID))
	require.Equal(t, pkicmp.BodyTypeError, response.Body.Type)
	_, err = response.Verify(pkicmp.VerifyOptions{
		SharedSecret:       secret,
		RequiredProtection: pkicmp.ProtectionMAC,
	})
	assert.NoError(t, err, "a MAC client must be able to verify the rejection")
}

// A Handler error that is not a *server.Error must not put its text on the wire,
// and a wrapped *server.Error must keep the status the Handler chose.
func TestHandlerErrorTextIsNotDisclosed(t *testing.T) {
	secret := []byte("error-text-secret")

	tests := []struct {
		name         string
		err          error
		wantFailInfo pkicmp.PKIFailureInfo
		wantText     string
	}{
		{
			name:         "wrapped server error keeps its status",
			err:          fmt.Errorf("issuing from postgres://ca:pw@db/ca: %w", &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not authorized"}),
			wantFailInfo: pkicmp.FailNotAuthorized,
			wantText:     "not authorized",
		},
		{
			name:         "plain error discloses nothing",
			err:          errors.New("dial postgres://ca:pw@10.0.0.5/ca: connection refused"),
			wantFailInfo: pkicmp.FailSystemFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &mockHandler{handleCertRequest: func(_ context.Context, _ *certRequest) (*certResponse, error) {
				return nil, test.err
			}}
			ts := httptest.NewServer(server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret})))
			defer ts.Close()

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			message := pkicmp.NewPKIMessage(
				pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "error-text")}),
				macMessageOpts(),
			)
			protectMAC(message, secret)

			status := statusInfoOf(t, postCMP(t, ts, message))
			assert.NotZero(t, status.FailInfo&test.wantFailInfo)
			joined := strings.Join(status.StatusString, " ")
			assert.NotContains(t, joined, "postgres://")
			if test.wantText != "" {
				assert.Contains(t, joined, test.wantText)
			} else {
				assert.Empty(t, joined)
			}
		})
	}
}
