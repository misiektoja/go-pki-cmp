package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestHTTPMethodRejection(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: []byte("secret")}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, ts.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, "method %s should be rejected", method)
		resp.Body.Close()
	}
}

// TestHTTPContentTypeRejection verifies that unrelated and malformed media types are rejected.
func TestHTTPContentTypeRejection(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: []byte("secret")}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	for _, contentType := range []string{"application/json", "application/pkixcmp; charset"} {
		resp, err := http.Post(ts.URL, contentType, strings.NewReader("{}"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
		resp.Body.Close()
	}
}

// TestHTTPContentTypeVariants verifies that case-insensitive CMP media types with parameters are accepted.
func TestHTTPContentTypeVariants(t *testing.T) {
	secret := []byte("media-type-secret")
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, err := msg.MarshalBinary()
	require.NoError(t, err)

	for _, contentType := range []string{
		"Application/PKIXCMP",
		"application/pkixcmp; charset=binary",
	} {
		resp, err := http.Post(ts.URL, contentType, strings.NewReader(string(msgDER)))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
}

func TestHTTPBadBody(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: []byte("secret")}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader("not-valid-der"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestUnsupportedBodyType(t *testing.T) {
	secret := []byte("unsup-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	unsupMsg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), macMessageOpts())
	protectMAC(unsupMsg, secret)
	unsupDER, _ := unsupMsg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(unsupDER)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, err := pkicmp.ParsePKIMessage(buf[:n])
	require.NoError(t, err)
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, err := respMsg.Body.Error()
	require.NoError(t, err)
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadRequest)
}

func TestUnsupportedVersion(t *testing.T) {
	secret := []byte("ver-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{}), macMessageOpts())
	msg.Header.PVNO = 99
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, err := pkicmp.ParsePKIMessage(buf[:n])
	require.NoError(t, err)
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, err := respMsg.Body.Error()
	require.NoError(t, err)
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailUnsupportedVersion)
}

func TestErrorBodyFromClient(t *testing.T) {
	secret := []byte("error-body-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
		PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection},
	}), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypePKIConf, respMsg.Body.Type)
}

func TestServerErrorString(t *testing.T) {
	e := &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "bad"}
	assert.Contains(t, e.Error(), "rejection")
	assert.Contains(t, e.Error(), "badRequest")
	assert.Contains(t, e.Error(), "bad")

	e2 := &server.Error{Status: pkicmp.StatusRejection}
	assert.Contains(t, e2.Error(), "rejection")
}

func TestRecipientMismatch(t *testing.T) {
	secret := []byte("recip-secret")

	srv := server.New(&mockHandler{},
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithSender(pkix.Name{CommonName: "CMP Server"}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Send a message with a recipient that doesn't match the server's identity.
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), pkicmp.MessageOptions{
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "Wrong Server"}),
	})
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, _ := respMsg.Body.Error()
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadRequest)
}

func TestRecipientNullDN(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("null-dn-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler,
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithSender(pkix.Name{CommonName: "CMP Server"}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// NULL-DN recipient should be accepted (client doesn't know server name).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "null-dn-test"}),
		client.WithSender(pkix.Name{CommonName: "null-dn-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}
