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

func TestIRWithMAC(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("test-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			assert.Equal(t, requestIR, req.Type)
			assert.Equal(t, "test-device", req.Subject.CommonName)
			cert := issueCert(ca, req)
			return &certResponse{
				Certificate: cert,
				CACerts:     []*x509.Certificate{&caCert},
			}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)

	c := client.NewClient(ts.URL)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "test-device"}),
		client.WithSender(pkix.Name{CommonName: "test-device"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "test-device", result.Certificate.Subject.CommonName)
	require.Len(t, result.CAPubs, 1)
}

func TestIRWithSignature(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	caKey, _ := ca.PrivateKey()

	signerCert := &certyaml.Certificate{Subject: "CN=CMP Signer", Issuer: ca}
	signerX509, _ := signerCert.X509Certificate()
	signerKey, _ := signerCert.PrivateKey()

	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: ca}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(&caCert)

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			assert.Equal(t, requestIR, req.Type)
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler,
		server.WithSigner(signerKey, &signerX509),
		server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewSignatureCredentials(clientKey, &clientX509, &caCert)
	require.NoError(t, err)

	c := client.NewClient(ts.URL, client.WithTrustedCAs(trustedCAs), client.WithExtraCerts([]*x509.Certificate{&clientX509}))
	result, err := c.SendIR(context.Background(), newKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "sig-test"}),
		client.WithSender(clientX509.Subject),
	)
	require.NoError(t, err)
	assert.Equal(t, "sig-test", result.Certificate.Subject.CommonName)
	_ = caKey
}

func TestCRWithMAC(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("cr-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			assert.Equal(t, requestCR, req.Type)
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendCR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "cr-test"}),
		client.WithSender(pkix.Name{CommonName: "cr-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "cr-test", result.Certificate.Subject.CommonName)
}

func TestP10CRWithMAC(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("p10-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			assert.Equal(t, requestP10CR, req.Type)
			assert.Equal(t, "p10-test", req.Subject.CommonName)
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "p10-test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)

	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendP10CR(context.Background(), csrDER, creds,
		client.WithSender(pkix.Name{CommonName: "p10-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "p10-test", result.Certificate.Subject.CommonName)
}

func TestHandlerError(t *testing.T) {
	secret := []byte("err-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return nil, &server.Error{
				Status:      pkicmp.StatusRejection,
				FailureInfo: pkicmp.FailBadRequest,
				StatusText:  "request denied",
			}
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "err-test"}),
		client.WithSender(pkix.Name{CommonName: "err-test"}),
	)
	require.Error(t, err)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailBadRequest))
}

func TestHandlerReturnsGenericError(t *testing.T) {
	secret := []byte("generic-err")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return nil, assert.AnError
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "test"}),
		client.WithSender(pkix.Name{CommonName: "test"}),
	)
	require.Error(t, err)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailSystemFailure))
}

func TestIRWithEmptyCRMF(t *testing.T) {
	secret := []byte("empty-crmf")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	emptyMsgs := pkicmp.CertReqMessages{}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&emptyMsgs), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
}

func TestIRWithMultipleCRMF(t *testing.T) {
	secret := []byte("multi-crmf")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER}}},
		{CertReq: pkicmp.CertRequest{CertReqID: 1, CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER}}},
	}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&msgs), macMessageOpts())
	protectMAC(msg, secret)
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
}

func TestIRWithExtensions(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("ext-secret")

	var gotExtensions bool
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			if len(req.Extensions) > 0 {
				gotExtensions = true
			}
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	ext := pkix.Extension{
		Id:    []int{2, 5, 29, 17},
		Value: []byte{0x30, 0x00},
	}
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "ext-test"}),
		client.WithTemplateExtension(ext),
		client.WithSender(pkix.Name{CommonName: "ext-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.True(t, gotExtensions)
}

func TestIRWithSignatureAndSenderKID(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	caKey, _ := ca.PrivateKey()

	signerCert := &certyaml.Certificate{Subject: "CN=CMP Signer", Issuer: ca}
	signerX509, _ := signerCert.X509Certificate()
	signerKey, _ := signerCert.PrivateKey()

	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: ca}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(&caCert)

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			assert.NotNil(t, req.Sender)
			assert.NotNil(t, req.Sender.Certificate)
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler,
		server.WithSigner(signerKey, &signerX509),
		server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewSignatureCredentials(clientKey, &clientX509, &caCert)

	c := client.NewClient(ts.URL, client.WithTrustedCAs(trustedCAs), client.WithExtraCerts([]*x509.Certificate{&clientX509}))
	result, err := c.SendIR(context.Background(), newKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "sig-kid-test"}),
		client.WithSender(clientX509.Subject),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	_ = caKey
}

func TestIRWithRSAKey(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=RSA CA", KeyType: certyaml.KeyTypeRSA}
	caCert, _ := ca.X509Certificate()
	secret := []byte("rsa-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
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
		client.WithTemplateSubject(pkix.Name{CommonName: "rsa-test"}),
		client.WithSender(pkix.Name{CommonName: "rsa-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestIRWithP384Key(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=P384 CA", KeyType: certyaml.KeyTypeEC, KeySize: 384}
	caCert, _ := ca.X509Certificate()
	secret := []byte("p384-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "p384-test"}),
		client.WithSender(pkix.Name{CommonName: "p384-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestIRWithP521Key(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=P521 CA", KeyType: certyaml.KeyTypeEC, KeySize: 521}
	caCert, _ := ca.X509Certificate()
	secret := []byte("p521-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "p521-test"}),
		client.WithSender(pkix.Name{CommonName: "p521-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestIRWithRSA384Key(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=RSA384 CA", KeyType: certyaml.KeyTypeRSA, KeySize: 3072}
	caCert, _ := ca.X509Certificate()
	secret := []byte("rsa384-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enrollKey := &certyaml.Certificate{Subject: "CN=enroll", KeyType: certyaml.KeyTypeRSA, KeySize: 3072}
	enrollPriv, _ := enrollKey.PrivateKey()

	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), enrollPriv, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "rsa384-test"}),
		client.WithSender(pkix.Name{CommonName: "rsa384-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestIRWithRSA4096Key(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=RSA512 CA", KeyType: certyaml.KeyTypeRSA, KeySize: 4096}
	caCert, _ := ca.X509Certificate()
	secret := []byte("rsa512-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enrollKey := &certyaml.Certificate{Subject: "CN=enroll", KeyType: certyaml.KeyTypeRSA, KeySize: 4096}
	enrollPriv, _ := enrollKey.PrivateKey()

	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), enrollPriv, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "rsa512-test"}),
		client.WithSender(pkix.Name{CommonName: "rsa512-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestIRWithEd25519Key(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=EC CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("ed25519-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enrollKey := &certyaml.Certificate{Subject: "CN=enroll", KeyType: certyaml.KeyTypeEd25519}
	enrollPriv, _ := enrollKey.PrivateKey()

	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), enrollPriv, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "ed25519-test"}),
		client.WithSender(pkix.Name{CommonName: "ed25519-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}
