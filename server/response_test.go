package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

func TestWithExtraCertsAndSenderOptions(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("opts-secret")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(handler,
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithExtraCerts([]*x509.Certificate{&caCert}),
		server.WithSender(pkix.Name{CommonName: "CMP Server"}),
		server.WithConfirmWaitTime(30*time.Second),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "opts-test"}),
		client.WithSender(pkix.Name{CommonName: "opts-test"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.NotEmpty(t, result.ExtraCertificates)
}
