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

// Tests for LightweightPolicy middleware (RFC 9483 compliance).

func TestKURWithMACRejected(t *testing.T) {
	secret := []byte("kur-secret")

	srv := server.New(server.LightweightPolicy()(&mockHandler{}), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials(secret)
	c := client.NewClient(ts.URL)

	// RFC 9483 §4.1.3: KUR MUST be signature-protected.
	_, err := c.SendKUR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "kur-test"}),
		client.WithSender(pkix.Name{CommonName: "kur-test"}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrongIntegrity")
}

func TestRAVerifiedPOPRejected(t *testing.T) {
	secret := []byte("ra-verified")

	srv := server.New(server.LightweightPolicy()(&mockHandler{}), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{
			CertReq: pkicmp.CertRequest{
				CertReqID:    0,
				CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER},
			},
			Popo: pkicmp.NewRAVerifiedPOP(),
		},
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
	// RFC 9810 §5.2.8.1: raVerified not allowed for end entities.
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.NotZero(t, rep.Response[0].Status.FailInfo&pkicmp.FailNotAuthorized)
}

func TestMissingPOPRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("no-pop")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(server.LightweightPolicy()(handler), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{
			CertReq: pkicmp.CertRequest{
				CertReqID: 0,
				CertTemplate: pkicmp.CertTemplate{
					Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "no-pop-test"}),
					PublicKey: pubDER,
				},
			},
		},
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
	// RFC 9483 §5.1.1: POP is required unless central key generation is requested.
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
}

func TestKeyEnciphermentPOPRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("ke-pop")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(server.LightweightPolicy()(handler), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	subMsg := int64(1)
	msgs := pkicmp.CertReqMessages{
		{
			CertReq: pkicmp.CertRequest{
				CertReqID: 0,
				CertTemplate: pkicmp.CertTemplate{
					Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "ke-pop-test"}),
					PublicKey: pubDER,
				},
			},
			Popo: pkicmp.NewKeyEnciphermentPOP(&subMsg),
		},
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
	// RFC 9483 §5.1.1: Signature POP is required for signature-capable keys (ECDSA).
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
}

func TestMissingSubjectRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, _ := ca.X509Certificate()
	secret := []byte("no-subj")

	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			cert := issueCert(ca, req)
			return &certResponse{Certificate: cert, CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}

	srv := server.New(server.LightweightPolicy()(handler), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	msgs := pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{
			CertReqID:    0,
			CertTemplate: pkicmp.CertTemplate{PublicKey: pubDER},
		}},
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
	// RFC 9483 §4.1.1: Subject is required in certTemplate.
	assert.Equal(t, pkicmp.BodyTypeIP, respMsg.Body.Type)
	rep, _ := respMsg.Body.IP()
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
}
