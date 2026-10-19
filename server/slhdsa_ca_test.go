package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// slhdsaCA is a certificate authority with an SLH-DSA key.
type slhdsaCA struct {
	cert *x509.Certificate
	key  slhdsa.PrivateKey
}

// newSLHDSACA creates a self-signed SLH-DSA CA of parameter set id.
func newSLHDSACA(t *testing.T, id slhdsa.ID) *slhdsaCA {
	t.Helper()
	key := newSLHDSAKey(t, id)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SLH-DSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte("SLH-DSA CA"),
	}
	ca := &slhdsaCA{key: key}
	ca.cert = ca.sign(t, tmpl, tmpl, key.Public())
	return ca
}

// sign creates a certificate for pub from tmpl, signed with the CA key under parent.
func (ca *slhdsaCA) sign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(pub)
	require.NoError(t, err)
	oid, ok := pkicmp.SLHDSAAlgorithmOID(ca.key.ID)
	require.True(t, ok)
	der, err := kemcert.CreateSLHDSACertificate(tmpl, parent, spki, oid, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// issue certifies pub for subject with a digitalSignature certificate.
func (ca *slhdsaCA) issue(t *testing.T, subject pkix.Name, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	return ca.sign(t, &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, ca.cert, pub)
}

// TestEnrollmentWithSLHDSACA runs IR, certConf and pkiConf against a CA whose
// SLH-DSA key signs the issued certificate and, in some cases, the CMP responses.
func TestEnrollmentWithSLHDSACA(t *testing.T) {
	ca := newSLHDSACA(t, slhdsa.SHA2_128f)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientCert := ca.issue(t, pkix.Name{CommonName: "Client"}, clientKey.Public())
	raKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	raCert := ca.issue(t, pkix.Name{CommonName: "CMP RA"}, raKey.Public())

	handler := func(accepted *[]int64) *mockHandler {
		return &mockHandler{
			handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
				return &certResponse{Certificate: ca.issue(t, req.Subject, req.PublicKey), CACerts: []*x509.Certificate{ca.cert}}, nil
			},
			handleCertConfirm: func(ctx context.Context, confirm *certConfirmation) error {
				*accepted = append(*accepted, confirm.Accepted...)
				return nil
			},
		}
	}
	signers := map[string]server.Option{
		"CA signs responses":           server.WithSigner(ca.key, ca.cert),
		"classical RA signs responses": server.WithSigner(raKey, raCert, ca.cert),
	}
	for name, signer := range signers {
		t.Run(name, func(t *testing.T) {
			var accepted []int64
			srv := server.New(handler(&accepted), signer,
				server.WithCertificateLookup(&staticCertLookup{cert: clientCert}),
				server.WithStrictProfileValidation(),
			)
			ts := httptest.NewServer(srv)
			defer ts.Close()

			creds, err := pkicmp.NewSignatureCredentials(clientKey, clientCert, ca.cert)
			require.NoError(t, err)
			newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert)))
			result, err := c.SendIR(context.Background(), newKey, creds,
				client.WithTemplateSubject(pkix.Name{CommonName: "slh-dsa-device"}),
				client.WithSender(clientCert.Subject),
			)
			require.NoError(t, err)
			require.Equal(t, "slh-dsa-device", result.Certificate.Subject.CommonName)
			require.NoError(t, slhdsasig.CheckSignatureFrom(result.Certificate, ca.cert))
			require.Equal(t, []int64{0}, accepted)
		})
	}

	t.Run("untrusted CA", func(t *testing.T) {
		other := newSLHDSACA(t, slhdsa.SHA2_128f)
		var accepted []int64
		srv := server.New(handler(&accepted),
			server.WithSigner(ca.key, ca.cert),
			server.WithCertificateLookup(&staticCertLookup{cert: clientCert}),
		)
		ts := httptest.NewServer(srv)
		defer ts.Close()

		creds, err := pkicmp.NewSignatureCredentials(clientKey, clientCert, ca.cert)
		require.NoError(t, err)
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(other.cert)))
		_, err = c.SendIR(context.Background(), newKey, creds,
			client.WithTemplateSubject(pkix.Name{CommonName: "slh-dsa-device"}),
			client.WithSender(clientCert.Subject),
		)
		require.Error(t, err)
		require.Empty(t, accepted)
	})
}
