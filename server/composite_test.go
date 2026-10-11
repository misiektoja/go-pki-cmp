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

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// compositeCA is a certificate authority with a composite ML-DSA key.
type compositeCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newCompositeCA creates a self-signed composite ML-DSA CA.
func newCompositeCA(t *testing.T, alg compositemldsa.Algorithm) *compositeCA {
	t.Helper()
	key, err := compositemldsa.GenerateKey(alg)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Composite CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &compositeCA{cert: cert, key: key}
}

// issue certifies pub for subject with a digitalSignature certificate.
func (ca *compositeCA) issue(t *testing.T, subject pkix.Name, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// compositeIssuingHandler issues from ca and records the confirmed certReqIds.
func compositeIssuingHandler(t *testing.T, ca *compositeCA, accepted *[]int64) *mockHandler {
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

// TestEnrollmentWithCompositeCA runs IR, certConf and pkiConf against a CA
// whose composite ML-DSA key signs the issued certificate and, in some cases,
// the CMP responses.
func TestEnrollmentWithCompositeCA(t *testing.T) {
	for _, alg := range []compositemldsa.Algorithm{compositemldsa.MLDSA44ECDSAP256SHA256, compositemldsa.MLDSA65ECDSAP256SHA512} {
		t.Run(alg.String(), func(t *testing.T) {
			ca := newCompositeCA(t, alg)
			clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			clientCert := ca.issue(t, pkix.Name{CommonName: "Client"}, clientKey.Public())
			raKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			raCert := ca.issue(t, pkix.Name{CommonName: "CMP RA"}, raKey.Public())

			signers := map[string]server.Option{
				"CA signs responses":           server.WithSigner(ca.key, ca.cert),
				"classical RA signs responses": server.WithSigner(raKey, raCert, ca.cert),
			}
			for name, signer := range signers {
				t.Run(name, func(t *testing.T) {
					var accepted []int64
					srv := server.New(compositeIssuingHandler(t, ca, &accepted), signer,
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
						client.WithTemplateSubject(pkix.Name{CommonName: "composite-device"}),
						client.WithSender(clientCert.Subject),
					)
					require.NoError(t, err)
					require.Equal(t, "composite-device", result.Certificate.Subject.CommonName)
					require.NoError(t, compositex509.CheckSignatureFrom(result.Certificate, ca.cert))
					require.Equal(t, []int64{0}, accepted)
				})
			}

			t.Run("MAC with caPubs", func(t *testing.T) {
				secret := []byte("composite-secret")
				var accepted []int64
				srv := server.New(compositeIssuingHandler(t, ca, &accepted), server.WithSecretLookup(&staticMACLookup{secret: secret}))
				ts := httptest.NewServer(srv)
				defer ts.Close()

				creds, err := pkicmp.NewMACCredentials(secret)
				require.NoError(t, err)
				newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				result, err := client.NewClient(ts.URL).SendIR(context.Background(), newKey, creds,
					client.WithTemplateSubject(pkix.Name{CommonName: "composite-device"}),
					client.WithSender(pkix.Name{CommonName: "composite-device"}),
				)
				require.NoError(t, err)
				require.Len(t, result.CAPubs, 1)
				require.True(t, result.CAPubs[0].Equal(ca.cert))
				require.Equal(t, []int64{0}, accepted)
			})
		})
	}
}

// TestEnrollmentRejectsUntrustedCompositeCA makes the client reject a
// certificate from a composite CA it does not trust.
func TestEnrollmentRejectsUntrustedCompositeCA(t *testing.T) {
	ca := newCompositeCA(t, compositemldsa.MLDSA44ECDSAP256SHA256)
	trusted := newCompositeCA(t, compositemldsa.MLDSA44ECDSAP256SHA256)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientCert := trusted.issue(t, pkix.Name{CommonName: "Client"}, clientKey.Public())

	var accepted []int64
	srv := server.New(compositeIssuingHandler(t, ca, &accepted),
		server.WithSigner(trusted.key, trusted.cert),
		server.WithCertificateLookup(&staticCertLookup{cert: clientCert}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	creds, err := pkicmp.NewSignatureCredentials(clientKey, clientCert, trusted.cert)
	require.NoError(t, err)
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(trusted.cert)))
	_, err = c.SendIR(context.Background(), newKey, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "composite-device"}),
		client.WithSender(clientCert.Subject),
	)
	require.ErrorContains(t, err, "verify certificate trust")
	require.Empty(t, accepted)
}

// x509pool returns a certificate pool holding certs.
func x509pool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
