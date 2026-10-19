package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
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
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// slhdsaDeviceCA is a deviceCA that certifies SLH-DSA keys, which crypto/x509 cannot encode.
type slhdsaDeviceCA struct {
	*deviceCA
}

// IssueCertificate certifies the requested SLH-DSA key for signing.
func (c *slhdsaDeviceCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	spki, err := pkicmp.MarshalPublicKey(tmpl.PublicKey)
	if err != nil {
		return nil, err
	}
	der, err := kemcert.CreateCertificate(tmpl, c.cert, spki, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issued = append(c.issued, cert)
	return &server.Response{Certificate: cert, CACerts: []*x509.Certificate{c.cert}}, nil
}

// serve starts a CA server that authenticates MAC requests with secret and signs responses with the CA key.
func (c *slhdsaDeviceCA) serve(t *testing.T, secret []byte) *httptest.Server {
	t.Helper()
	srv := server.NewCAServer(c, server.LightweightPolicy(),
		server.WithSigner(c.key, c.cert),
		server.WithCertificateLookup(c),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// newSLHDSAKey generates an SLH-DSA key of parameter set id.
func newSLHDSAKey(t *testing.T, id slhdsa.ID) slhdsa.PrivateKey {
	t.Helper()
	_, key, err := slhdsa.GenerateKey(rand.Reader, id)
	require.NoError(t, err)
	return key
}

// slhdsaCSR returns a PKCS #10 request for subject signed by key.
func slhdsaCSR(t *testing.T, key slhdsa.PrivateKey, subject string) []byte {
	t.Helper()
	spki, err := pkicmp.MarshalPublicKey(key.Public())
	require.NoError(t, err)
	oid, ok := pkicmp.SLHDSAAlgorithmOID(key.ID)
	require.True(t, ok)
	der, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, spki, oid, key)
	require.NoError(t, err)
	return der
}

// requireCertifiesSLHDSA checks that cert certifies key and chains to ca.
func requireCertifiesSLHDSA(t *testing.T, cert *x509.Certificate, key slhdsa.PrivateKey, ca *x509.Certificate) {
	t.Helper()
	pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.True(t, pkicmp.PublicKeysEqual(pub, key.Public()))
	require.NoError(t, cert.CheckSignatureFrom(ca))
}

// TestSLHDSADeviceKeyEnrollment runs every request type with SLH-DSA device
// keys under classical and pure ML-DSA CAs.
func TestSLHDSADeviceKeyEnrollment(t *testing.T) {
	secret := []byte("slh-dsa-device-secret")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	for name, caKey := range map[string]crypto.Signer{"ECDSA CA": ecKey, "ML-DSA CA": mldsaKey} {
		t.Run(name, func(t *testing.T) {
			ca := &slhdsaDeviceCA{newDeviceCA(t, caKey)}
			ts := ca.serve(t, secret)
			c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert)))
			macCreds, err := pkicmp.NewMACCredentials(secret)
			require.NoError(t, err)
			ctx := context.Background()

			deviceKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
			device := pkix.Name{CommonName: "slh-dsa-device"}
			ir, err := c.SendIR(ctx, deviceKey, macCreds, client.WithTemplateSubject(device), client.WithSender(device))
			require.NoError(t, err)
			requireCertifiesSLHDSA(t, ir.Certificate, deviceKey, ca.cert)

			csrKey := newSLHDSAKey(t, slhdsa.SHAKE_128f)
			p10cr, err := c.SendP10CR(ctx, slhdsaCSR(t, csrKey, "slh-dsa-p10cr"), macCreds, client.WithSender(pkix.Name{CommonName: "slh-dsa-p10cr"}))
			require.NoError(t, err)
			require.Equal(t, "slh-dsa-p10cr", p10cr.Certificate.Subject.CommonName)
			requireCertifiesSLHDSA(t, p10cr.Certificate, csrKey, ca.cert)

			deviceCreds, err := pkicmp.NewSignatureCredentials(deviceKey, ir.Certificate, ca.cert)
			require.NoError(t, err)
			crKey := newSLHDSAKey(t, slhdsa.SHA2_192f)
			cr, err := c.SendCR(ctx, crKey, deviceCreds, client.WithTemplateSubject(pkix.Name{CommonName: "slh-dsa-device-cr"}), client.WithSender(device))
			require.NoError(t, err)
			requireCertifiesSLHDSA(t, cr.Certificate, crKey, ca.cert)

			newKey := newSLHDSAKey(t, slhdsa.SHAKE_256f)
			kur, err := c.SendKUR(ctx, newKey, deviceCreds, client.WithTemplateSubject(device), client.WithSender(device))
			require.NoError(t, err)
			requireCertifiesSLHDSA(t, kur.Certificate, newKey, ca.cert)
			require.Len(t, ca.confirmed, 4)

			crCreds, err := pkicmp.NewSignatureCredentials(crKey, cr.Certificate, ca.cert)
			require.NoError(t, err)
			require.NoError(t, c.SendRR(ctx, cr.Certificate, pkicmp.CRLReasonKeyCompromise, crCreds, client.WithSender(cr.Certificate.Subject)))
			require.Equal(t, pkicmp.CRLReasonKeyCompromise, ca.revoked[cr.Certificate.SerialNumber.String()])
		})
	}
}

// TestSLHDSADeviceKeyRejections refuses SLH-DSA requests that do not prove possession of the requested key.
func TestSLHDSADeviceKeyRejections(t *testing.T) {
	secret := []byte("slh-dsa-device-secret")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &slhdsaDeviceCA{newDeviceCA(t, caKey)}
	ts := ca.serve(t, secret)
	key := newSLHDSAKey(t, slhdsa.SHA2_128f)

	t.Run("POP by another key", func(t *testing.T) {
		pubDER, err := pkicmp.MarshalPublicKey(key.Public())
		require.NoError(t, err)
		reqMsg := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
			Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "slh-dsa-device"}),
			PublicKey: pubDER,
		}}}
		require.NoError(t, reqMsg.GeneratePOP(newSLHDSAKey(t, slhdsa.SHA2_128f)))
		req := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{reqMsg}), macMessageOpts())
		protectMAC(req, secret)
		status := statusInfoOf(t, postCMP(t, ts, req))
		require.Equal(t, pkicmp.FailBadPOP, status.FailInfo)
	})

	t.Run("tampered PKCS#10 signature", func(t *testing.T) {
		der := slhdsaCSR(t, key, "slh-dsa-p10cr")
		der[len(der)-1] ^= 1
		tampered, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		req := pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(tampered), macMessageOpts())
		protectMAC(req, secret)
		status := statusInfoOf(t, postCMP(t, ts, req))
		require.Equal(t, pkicmp.FailBadPOP, status.FailInfo)
	})
}
