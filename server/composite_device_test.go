package server_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/client"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// deviceCA issues, looks up and revokes certificates for any requested key.
type deviceCA struct {
	cert *x509.Certificate
	key  crypto.Signer

	mu        sync.Mutex
	issued    []*x509.Certificate
	confirmed []*x509.Certificate
	revoked   map[string]pkicmp.CRLReason
}

// newDeviceCA creates a self-signed CA whose key is key.
func newDeviceCA(t *testing.T, key crypto.Signer) *deviceCA {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Device CA"},
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
	return &deviceCA{cert: cert, key: key, revoked: map[string]pkicmp.CRLReason{}}
}

// IssueCertificate certifies the requested key, which may be a composite ML-DSA key.
func (c *deviceCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
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

// ConfirmCertificate records accepted certificates.
func (c *deviceCA) ConfirmCertificate(_ context.Context, cert *x509.Certificate, status server.ConfirmStatus, _ any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if status == server.ConfirmAccepted {
		c.confirmed = append(c.confirmed, cert)
	}
	return nil
}

// LookupCertificate returns the certificate issued for subject whose subject key identifier is senderKID.
func (c *deviceCA) LookupCertificate(_ pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cert := range c.issued {
		if cert.Subject.String() == subject.String() && bytes.Equal(cert.SubjectKeyId, senderKID) {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// RevokeCertificate revokes a certificate this CA issued after matching every hint in req.
func (c *deviceCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var cert *x509.Certificate
	for _, issued := range c.issued {
		if issued.SerialNumber.Cmp(req.SerialNumber) == 0 {
			cert = issued
		}
	}
	if err := req.Match(cert); err != nil {
		return err
	}
	c.revoked[cert.SerialNumber.String()] = req.Reason
	return nil
}

// serve starts a CA server that authenticates MAC requests with secret and signs responses with the CA key.
func (c *deviceCA) serve(t *testing.T, secret []byte) *httptest.Server {
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

// requireCertifies checks that cert certifies key and chains to ca.
func requireCertifies(t *testing.T, cert *x509.Certificate, key *compositemldsa.PrivateKey, ca *x509.Certificate) {
	t.Helper()
	pub, err := compositex509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.True(t, key.PublicKey().Equal(pub))
	require.NoError(t, compositex509.CheckSignatureFrom(cert, ca))
}

// compositeCSR returns a PKCS#10 request for subject signed by key.
func compositeCSR(t *testing.T, key crypto.Signer, subject string) []byte {
	t.Helper()
	der, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
	require.NoError(t, err)
	return der
}

// deviceCAKeys returns a classical, a pure ML-DSA and a composite CA key.
func deviceCAKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	compositeKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	require.NoError(t, err)
	return map[string]crypto.Signer{"ECDSA CA": ecKey, "ML-DSA CA": mldsaKey, "composite CA": compositeKey}
}

// TestCompositeDeviceKeyEnrollment runs every request type with composite
// ML-DSA device keys under classical, pure ML-DSA and composite CAs.
func TestCompositeDeviceKeyEnrollment(t *testing.T) {
	secret := []byte("composite-device-secret")
	for name, caKey := range deviceCAKeys(t) {
		t.Run(name, func(t *testing.T) {
			ca := newDeviceCA(t, caKey)
			ts := ca.serve(t, secret)
			c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert)))
			macCreds, err := pkicmp.NewMACCredentials(secret)
			require.NoError(t, err)
			ctx := context.Background()

			deviceKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
			require.NoError(t, err)
			device := pkix.Name{CommonName: "composite-device"}
			ir, err := c.SendIR(ctx, deviceKey, macCreds, client.WithTemplateSubject(device), client.WithSender(device))
			require.NoError(t, err)
			requireCertifies(t, ir.Certificate, deviceKey, ca.cert)

			csrKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44Ed25519SHA512)
			require.NoError(t, err)
			p10cr, err := c.SendP10CR(ctx, compositeCSR(t, csrKey, "composite-p10cr"), macCreds, client.WithSender(pkix.Name{CommonName: "composite-p10cr"}))
			require.NoError(t, err)
			require.Equal(t, "composite-p10cr", p10cr.Certificate.Subject.CommonName)
			requireCertifies(t, p10cr.Certificate, csrKey, ca.cert)

			deviceCreds, err := pkicmp.NewSignatureCredentials(deviceKey, ir.Certificate, ca.cert)
			require.NoError(t, err)
			crKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA87ECDSAP384SHA512)
			require.NoError(t, err)
			cr, err := c.SendCR(ctx, crKey, deviceCreds, client.WithTemplateSubject(pkix.Name{CommonName: "composite-device-cr"}), client.WithSender(device))
			require.NoError(t, err)
			requireCertifies(t, cr.Certificate, crKey, ca.cert)

			newKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
			require.NoError(t, err)
			kur, err := c.SendKUR(ctx, newKey, deviceCreds, client.WithTemplateSubject(device), client.WithSender(device))
			require.NoError(t, err)
			requireCertifies(t, kur.Certificate, newKey, ca.cert)
			require.Len(t, ca.confirmed, 4)

			crCreds, err := pkicmp.NewSignatureCredentials(crKey, cr.Certificate, ca.cert)
			require.NoError(t, err)
			require.NoError(t, c.SendRR(ctx, cr.Certificate, pkicmp.CRLReasonKeyCompromise, crCreds, client.WithSender(cr.Certificate.Subject)))
			require.Equal(t, pkicmp.CRLReasonKeyCompromise, ca.revoked[cr.Certificate.SerialNumber.String()])
		})
	}
}

// TestCompositeDeviceKeyAlgorithms enrolls one composite device key of each
// pre-hash and traditional component family.
func TestCompositeDeviceKeyAlgorithms(t *testing.T) {
	secret := []byte("composite-device-secret")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := newDeviceCA(t, caKey)
	ts := ca.serve(t, secret)
	macCreds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	for _, alg := range []compositemldsa.Algorithm{
		compositemldsa.MLDSA44RSA2048PSSSHA256,
		compositemldsa.MLDSA65RSA3072PKCS15SHA512,
		compositemldsa.MLDSA65Ed25519SHA512,
		compositemldsa.MLDSA87ECDSAP521SHA512,
	} {
		t.Run(alg.String(), func(t *testing.T) {
			key, err := compositemldsa.GenerateKey(alg)
			require.NoError(t, err)
			subject := pkix.Name{CommonName: "composite-" + alg.String()}
			result, err := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert))).
				SendIR(context.Background(), key, macCreds, client.WithTemplateSubject(subject), client.WithSender(subject))
			require.NoError(t, err)
			requireCertifies(t, result.Certificate, key, ca.cert)
		})
	}
}

// TestCompositeDeviceKeyRejections refuses composite requests that do not
// prove possession or name another key.
func TestCompositeDeviceKeyRejections(t *testing.T) {
	secret := []byte("composite-device-secret")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := newDeviceCA(t, caKey)
	ts := ca.serve(t, secret)
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	other, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)

	t.Run("POP by another key", func(t *testing.T) {
		pubDER, err := compositex509.MarshalPKIXPublicKey(key.Public())
		require.NoError(t, err)
		reqMsg := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
			Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "composite-device"}),
			PublicKey: pubDER,
		}}}
		require.NoError(t, reqMsg.GeneratePOP(other))
		req := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{reqMsg}), macMessageOpts())
		protectMAC(req, secret)
		status := statusInfoOf(t, postCMP(t, ts, req))
		require.Equal(t, pkicmp.FailBadPOP, status.FailInfo)
	})

	t.Run("tampered PKCS#10 signature", func(t *testing.T) {
		der := compositeCSR(t, key, "composite-p10cr")
		// The signature BIT STRING ends the request, so this flips a bit of the traditional signature.
		der[len(der)-1] ^= 1
		tampered, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		req := pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(tampered), macMessageOpts())
		protectMAC(req, secret)
		status := statusInfoOf(t, postCMP(t, ts, req))
		require.Equal(t, pkicmp.FailBadPOP, status.FailInfo)
	})

	t.Run("revocation naming another key", func(t *testing.T) {
		macCreds, err := pkicmp.NewMACCredentials(secret)
		require.NoError(t, err)
		device := pkix.Name{CommonName: "composite-revocation"}
		ir, err := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert))).
			SendIR(context.Background(), key, macCreds, client.WithTemplateSubject(device), client.WithSender(device))
		require.NoError(t, err)

		details, err := pkicmp.NewRevDetails(ir.Certificate, pkicmp.CRLReasonKeyCompromise)
		require.NoError(t, err)
		details.CertDetails.PublicKey, err = compositex509.MarshalPKIXPublicKey(other.Public())
		require.NoError(t, err)
		creds, err := pkicmp.NewSignatureCredentials(key, ir.Certificate, ca.cert)
		require.NoError(t, err)
		msg := pkicmp.NewPKIMessage(pkicmp.NewRRBody(&pkicmp.RevReqContent{details}), pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(device)})
		require.NoError(t, creds.Protect(msg))
		status := rpStatus(t, postCMP(t, ts, msg))
		require.Equal(t, pkicmp.FailBadCertId, status.FailInfo)

		details.CertDetails.PublicKey = ir.Certificate.RawSubjectPublicKeyInfo
		msg = pkicmp.NewPKIMessage(pkicmp.NewRRBody(&pkicmp.RevReqContent{details}), pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(device)})
		require.NoError(t, creds.Protect(msg))
		require.Equal(t, pkicmp.StatusAccepted, rpStatus(t, postCMP(t, ts, msg)).Status)
	})
}

// A CR for the key of the certificate that signs it is confirmed with that
// certificate, which also certifies the issued key. RFC 9483 §4.1.1 requires
// the certConf to use the credentials of the request.
func TestCompositeSameKeyRequestConfirmed(t *testing.T) {
	secret := []byte("composite-device-secret")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := newDeviceCA(t, caKey)
	ts := ca.serve(t, secret)
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	macCreds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	device := pkix.Name{CommonName: "composite-certconf"}
	c := client.NewClient(ts.URL, client.WithTrustedCAs(x509pool(ca.cert)))
	ir, err := c.SendIR(context.Background(), key, macCreds, client.WithTemplateSubject(device), client.WithSender(device))
	require.NoError(t, err)

	creds, err := pkicmp.NewSignatureCredentials(key, ir.Certificate, ca.cert)
	require.NoError(t, err)
	confirmed := len(ca.confirmed)
	cr, err := c.SendCR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "composite-same-key"}), client.WithSender(device))
	require.NoError(t, err)
	requireCertifies(t, cr.Certificate, key, ca.cert)
	require.Len(t, ca.confirmed, confirmed+1)
}
