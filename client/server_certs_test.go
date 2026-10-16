package client_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// rsaHierarchy is a root CA, an issuing CA and an end-entity certificate it issued.
type rsaHierarchy struct {
	rootKey    *rsa.PrivateKey
	root       *x509.Certificate
	issuingKey *rsa.PrivateKey
	issuing    *x509.Certificate
	eeKey      *rsa.PrivateKey
	ee         *x509.Certificate
}

// newRSAHierarchy builds the hierarchy with an issuing CA whose keyUsage is keyCertSign and cRLSign only.
func newRSAHierarchy(t *testing.T) *rsaHierarchy {
	t.Helper()
	h := &rsaHierarchy{rootKey: rsaKey(t), issuingKey: rsaKey(t), eeKey: rsaKey(t)}
	h.root = issueCert(t, caTemplate(pkix.Name{Country: []string{"DE"}, Organization: []string{"Example"}, CommonName: "Root CA"}), nil, &h.rootKey.PublicKey, h.rootKey)
	h.issuing = issueCert(t, caTemplate(issuingCAName), h.root, &h.issuingKey.PublicKey, h.rootKey)
	h.ee = issueCert(t, &x509.Certificate{
		Subject:  pkix.Name{Country: []string{"DE"}, Organization: []string{"Example"}, CommonName: "device-01"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, h.issuing, &h.eeKey.PublicKey, h.issuingKey)
	return h
}

// issuingCAName is the subject of the issuing CA, which signs the revocation responses.
var issuingCAName = pkix.Name{Country: []string{"DE"}, Organization: []string{"Example"}, CommonName: "Issuing CA"}

// trust returns a pool holding the root and the issuing CA, as a client configured with the CA chain has.
func (h *rsaHierarchy) trust() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(h.root)
	pool.AddCert(h.issuing)
	return pool
}

// rsaKey generates a 2048-bit RSA key.
func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// caTemplate returns a CA certificate template that may sign certificates and CRLs but not other data.
func caTemplate(subject pkix.Name) *x509.Certificate {
	return &x509.Certificate{
		Subject:               subject,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// issueCert signs template for pub with issuerKey, self-signed when issuer is nil.
func issueCert(t *testing.T, template, issuer *x509.Certificate, pub crypto.PublicKey, issuerKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template.SerialNumber = serial
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	if issuer == nil {
		issuer = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// oidSHA256WithRSA identifies sha256WithRSAEncryption (RFC 4055).
var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

// rpWithoutExtraCerts answers every rr with an rp signed by key on behalf of signer and carrying no extraCerts.
//
// The response has the shape some CAs send: the issuing CA as sender, no senderKID, header, body and
// protection only. It returns the server and the number of requests it received.
func rpWithoutExtraCerts(t *testing.T, signer *x509.Certificate, key *rsa.PrivateKey, status pkicmp.PKIStatusInfo) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		if err != nil || req.Body.Type != pkicmp.BodyTypeRR {
			http.Error(w, "expected rr", http.StatusBadRequest)
			return
		}
		nonce := make([]byte, 16)
		_, _ = rand.Read(nonce)
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          pkicmp.PVNO2,
				Sender:        pkicmp.NewDirectoryNameFromRawDER(signer.RawSubject),
				Recipient:     req.Header.Sender,
				ProtectionAlg: &pkicmp.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullBytes},
				TransactionID: req.Header.TransactionID,
				SenderNonce:   nonce,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body:       pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{status}}),
			Protection: []byte{0},
		}
		der, err := signRSA(resp, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(ts.Close)
	return ts, &requests
}

// signRSA replaces the protection of msg with an RSA PKCS #1 v1.5 SHA-256 signature by key and returns its DER.
func signRSA(msg *pkicmp.PKIMessage, key *rsa.PrivateKey) ([]byte, error) {
	der, err := msg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	parsed, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return nil, err
	}
	data, err := parsed.ProtectedData()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if msg.Protection, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:]); err != nil {
		return nil, err
	}
	if len(msg.ExtraCerts) > 0 {
		return nil, errors.New("the response must not carry extraCerts")
	}
	return msg.MarshalBinary()
}

// revoke sends an rr for the hierarchy's end-entity certificate, signed with that certificate.
func (h *rsaHierarchy) revoke(t *testing.T, url string, opts ...client.Option) error {
	t.Helper()
	creds, err := pkicmp.NewSignatureCredentials(h.eeKey, h.ee, h.issuing)
	require.NoError(t, err)
	c := client.NewClient(url, append([]client.Option{client.WithTrustedCAs(h.trust())}, opts...)...)
	return c.SendRR(context.Background(), h.ee, pkicmp.CRLReasonCessationOfOperation, creds)
}

// A revocation response without extraCerts verifies once the CA certificate that signs it is configured.
func TestSendRRWithServerCerts(t *testing.T) {
	h := newRSAHierarchy(t)

	t.Run("accepted", func(t *testing.T) {
		ts, requests := rpWithoutExtraCerts(t, h.issuing, h.issuingKey, pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted})

		err := h.revoke(t, ts.URL)
		var ve *pkicmp.VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, pkicmp.ReasonNoCandidateSigner, ve.Reason)
		assert.ErrorContains(t, err, "WithServerCerts")
		// The CA acted on the request even though its answer could not be verified.
		assert.Equal(t, int32(1), requests.Load())

		require.NoError(t, h.revoke(t, ts.URL, client.WithServerCerts([]*x509.Certificate{h.issuing})))
		assert.Equal(t, int32(2), requests.Load())
	})

	t.Run("rejection is authenticated", func(t *testing.T) {
		rejected := pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			StatusString: pkicmp.PKIFreeText{"certificate already revoked"},
			FailInfo:     pkicmp.FailCertRevoked,
		}
		ts, _ := rpWithoutExtraCerts(t, h.issuing, h.issuingKey, rejected)

		err := h.revoke(t, ts.URL, client.WithServerCerts([]*x509.Certificate{nil, h.issuing}))
		var statusErr *pkicmp.PKIStatusError
		require.ErrorAs(t, err, &statusErr)
		assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
		assert.True(t, pkicmp.HasFailure(err, pkicmp.FailCertRevoked))
		var unverified *client.UnverifiedStatusError
		assert.False(t, errors.As(err, &unverified), "the rejection was verified")
	})
}

// A configured server certificate is held to the chain, sender and signature checks of one from extraCerts.
func TestSendRRRefusesWrongServerCerts(t *testing.T) {
	h := newRSAHierarchy(t)
	ts, _ := rpWithoutExtraCerts(t, h.issuing, h.issuingKey, pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted})

	// Same name and trusted issuer, different key.
	impostorKey := rsaKey(t)
	sameNameOtherKey := issueCert(t, caTemplate(issuingCAName), h.root, &impostorKey.PublicKey, h.rootKey)

	// The right key and name under an issuer the client does not trust.
	otherRootKey := rsaKey(t)
	otherRoot := issueCert(t, caTemplate(pkix.Name{CommonName: "Other Root CA"}), nil, &otherRootKey.PublicKey, otherRootKey)
	untrustedCopy := issueCert(t, caTemplate(issuingCAName), otherRoot, &h.issuingKey.PublicKey, otherRootKey)

	cases := []struct {
		name   string
		certs  []*x509.Certificate
		reason pkicmp.InvalidReason
	}{
		{"same name with another key", []*x509.Certificate{sameNameOtherKey}, pkicmp.ReasonSignatureFailed},
		{"right key under an untrusted issuer", []*x509.Certificate{untrustedCopy, otherRoot}, pkicmp.ReasonUntrustedSigner},
		{"trusted certificate of another name", []*x509.Certificate{h.root}, pkicmp.ReasonSenderMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := h.revoke(t, ts.URL, client.WithServerCerts(tc.certs))
			var ve *pkicmp.VerificationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, tc.reason, ve.Reason)
		})
	}
}

// The option copies its argument, so a later change to the caller's slice does not alter the client.
func TestWithServerCertsCopiesArgument(t *testing.T) {
	h := newRSAHierarchy(t)
	ts, _ := rpWithoutExtraCerts(t, h.issuing, h.issuingKey, pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted})

	certs := []*x509.Certificate{h.issuing}
	opt := client.WithServerCerts(certs)
	certs[0] = h.root
	require.NoError(t, h.revoke(t, ts.URL, opt))
}
