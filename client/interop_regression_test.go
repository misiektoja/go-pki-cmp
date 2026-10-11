package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// enrollmentExchange serves one enrollment: an ip for the first request and a pkiConf for the certConf.
type enrollmentExchange struct {
	// issuer mints the end-entity certificate returned in the ip.
	issuer *certyaml.Certificate
	// sender, when set, is placed in the header of every response.
	sender pkix.Name
	// extraCertsOnIP and extraCertsOnPKIConf model servers that stop sending
	// certificates after their first message.
	extraCertsOnIP      []*x509.Certificate
	extraCertsOnPKIConf []*x509.Certificate
	// protect applies message protection to each response.
	protect func(*pkicmp.PKIMessage)
	// responseContentType overrides the default CMP response media type.
	responseContentType string

	// recipientSeen records the recipient the client put in its first request.
	recipientSeen pkicmp.GeneralName
	issuedCert    *x509.Certificate
	calls         int
}

func (e *enrollmentExchange) start(t *testing.T) *httptest.Server {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		e.calls++
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
		}
		if !isEmptyTestName(e.sender) {
			resp.Header.Sender = pkicmp.NewDirectoryName(e.sender)
		}

		var attached []*x509.Certificate
		if e.calls == 1 {
			e.recipientSeen = req.Header.Recipient
			e.issuedCert = issueForRequest(e.issuer, pkix.Name{CommonName: "enrolled-ee"}, req)
			require.NotNil(t, e.issuedCert)
			resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: e.issuedCert.Raw}},
					},
				}},
			})
			attached = e.extraCertsOnIP
		} else {
			resp.Body = pkicmp.NewPKIConfBody()
			attached = e.extraCertsOnPKIConf
		}
		for _, cert := range attached {
			resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
		}

		e.protect(resp)

		der, err := resp.MarshalBinary()
		require.NoError(t, err)
		contentType := e.responseContentType
		if contentType == "" {
			contentType = "application/pkixcmp"
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server
}

func isEmptyTestName(name pkix.Name) bool {
	return name.CommonName == "" && len(name.Organization) == 0 && len(name.Country) == 0
}

// interopSecret is the shared secret of both the client and the mock CAs in these tests.
const interopSecret = "secret"

// macProtector returns a function that MAC-protects a message with interopSecret.
func macProtector() func(*pkicmp.PKIMessage) {
	return func(msg *pkicmp.PKIMessage) {
		creds, _ := pkicmp.NewMACCredentials([]byte(interopSecret))
		_ = creds.Protect(msg)
	}
}

func signatureProtector(key crypto.Signer, cert *x509.Certificate) func(*pkicmp.PKIMessage) {
	return func(msg *pkicmp.PKIMessage) {
		creds, _ := pkicmp.NewSignatureCredentials(key, cert)
		_ = creds.Protect(msg)
		// ProtectWithSignature sets senderKID from the certificate. Clearing it
		// models a server that omits the field, which leaves the sender name as
		// the only hint to the signer.
		msg.Header.SenderKID = nil
	}
}

// A CA routes on the recipient field, so a name the caller built in Go must
// reach the wire. pkix.Name.Names is empty for such a name, so testing it to
// decide whether a recipient was configured silently drops it.
func TestRequestCarriesProgrammaticallyBuiltRecipient(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=recipient-test-ca"}
	exchange := &enrollmentExchange{issuer: ca, protect: macProtector()}
	server := exchange.start(t)

	recipient := pkix.Name{
		Country:      []string{"DE"},
		Organization: []string{"Example"},
		CommonName:   "issuing-ca",
	}
	require.Empty(t, recipient.Names, "a programmatically built name has no parsed attributes")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)

	require.NotEmpty(t, exchange.recipientSeen.DirectoryName, "recipient must not be dropped")
	assert.Equal(t, recipient.String(), exchange.recipientSeen.DirectoryName.String())
}

// TestClientAcceptsCMPMediaTypeVariants verifies case-insensitive media types with optional parameters.
func TestClientAcceptsCMPMediaTypeVariants(t *testing.T) {
	for _, contentType := range []string{
		"Application/PKIXCMP",
		"application/pkixcmp; charset=binary",
	} {
		t.Run(contentType, func(t *testing.T) {
			ca := &certyaml.Certificate{Subject: "cn=media-type-ca"}
			exchange := &enrollmentExchange{
				issuer:              ca,
				protect:             macProtector(),
				responseContentType: contentType,
			}
			server := exchange.start(t)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
			require.NoError(t, err)

			c := client.NewClient(server.URL)
			result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
			require.NoError(t, err)
			require.NotNil(t, result.Certificate)
		})
	}
}

// TestClientRejectsMalformedCMPMediaType verifies that invalid media type parameters fail closed.
func TestClientRejectsMalformedCMPMediaType(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=media-type-ca"}
	exchange := &enrollmentExchange{
		issuer:              ca,
		protect:             macProtector(),
		responseContentType: "application/pkixcmp; charset",
	}
	server := exchange.start(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL)
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected Content-Type")
}

// A CA that issues from an intermediate returns that intermediate in
// extraCerts, so the issued certificate must validate against a trust anchor
// that holds only the root.
func TestIssuedCertificateChainsThroughExtraCertsIntermediate(t *testing.T) {
	isCA := true
	root := &certyaml.Certificate{Subject: "cn=interop-root"}
	rootCert, err := root.X509Certificate()
	require.NoError(t, err)
	intermediate := &certyaml.Certificate{Subject: "cn=interop-intermediate", Issuer: root, IsCA: &isCA}
	intermediateCert, err := intermediate.X509Certificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:         intermediate,
		extraCertsOnIP: []*x509.Certificate{&intermediateCert},
		protect:        macProtector(),
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&rootCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
	assert.Equal(t, "interop-intermediate", result.Certificate.Issuer.CommonName)
}

// A server may send extraCerts only on its first message, so a later message in
// the same operation must still verify against the signer already authenticated.
func TestPKIConfVerifiesAgainstSignerFromEarlierMessage(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=retained-signer-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	cmpSigner := &certyaml.Certificate{Subject: "cn=cmp-signer", Issuer: ca}
	cmpSignerCert, err := cmpSigner.X509Certificate()
	require.NoError(t, err)
	cmpSignerTLS, err := cmpSigner.TLSCertificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:              ca,
		sender:              pkix.Name{CommonName: "cmp-signer"},
		extraCertsOnIP:      []*x509.Certificate{&cmpSignerCert},
		extraCertsOnPKIConf: nil,
		protect:             signatureProtector(cmpSignerTLS.PrivateKey.(crypto.Signer), &cmpSignerCert),
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&caCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
}

// Retaining the earlier signer must not let any other certificate close the
// operation, even one that chains to the same trust anchor.
func TestPKIConfRejectsSignerThatDidNotProtectEarlierMessage(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=retained-signer-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	cmpSigner := &certyaml.Certificate{Subject: "cn=cmp-signer", Issuer: ca}
	cmpSignerCert, err := cmpSigner.X509Certificate()
	require.NoError(t, err)
	cmpSignerTLS, err := cmpSigner.TLSCertificate()
	require.NoError(t, err)
	impostor := &certyaml.Certificate{Subject: "cn=impostor", Issuer: ca}
	impostorCert, err := impostor.X509Certificate()
	require.NoError(t, err)
	impostorTLS, err := impostor.TLSCertificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:         ca,
		sender:         pkix.Name{CommonName: "cmp-signer"},
		extraCertsOnIP: []*x509.Certificate{&cmpSignerCert},
	}
	signWithCMPSigner := signatureProtector(cmpSignerTLS.PrivateKey.(crypto.Signer), &cmpSignerCert)
	signWithImpostor := signatureProtector(impostorTLS.PrivateKey.(crypto.Signer), &impostorCert)
	exchange.protect = func(msg *pkicmp.PKIMessage) {
		if exchange.calls == 1 {
			signWithCMPSigner(msg)
			return
		}
		signWithImpostor(msg)
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&caCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)

	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify PKIConf", ce.Op)
}

// TestAuthenticatedCMPErrorOnHTTPErrorStatus verifies that protected CMP failure details survive an HTTP error status.
func TestAuthenticatedCMPErrorOnHTTPErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
				PKIStatusInfo: pkicmp.PKIStatusInfo{
					Status:   pkicmp.StatusRejection,
					FailInfo: pkicmp.FailTransactionIdInUse,
				},
			}),
		}
		macProtector()(resp)
		der, err := resp.MarshalBinary()
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/pkixcmp")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL)
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailTransactionIdInUse))
	assert.Contains(t, err.Error(), "HTTP 400: Bad Request")
}

// TestPollingAcceptsDelayedResponseNonce verifies that a final response may refer to the request whose processing was delayed.
func TestPollingAcceptsDelayedResponseNonce(t *testing.T) {
	issuer := &certyaml.Certificate{Subject: "cn=delayed-response-ca"}
	var calls atomic.Int32
	var originalRequest *pkicmp.PKIMessage
	var originalNonce []byte
	var pollNonce []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		count := calls.Add(1)
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
		}
		switch count {
		case 1:
			originalRequest = req
			originalNonce = append([]byte(nil), req.Header.SenderNonce...)
			resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
				}},
			})
		case 2:
			pollNonce = append([]byte(nil), req.Header.SenderNonce...)
			issuedCert := issueForRequest(issuer, pkix.Name{CommonName: "enrolled-ee"}, originalRequest)
			require.NotNil(t, issuedCert)
			resp.Header.RecipNonce = originalNonce
			resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: issuedCert.Raw}},
					},
				}},
			})
		default:
			resp.Body = pkicmp.NewPKIConfBody()
		}

		macProtector()(resp)
		der, err := resp.MarshalBinary()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL)
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
	assert.Equal(t, int32(3), calls.Load())
	assert.NotEqual(t, originalNonce, pollNonce)
}

// TestPollingRejectsDelayedNonceOnPollRep verifies that a poll response remains bound to its poll request.
func TestPollingRejectsDelayedNonceOnPollRep(t *testing.T) {
	var calls atomic.Int32
	var originalNonce []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
		}
		if calls.Add(1) == 1 {
			originalNonce = append([]byte(nil), req.Header.SenderNonce...)
			resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
				}},
			})
		} else {
			require.NotEqual(t, originalNonce, req.Header.SenderNonce)
			resp.Header.RecipNonce = originalNonce
			resp.Body = pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}})
		}

		macProtector()(resp)
		der, err := resp.MarshalBinary()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL)
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recipient nonce mismatch")
}

// signedErrorExchange answers every request with a signature-protected error message.
type signedErrorExchange struct {
	// sender names the signer in the header, which is the only hint to the
	// protection certificate once senderKID is omitted.
	sender pkix.Name
	// extraCerts carries the protection certificate to the client.
	extraCerts []*x509.Certificate
	// protect applies signature protection to the error message.
	protect func(*pkicmp.PKIMessage)
}

func (e *signedErrorExchange) start(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
				Sender:        pkicmp.NewDirectoryName(e.sender),
			},
			Body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
				PKIStatusInfo: pkicmp.PKIStatusInfo{
					Status:       pkicmp.StatusRejection,
					StatusString: pkicmp.PKIFreeText{signedErrorStatusString},
					FailInfo:     pkicmp.FailTransactionIdInUse,
				},
			}),
		}
		for _, cert := range e.extraCerts {
			resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
		}
		e.protect(resp)
		der, err := resp.MarshalBinary()
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)
	return server
}

const signedErrorStatusString = "transaction id already in use"

// newSignedErrorExchange returns an exchange signed by a fresh CA, with that CA in a trust pool.
func newSignedErrorExchange(t *testing.T) (*signedErrorExchange, *x509.CertPool) {
	t.Helper()
	ca := &certyaml.Certificate{Subject: "cn=signed-error-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	signer := &certyaml.Certificate{Subject: "cn=signed-error-cmp-signer", Issuer: ca}
	signerCert, err := signer.X509Certificate()
	require.NoError(t, err)
	signerTLS, err := signer.TLSCertificate()
	require.NoError(t, err)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&caCert)

	return &signedErrorExchange{
		sender:     pkix.Name{CommonName: "signed-error-cmp-signer"},
		extraCerts: []*x509.Certificate{&signerCert},
		protect:    signatureProtector(signerTLS.PrivateKey.(crypto.Signer), &signerCert),
	}, trustPool
}

// A CA signs an error message however the request was protected, so a client
// holding only a shared secret cannot authenticate a rejection. It must still
// learn what the peer claimed, clearly marked as unauthenticated.
func TestSignedErrorStatusReportedWithoutTrustAnchors(t *testing.T) {
	exchange, _ := newSignedErrorExchange(t)
	server := exchange.start(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL)
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)

	var unverified *client.UnverifiedStatusError
	require.ErrorAs(t, err, &unverified)
	assert.Equal(t, pkicmp.StatusRejection, unverified.Status)
	assert.Equal(t, pkicmp.FailTransactionIdInUse, unverified.FailInfo)
	assert.Equal(t, signedErrorStatusString, unverified.StatusString)

	// The status is attacker-controlled here, so it must not reach the checks a
	// caller uses to act on an authenticated failure, and the peer's free text
	// must not be formatted into a message headed for a log.
	assert.False(t, pkicmp.HasFailure(err, pkicmp.FailTransactionIdInUse))
	assert.NotContains(t, err.Error(), signedErrorStatusString)

	// The remedy has to be visible to whoever reads the failure.
	assert.Contains(t, err.Error(), "no trusted CAs are configured")
}

// The same rejection is authenticated, and actionable, once the client is given
// the trust anchors the signed error message needs.
func TestSignedErrorAuthenticatedWithTrustAnchors(t *testing.T) {
	exchange, trustPool := newSignedErrorExchange(t)
	server := exchange.start(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)

	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailTransactionIdInUse))
	var unverified *client.UnverifiedStatusError
	assert.False(t, errors.As(err, &unverified))
}

// The peer chooses checkAfter. Left unclamped, a value past what a duration can
// hold collapses into no wait at all and turns polling into a tight request
// loop, while a merely large one parks the operation for years.
func TestPollingClampsCheckAfter(t *testing.T) {
	tests := []struct {
		name         string
		checkAfter   int64
		emptyPollRep bool
		minInterval  time.Duration
		maxInterval  time.Duration
		wantAtLeast  time.Duration
	}{
		{name: "overflowing value waits the configured maximum", checkAfter: math.MaxInt64, minInterval: 0, maxInterval: 200 * time.Millisecond, wantAtLeast: 200 * time.Millisecond},
		{name: "zero waits the configured minimum", checkAfter: 0, minInterval: 150 * time.Millisecond, maxInterval: time.Second, wantAtLeast: 150 * time.Millisecond},
		{name: "negative value waits the configured minimum", checkAfter: -1, minInterval: 150 * time.Millisecond, maxInterval: time.Second, wantAtLeast: 150 * time.Millisecond},
		{name: "value within the limits is honored", checkAfter: 1, minInterval: 0, maxInterval: 5 * time.Second, wantAtLeast: time.Second},
		{name: "empty pollRep waits the configured minimum", emptyPollRep: true, minInterval: 150 * time.Millisecond, maxInterval: time.Second, wantAtLeast: 150 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			var pollRepAt, finalAt atomic.Int64

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				req, err := pkicmp.ParsePKIMessage(body)
				require.NoError(t, err)

				resp := &pkicmp.PKIMessage{
					Header: pkicmp.PKIHeader{
						PVNO:          req.Header.PVNO,
						TransactionID: req.Header.TransactionID,
						RecipNonce:    req.Header.SenderNonce,
					},
				}
				switch calls.Add(1) {
				case 1:
					resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
						Response: []pkicmp.CertResponse{{
							CertReqID: 0,
							Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
						}},
					})
				case 2:
					pollRepAt.Store(time.Now().UnixNano())
					pollRep := pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: tt.checkAfter}}
					if tt.emptyPollRep {
						pollRep = pkicmp.PollRepContent{}
					}
					resp.Body = pkicmp.NewPollRepBody(&pollRep)
				default:
					finalAt.Store(time.Now().UnixNano())
					resp.Body = pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
						PKIStatusInfo: pkicmp.PKIStatusInfo{
							Status:   pkicmp.StatusRejection,
							FailInfo: pkicmp.FailSystemFailure,
						},
					})
				}
				macProtector()(resp)
				der, err := resp.MarshalBinary()
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/pkixcmp")
				_, _ = w.Write(der)
			}))
			t.Cleanup(server.Close)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			creds, err := pkicmp.NewMACCredentials([]byte(interopSecret))
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c := client.NewClient(server.URL, client.WithCheckAfterLimits(tt.minInterval, tt.maxInterval))
			_, err = c.SendIR(ctx, key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
			require.Error(t, err)
			assert.True(t, pkicmp.HasFailure(err, pkicmp.FailSystemFailure))
			require.EqualValues(t, 3, calls.Load())

			waited := time.Duration(finalAt.Load() - pollRepAt.Load())
			assert.GreaterOrEqual(t, waited, tt.wantAtLeast)
			assert.Less(t, waited, 10*time.Second, "the wait must stay inside the configured maximum")
		})
	}
}
