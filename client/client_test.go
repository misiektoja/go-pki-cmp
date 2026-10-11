package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// testPKI holds certificates and keys for tests.
type testPKI struct {
	ca        *certyaml.Certificate
	caCert    *x509.Certificate
	ee        *certyaml.Certificate
	eeCert    *x509.Certificate
	extraCert *x509.Certificate
}

func newTestPKI() testPKI {
	ca := &certyaml.Certificate{Subject: "cn=test-ca"}
	caCert, _ := ca.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	extra := &certyaml.Certificate{Subject: "cn=extra-cert", Issuer: ca}
	extraCert, _ := extra.X509Certificate()

	return testPKI{ca: ca, caCert: &caCert, ee: ee, eeCert: &eeCert, extraCert: &extraCert}
}

// mockCMPServer creates a mock CMP server that responds with the given body type and handles certConf.
func mockCMPServer(pki testPKI, respBodyFn func(req *pkicmp.PKIMessage) *pkicmp.PKIBody, secret []byte) *httptest.Server {
	var callCount atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			respBody := respBodyFn(req)
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body:       respBody,
				ExtraCerts: []pkicmp.CMPCertificate{{Raw: pki.extraCert.Raw}},
			}
		} else {
			// certConf -> PKIConf
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		}

		{
			_mc, _ := pkicmp.NewMACCredentials(secret)
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
}

func TestSendIRHappyPath(t *testing.T) {
	pki := newTestPKI()
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	// Enroll with the key the mock CA's certificate actually certifies, because
	// the client now rejects a certificate issued for some other key.
	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.Equal(t, pki.eeCert.SerialNumber, result.Certificate.SerialNumber)
	require.Len(t, result.CAPubs, 1)
	assert.Equal(t, pki.caCert.Raw, result.CAPubs[0].Raw)
	require.Len(t, result.ExtraCertificates, 1)
	assert.Equal(t, pki.extraCert.Raw, result.ExtraCertificates[0].Raw)
}

func TestSendCRHappyPath(t *testing.T) {
	pki := newTestPKI()
	sigCert := &certyaml.Certificate{Subject: "cn=signer", Issuer: pki.ca}
	sigKey, _ := sigCert.PrivateKey()
	sigX509, _ := sigCert.X509Certificate()

	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewCPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	// Use MAC secret for response verification since mock uses MAC.
	// But request is signature-protected.
	// Actually the mock protects response with MAC using "secret", so we need MAC creds for verification.
	// Let's use MAC creds for simplicity since the mock always uses MAC.
	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewSignatureCredentials(sigKey, &sigX509)
	require.NoError(t, err)

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(pki.caCert)

	// Signature creds won't have a secret for MAC verification of response.
	// The mock uses MAC protection. We need to adjust: use MAC creds or make mock use sig.
	// Let's make a sig-protected mock instead.
	server.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var resp *pkicmp.PKIMessage
		if req.Body.Type == pkicmp.BodyTypeCertConf {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		} else {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewCPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
		}
		{
			_sc, _ := pkicmp.NewSignatureCredentials(sigKey, &sigX509)
			_ = _sc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server2.Close()

	c := client.NewClient(server2.URL, client.WithTrustedCAs(trustedCAs))
	result, err := c.SendCR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.Equal(t, pki.eeCert.SerialNumber, result.Certificate.SerialNumber)
}

func TestSendKURHappyPath(t *testing.T) {
	pki := newTestPKI()
	sigCert := &certyaml.Certificate{Subject: "cn=signer", Issuer: pki.ca}
	sigKey, _ := sigCert.PrivateKey()
	sigX509, _ := sigCert.X509Certificate()

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(pki.caCert)
	controlsCh := make(chan []pkicmp.AttributeTypeAndValue, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var resp *pkicmp.PKIMessage
		if req.Body.Type == pkicmp.BodyTypeCertConf {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		} else {
			requests, parseErr := req.Body.KUR()
			var controls []pkicmp.AttributeTypeAndValue
			if parseErr == nil && requests != nil && len(*requests) == 1 {
				controls = (*requests)[0].CertReq.Controls
			}
			controlsCh <- controls
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewKUPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
		}
		{
			_sc, _ := pkicmp.NewSignatureCredentials(sigKey, &sigX509)
			_ = _sc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewSignatureCredentials(sigKey, &sigX509)
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	result, err := c.SendKUR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.Equal(t, pki.eeCert.SerialNumber, result.Certificate.SerialNumber)
	controls := <-controlsCh
	require.Len(t, controls, 1)
	control := controls[0]
	assert.Equal(t, "1.3.6.1.5.5.7.5.1.5", control.Type.String())
	var oldCertID struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	rest, err := asn1.Unmarshal(control.Value, &oldCertID)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, sigX509.SerialNumber, oldCertID.SerialNumber)
}

func TestSendP10CRHappyPath(t *testing.T) {
	pki := newTestPKI()

	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewCPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)

	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendP10CR(context.Background(), csrDER, creds)
	require.NoError(t, err)
	assert.Equal(t, pki.eeCert.SerialNumber, result.Certificate.SerialNumber)
}

func TestPollingHappyPath(t *testing.T) {
	pki := newTestPKI()
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		switch {
		case count == 1:
			// First request: return waiting status
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
		case count == 2:
			// PollReq -> PollRep with checkAfter=0
			pollRep := pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}}
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPollRepBody(&pollRep),
			}
		case count == 3:
			// PollReq -> final IP response
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
		default:
			// certConf -> PKIConf
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		}

		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.Equal(t, pki.eeCert.SerialNumber, result.Certificate.SerialNumber)
	assert.Equal(t, int32(4), callCount.Load())
}

func TestPollingMaxRetries(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			// First: return waiting
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
		} else {
			// Always return PollRep
			pollRep := pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}}
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPollRepBody(&pollRep),
			}
		}

		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxPolls(3))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "polling exceeded max retries")
}

func TestPollingContextCancellation(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
		} else {
			// Return PollRep with checkAfter=5 to trigger context wait
			pollRep := pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 5}}
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPollRepBody(&pollRep),
			}
		}

		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxPolls(100))

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first poll reply is received (checkAfter=5 will block)
	go func() {
		for callCount.Load() < 2 {
		}
		cancel()
	}()

	_, err = c.SendIR(ctx, key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.ErrorIs(t, err, context.Canceled)
}

func TestHTTPErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "HTTP 500")
}

func TestProtectMessageNoCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server")
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := client.NewClient(server.URL)

	_, err := c.SendIR(context.Background(), key, nil, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
}

func TestSignatureCredentialsMismatch(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=ca"}
	cert := &certyaml.Certificate{Subject: "cn=signer", Issuer: ca}
	certX509, _ := cert.X509Certificate()

	// Generate a different key that doesn't match the cert
	mismatchedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := pkicmp.NewSignatureCredentials(mismatchedKey, &certX509)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestContentTypeValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("not CMP"))
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "unexpected Content-Type")
}

func TestServerReturnsErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
				PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
}

func TestWithExtraCertsAndSender(t *testing.T) {
	pki := newTestPKI()
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL,
		client.WithExtraCerts([]*x509.Certificate{pki.caCert}),
		client.WithHTTPClient(http.DefaultClient),
	)

	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "test"}),
		client.WithSender(pkix.Name{CommonName: "sender"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestWithTemplateExtension(t *testing.T) {
	pki := newTestPKI()
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	ext := pkix.Extension{
		Id:    []int{2, 5, 29, 17}, // SAN OID
		Value: []byte{0x30, 0x00},
	}
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "test"}),
		client.WithTemplateExtension(ext),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestClientErrorString(t *testing.T) {
	// Error with Err set
	ce := &client.Error{Op: "test op", Err: assert.AnError}
	assert.Contains(t, ce.Error(), "test op")
	assert.Contains(t, ce.Error(), assert.AnError.Error())

	// Error without Err
	ce2 := &client.Error{Op: "test op only"}
	assert.Equal(t, "cmp: test op only", ce2.Error())
	assert.Nil(t, ce2.Unwrap())
}

func TestSendP10CRInvalidCSR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server")
	}))
	defer server.Close()

	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendP10CR(context.Background(), []byte("invalid-csr"), creds)
	require.Error(t, err)
}

func TestServerReturnsGrantedWithMods(t *testing.T) {
	pki := newTestPKI()
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusGrantedWithMods},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestServerReturnsRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection},
				}},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
}

func TestServerReturnsMissingCertifiedKeyPair(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID:        0,
					Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: nil,
				}},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "missing certifiedKeyPair")
}

func TestServerReturnsUnexpectedBodyType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		// Return KUP when IP is expected
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewKUPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				}},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "unexpected response body type")
}

func TestServerReturnsMissingProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				}},
			}),
		}
		// Don't protect - no MAC or signature
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify response", ce.Op)
}

func TestPollingServerReturnsErrorDuringPoll(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
		} else {
			// Return error during polling
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
					PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection},
				}),
			}
		}

		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
}

func TestSendIRWithRSAKey(t *testing.T) {
	// Uses RSA to cover SHA256WithRSA path in pkicmp.CertHash.
	ca := &certyaml.Certificate{Subject: "cn=rsa-ca", KeyType: certyaml.KeyTypeRSA}
	caCert, _ := ca.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=rsa-ee", Issuer: ca, KeyType: certyaml.KeyTypeRSA}
	eeCert, _ := ee.X509Certificate()

	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
						},
					}},
				}),
			}
		} else {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestSendIRWithP384Key(t *testing.T) {
	// Uses P384 to cover ECDSAWithSHA384 path in pkicmp.CertHash.
	ca := &certyaml.Certificate{Subject: "cn=p384-ca", KeyType: certyaml.KeyTypeEC, KeySize: 384}
	caCert, _ := ca.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=p384-ee", Issuer: ca, KeyType: certyaml.KeyTypeEC, KeySize: 384}
	eeCert, _ := ee.X509Certificate()

	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
						},
					}},
				}),
			}
		} else {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestSendIRWithP521Key(t *testing.T) {
	// Uses P521 to cover ECDSAWithSHA512 path in pkicmp.CertHash.
	ca := &certyaml.Certificate{Subject: "cn=p521-ca", KeyType: certyaml.KeyTypeEC, KeySize: 521}
	caCert, _ := ca.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=p521-ee", Issuer: ca, KeyType: certyaml.KeyTypeEC, KeySize: 521}
	eeCert, _ := ee.X509Certificate()

	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
						},
					}},
				}),
			}
		} else {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestPollingHTTPErrorDuringPoll(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		if count == 1 {
			// First: return waiting
			resp := &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(resp)
			}
			der, _ := resp.MarshalBinary()
			w.Header().Set("Content-Type", "application/pkixcmp")
			_, _ = w.Write(der)
		} else {
			// Poll request gets HTTP 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "HTTP 500")
}

func TestServerReturnsUnsupportedPVNO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          99, // unsupported version
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				}},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "unsupported protocol version")
}

func TestCAPubsWithExistingTrustedCAs(t *testing.T) {
	// Tests the path where effectiveTrustPool != nil and caPubs are present (Clone path).
	pki := newTestPKI()
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(pki.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
}

func TestCertConfServerReturnsError(t *testing.T) {
	// Tests the path where certConf exchange returns an error body.
	pki := newTestPKI()
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
		} else {
			// certConf -> Error
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
					PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection},
				}),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
}

func TestCertConfServerReturnsUnexpectedType(t *testing.T) {
	// Tests the path where certConf response is not PKIConf or Error.
	pki := newTestPKI()
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
		} else {
			// certConf -> IP (unexpected)
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					}},
				}),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "expected PKIConf")
}

func TestCertConfHTTPError(t *testing.T) {
	pki := newTestPKI()
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		if count == 1 {
			resp := &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
						},
					}},
				}),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(resp)
			}
			der, _ := resp.MarshalBinary()
			w.Header().Set("Content-Type", "application/pkixcmp")
			_, _ = w.Write(der)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	key, _ := pki.ee.PrivateKey()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "certConf exchange", ce.Op)
}

func TestServerReturnsEncryptedCert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: nil}, // encrypted cert
					},
				}},
			}),
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CertOrEncCert")
}

func TestPollingVerificationErrorDuringPoll(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(resp)
			}
		} else {
			// Poll response with wrong transaction ID to trigger verification error
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: []byte("wrong-txn-id"),
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}}),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(resp)
			}
		}

		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify polled response", ce.Op)
}

func TestPollingUnsupportedPVNODuringPoll(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		count := callCount.Add(1)

		var resp *pkicmp.PKIMessage
		if count == 1 {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting},
					}},
				}),
			}
		} else {
			resp = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          99,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}}),
			}
		}
		{
			_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
			_ = _mc.Protect(resp)
		}
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "unsupported protocol version")
}
