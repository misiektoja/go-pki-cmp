package client_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// revokingCA revokes each known certificate once.
type revokingCA struct {
	mu      sync.Mutex
	issued  []*x509.Certificate
	revoked map[string]pkicmp.CRLReason
}

// IssueCertificate refuses every request, since these tests exercise revocation only.
func (c *revokingCA) IssueCertificate(context.Context, server.RequestType, *x509.Certificate, *server.SenderIdentity) (*server.Response, error) {
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
}

// RevokeCertificate revokes a known certificate once and reports certRevoked afterwards.
func (c *revokingCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
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
	if _, ok := c.revoked[cert.SerialNumber.String()]; ok {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailCertRevoked, StatusText: "certificate already revoked"}
	}
	c.revoked[cert.SerialNumber.String()] = req.Reason
	return nil
}

// LookupCertificate finds a known certificate by its subject name.
func (c *revokingCA) LookupCertificate(_ pkix.Name, subject pkix.Name, _ []byte) (*x509.Certificate, error) {
	for _, cert := range c.issued {
		if cert.Subject.String() == subject.String() {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// RFC 9483 §4.2 against the server package: revoke once, then certRevoked.
func TestSendRRAgainstServer(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=rr-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	ee := &certyaml.Certificate{Subject: "cn=rr-ee", Issuer: ca}
	eeCert, err := ee.X509Certificate()
	require.NoError(t, err)
	eeKey, err := ee.PrivateKey()
	require.NoError(t, err)

	backend := &revokingCA{issued: []*x509.Certificate{&eeCert}, revoked: map[string]pkicmp.CRLReason{}}
	srv := server.NewCAServer(backend, server.LightweightPolicy(), server.WithSigner(caKey, &caCert), server.WithCertificateLookup(backend))
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	trusted := x509.NewCertPool()
	trusted.AddCert(&caCert)
	c := client.NewClient(ts.URL, client.WithTrustedCAs(trusted))
	creds, err := pkicmp.NewSignatureCredentials(eeKey, &eeCert, &caCert)
	require.NoError(t, err)

	require.NoError(t, c.SendRR(context.Background(), &eeCert, pkicmp.CRLReasonCessationOfOperation, creds))
	assert.Equal(t, pkicmp.CRLReasonCessationOfOperation, backend.revoked[eeCert.SerialNumber.String()])

	err = c.SendRR(context.Background(), &eeCert, pkicmp.CRLReasonCessationOfOperation, creds)
	var statusErr *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailCertRevoked))
}

// rrMockServer answers each request with the body respond returns, MAC-protected with "secret".
func rrMockServer(t *testing.T, respond func(n int32, req *pkicmp.PKIMessage) *pkicmp.PKIBody) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: respond(atomic.AddInt32(&calls, 1), req),
		}
		creds, _ := pkicmp.NewMACCredentials([]byte("secret"))
		_ = creds.Protect(resp)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

// sendRR revokes the test end-entity certificate with MAC credentials.
func sendRR(t *testing.T, url string, reason pkicmp.CRLReason) error {
	t.Helper()
	pki := newTestPKI()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	return client.NewClient(url).SendRR(context.Background(), pki.eeCert, reason, creds)
}

// The request carries one RevDetails naming the certificate by issuer and serial number.
func TestSendRRRequestContent(t *testing.T) {
	pki := newTestPKI()
	var got *pkicmp.RevReqContent
	ts, _ := rrMockServer(t, func(_ int32, req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		got, _ = req.Body.RR()
		return pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{{Status: pkicmp.StatusAccepted}}})
	})

	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	require.NoError(t, client.NewClient(ts.URL).SendRR(context.Background(), pki.eeCert, pkicmp.CRLReasonCertificateHold, creds))

	require.NotNil(t, got)
	require.Len(t, *got, 1)
	details := (*got)[0]
	assert.Equal(t, 0, details.CertDetails.SerialNumber.Cmp(pki.eeCert.SerialNumber))
	assert.Equal(t, pki.eeCert.RawIssuer, details.CertDetails.Issuer)
	exts, err := details.CRLEntryExtensions()
	require.NoError(t, err)
	require.Len(t, exts, 1)
	var code asn1.Enumerated
	_, err = asn1.Unmarshal(exts[0].Value, &code)
	require.NoError(t, err)
	assert.Equal(t, asn1.Enumerated(pkicmp.CRLReasonCertificateHold), code)
}

// RFC 9483 §4.4: a delayed rp arrives after an error message with status waiting and polling with certReqId -1.
func TestSendRRPolling(t *testing.T) {
	var polled []int64
	ts, calls := rrMockServer(t, func(n int32, req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		switch n {
		case 1:
			return pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}})
		case 2:
			pr, _ := req.Body.PollReq()
			polled = append(polled, *pr...)
			return pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: -1, CheckAfter: 0}})
		default:
			pr, _ := req.Body.PollReq()
			polled = append(polled, *pr...)
			return pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{{Status: pkicmp.StatusAccepted}}})
		}
	})

	require.NoError(t, sendRR(t, ts.URL, pkicmp.CRLReasonKeyCompromise))
	assert.Equal(t, int32(3), atomic.LoadInt32(calls))
	assert.Equal(t, []int64{-1, -1}, polled)
}

// Rejections and malformed answers are returned as errors.
func TestSendRRFailures(t *testing.T) {
	tests := []struct {
		name  string
		body  *pkicmp.PKIBody
		check func(t *testing.T, err error)
	}{
		{
			name: "Rejected",
			body: pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadCertId}}}),
			check: func(t *testing.T, err error) {
				var statusErr *pkicmp.PKIStatusError
				require.ErrorAs(t, err, &statusErr)
				assert.True(t, pkicmp.HasFailure(err, pkicmp.FailBadCertId))
			},
		},
		{
			name: "ErrorMessage",
			body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck}}),
			check: func(t *testing.T, err error) {
				assert.True(t, pkicmp.HasFailure(err, pkicmp.FailBadMessageCheck))
			},
		},
		{
			name: "TwoStatuses",
			body: pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{{Status: pkicmp.StatusAccepted}, {Status: pkicmp.StatusAccepted}}}),
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "2 statuses")
			},
		},
		{
			name: "UnexpectedBody",
			body: pkicmp.NewPKIConfBody(),
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "unexpected response body type")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := rrMockServer(t, func(int32, *pkicmp.PKIMessage) *pkicmp.PKIBody { return tt.body })
			err := sendRR(t, ts.URL, pkicmp.CRLReasonUnspecified)
			require.Error(t, err)
			tt.check(t, err)
		})
	}
}

// Invalid input fails before anything is sent.
func TestSendRRInvalidInput(t *testing.T) {
	ts, calls := rrMockServer(t, func(int32, *pkicmp.PKIMessage) *pkicmp.PKIBody { return pkicmp.NewPKIConfBody() })
	pki := newTestPKI()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(ts.URL)

	assert.Error(t, c.SendRR(context.Background(), nil, pkicmp.CRLReasonUnspecified, creds))
	assert.Error(t, c.SendRR(context.Background(), pki.eeCert, pkicmp.CRLReason(7), creds))
	assert.Error(t, c.SendRR(context.Background(), pki.eeCert, pkicmp.CRLReasonUnspecified, nil))
	assert.Zero(t, atomic.LoadInt32(calls))
}
