package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// requestKey returns the public key an ir or p10cr asks to certify.
func requestKey(req *pkicmp.PKIMessage) any {
	if req.Body.Type == pkicmp.BodyTypeP10CR {
		csr, err := req.Body.P10CR()
		if err != nil {
			return nil
		}
		return csr.PublicKey
	}
	return requestedPublicKey(req)
}

// sendP10CR enrolls a fresh P-256 key through a p10cr with MAC credentials and the given trust anchors.
func sendP10CR(t *testing.T, url string, trusted *x509.Certificate, opts ...client.RequestOption) (*client.EnrollResult, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, key)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(trusted)
	c := client.NewClient(url, client.WithTrustedCAs(pool))
	return c.SendP10CR(context.Background(), csrDER, creds, append([]client.RequestOption{client.WithSenderKID([]byte("test"))}, opts...)...)
}

// RFC 9810 §5.3.4: a CertResponse names the request it answers by certReqId.
// A p10cr carries none, so -1 from RFC 9810 and 0 from EJBCA both answer it.
// The certConf repeats the CA's value, also when it rejects a certificate
// issued under another one.
func TestCertReqIDMatchesRequest(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	for _, tc := range []struct {
		p10cr     bool
		certReqID int64
		accepted  bool
	}{
		{false, 0, true},
		{false, -1, false},
		{false, 1, false},
		{true, -1, true},
		{true, 0, true},
		{true, 1, false},
	} {
		name := fmt.Sprintf("ir/certReqId=%d", tc.certReqID)
		if tc.p10cr {
			name = fmt.Sprintf("p10cr/certReqId=%d", tc.certReqID)
		}
		t.Run(name, func(t *testing.T) {
			var issued *x509.Certificate
			rec := &confirmRecorder{
				issue: func(req *pkicmp.PKIMessage) []byte {
					issued = issueFor(t, ca, requestKey(req))
					return issued.Raw
				},
				adjust: func(rep *pkicmp.CertRepMessage) { rep.Response[0].CertReqID = tc.certReqID },
			}
			ts := rec.serve(t)

			send := sendIR
			if tc.p10cr {
				send = sendP10CR
			}
			result, err := send(t, ts.URL, &caCert)
			statuses := rec.recorded()
			require.Len(t, statuses, 1, "the client must send exactly one certConf")
			assert.Equal(t, tc.certReqID, statuses[0].CertReqID)

			if tc.accepted {
				require.NoError(t, err)
				assert.Equal(t, issued.Raw, result.Certificate.Raw)
				assert.Nil(t, statuses[0].StatusInfo)
				return
			}
			var ce *client.Error
			require.ErrorAs(t, err, &ce)
			assert.Equal(t, fmt.Sprintf("response certReqId %d does not match the request", tc.certReqID), ce.Op)
			assert.NotContains(t, err.Error(), "rejection not confirmed")
			require.NotNil(t, statuses[0].StatusInfo)
			assert.Equal(t, pkicmp.StatusRejection, statuses[0].StatusInfo.Status)
			assert.Equal(t, pkicmp.PKIFreeText{"certReqId does not match the request"}, statuses[0].StatusInfo.StatusString)
		})
	}
}

// The client requests one certificate, so a response with several
// CertResponse entries is refused rather than read from its first entry.
func TestMultipleCertResponsesRefused(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	rec := &confirmRecorder{
		issue: func(req *pkicmp.PKIMessage) []byte { return issueFor(t, ca, requestKey(req)).Raw },
		adjust: func(rep *pkicmp.CertRepMessage) {
			extra := rep.Response[0]
			extra.CertReqID = 1
			rep.Response = append(rep.Response, extra)
		},
	}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &caCert)
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "response carries 2 CertResponse entries for one request", ce.Op)
	assert.Empty(t, rec.recorded())
}

// A rejection is reported with the CA's status whatever certReqId it carries,
// since a CA that could not read the request may not know the value.
func TestRejectionReportedWithAnyCertReqID(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=issuing-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	rec := &confirmRecorder{
		issue: func(*pkicmp.PKIMessage) []byte { return nil },
		adjust: func(rep *pkicmp.CertRepMessage) {
			rep.Response[0] = pkicmp.CertResponse{
				CertReqID: -1,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadPOP},
			}
		},
	}
	ts := rec.serve(t)

	_, err = sendIR(t, ts.URL, &caCert)
	require.Error(t, err)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailBadPOP), "got %v", err)
	assert.Empty(t, rec.recorded())
}

// A waiting response under another certReqId is refused without polling for it.
func TestWaitingCertReqIDMismatchRefused(t *testing.T) {
	rec := &confirmRecorder{
		issue: func(*pkicmp.PKIMessage) []byte { return nil },
		adjust: func(rep *pkicmp.CertRepMessage) {
			rep.Response[0] = pkicmp.CertResponse{CertReqID: 1, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}}
		},
	}
	ts := rec.serve(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(ts.URL, client.WithMaxPolls(1), client.WithCheckAfterLimits(time.Millisecond, time.Millisecond))
	_, err = c.SendIR(context.Background(), key, creds, client.WithSenderKID([]byte("test")), client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "response certReqId 1 does not match the request", ce.Op)
	assert.Empty(t, rec.recorded())
}
