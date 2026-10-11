package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// certStatus returns a CertStatus for cert with certReqID, rejecting the certificate when reject is set.
func certStatus(t *testing.T, cert *x509.Certificate, certReqID int64, reject bool) pkicmp.CertStatus {
	t.Helper()
	status, err := pkicmp.NewCertStatus(cert, certReqID)
	require.NoError(t, err)
	if reject {
		status.StatusInfo = &pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection}
	}
	return status
}

// sendCertConf posts a MAC-protected certConf with statuses in the transaction resp belongs to.
func sendCertConf(t *testing.T, ts *httptest.Server, resp *pkicmp.PKIMessage, secret []byte, statuses ...pkicmp.CertStatus) *pkicmp.PKIMessage {
	t.Helper()
	conf := pkicmp.CertConfirmContent(statuses)
	msg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&conf), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: resp.Header.TransactionID,
		RecipNonce:    resp.Header.SenderNonce,
	})
	protectMAC(msg, secret)
	return postCMP(t, ts, msg)
}

// enrollForCertConf sends an ir, or a p10cr when p10cr is set, and returns the response and the issued certificate.
func enrollForCertConf(t *testing.T, ts *httptest.Server, secret []byte, p10cr bool) (*pkicmp.PKIMessage, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	body := pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "certconf-ir")})
	if p10cr {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "certconf-p10cr"}}, key)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		body = pkicmp.NewP10CRBody(csr)
	}
	req := pkicmp.NewPKIMessage(body, macMessageOpts())
	protectMAC(req, secret)
	resp := postCMP(t, ts, req)
	return resp, issuedCertificate(t, resp)
}

// newConfirmingServer serves a CA that records every confirmation it receives.
func newConfirmingServer(t *testing.T, secret []byte, opts ...server.Option) (*httptest.Server, *confirmingCA) {
	t.Helper()
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	opts = append(opts, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), opts...))
	t.Cleanup(ts.Close)
	return ts, ca
}

// RFC 9810 §5.3.18: each CertStatus reaches the CA as a verdict on the issued
// certificate, so every entry must name it and the entries must agree.
func TestCertConfEveryStatusNamesIssuedCertificate(t *testing.T) {
	secret := []byte("certconf-status-secret")

	t.Run("an unchecked extra entry is rejected and the transaction kept", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		ip, cert := enrollForCertConf(t, ts, secret, false)
		bogus := certStatus(t, cert, 0, true)
		bogus.CertHash = []byte("not-a-real-hash")

		status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false), bogus))
		assert.Equal(t, pkicmp.FailBadCertId, status.FailInfo)
		assert.Empty(t, ca.statuses)

		resp := sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false))
		assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
		assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
	})

	t.Run("a certReqId the response did not carry is rejected", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		ip, cert := enrollForCertConf(t, ts, secret, false)
		status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 1, false)))
		assert.Equal(t, pkicmp.FailBadCertId, status.FailInfo)
		assert.Empty(t, ca.statuses)
	})

	t.Run("entries that disagree are rejected", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		ip, cert := enrollForCertConf(t, ts, secret, false)
		status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false), certStatus(t, cert, 0, true)))
		assert.Equal(t, pkicmp.FailBadRequest, status.FailInfo)
		assert.Empty(t, ca.statuses)
	})

	t.Run("repeated entries confirm once", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		ip, cert := enrollForCertConf(t, ts, secret, false)
		resp := sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, true), certStatus(t, cert, 0, true))
		assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
		assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, ca.statuses)
	})

	t.Run("strict profile validation allows one entry", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret, server.WithStrictProfileValidation())
		ip, cert := enrollForCertConf(t, ts, secret, false)
		status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false), certStatus(t, cert, 0, false)))
		assert.Equal(t, pkicmp.FailBadRequest, status.FailInfo)
		assert.Empty(t, ca.statuses)
	})
}

// RFC 9810 answers a p10cr with certReqId -1, but RFC 9483 §4.1.4 keeps 0 for
// its certConf and EJBCA uses 0, so a p10cr certConf may carry either value
// with or without strict profile validation.
func TestP10CRCertConfAcceptsZeroAndMinusOne(t *testing.T) {
	secret := []byte("p10cr-certconf-secret")
	for _, strict := range []bool{false, true} {
		for _, certReqID := range []int64{-1, 0} {
			t.Run(fmt.Sprintf("strict=%t/certReqId=%d", strict, certReqID), func(t *testing.T) {
				var opts []server.Option
				if strict {
					opts = append(opts, server.WithStrictProfileValidation())
				}
				ts, ca := newConfirmingServer(t, secret, opts...)
				cp, cert := enrollForCertConf(t, ts, secret, true)
				rep, err := cp.Body.CP()
				require.NoError(t, err)
				require.Equal(t, int64(-1), rep.Response[0].CertReqID, "the cp answers a p10cr with -1")

				resp := sendCertConf(t, ts, cp, secret, certStatus(t, cert, certReqID, false))
				assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
				assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
			})
		}
	}

	t.Run("any other certReqId is rejected", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		cp, cert := enrollForCertConf(t, ts, secret, true)
		status := errorStatus(t, sendCertConf(t, ts, cp, secret, certStatus(t, cert, 1, false)))
		assert.Equal(t, pkicmp.FailBadCertId, status.FailInfo)
		assert.Empty(t, ca.statuses)
	})
}

// A restored transaction keeps its certReqId. One restored from a snapshot
// that predates the field confirms on certHash alone.
func TestSnapshotRestoresCertReqID(t *testing.T) {
	issuer := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Recovery CA"}}
	secret := []byte("certreqid-snapshot-secret")
	fresh := func() *server.Server {
		return server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	}

	first := fresh()
	ts := httptest.NewServer(first)
	ip, cert := enrollForCertConf(t, ts, secret, false)
	ts.Close()
	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)

	restore := func(t *testing.T, data []byte) *httptest.Server {
		t.Helper()
		restored := fresh()
		require.NoError(t, restored.RestoreTransactions(data, nil))
		ts := httptest.NewServer(restored)
		t.Cleanup(ts.Close)
		return ts
	}

	t.Run("the recorded certReqId is checked", func(t *testing.T) {
		ts := restore(t, snapshot)
		status := errorStatus(t, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 1, false)))
		assert.Equal(t, pkicmp.FailBadCertId, status.FailInfo)
		assert.Equal(t, pkicmp.BodyTypePKIConf, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false)).Body.Type)
	})

	t.Run("a snapshot without certReqId skips the check", func(t *testing.T) {
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(snapshot, &decoded))
		entries, ok := decoded["Entries"].([]any)
		require.True(t, ok)
		for _, entry := range entries {
			fields, ok := entry.(map[string]any)
			require.True(t, ok)
			require.Contains(t, fields, "CertReqID")
			delete(fields, "CertReqID")
		}
		older, err := json.Marshal(decoded)
		require.NoError(t, err)

		ts := restore(t, older)
		assert.Equal(t, pkicmp.BodyTypePKIConf, sendCertConf(t, ts, ip, secret, certStatus(t, cert, 1, false)).Body.Type)
	})
}
