//go:build integration

package openssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestOpenSSLInitialize(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:    "test-ref",
		SrvSecret: "enrollment-secret",
	})

	key := srv.RspKey

	// OpenSSL mock server only supports PBM, not PBMAC1.
	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"), pkicmp.WithPBM())
	require.NoError(t, err)

	// The OpenSSL mock server signs responses with its server certificate even for
	// PBM-protected requests, so WithTrustedCAs is needed for response signature verification.
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test"}),
	)
	require.NoError(t, err, "SendIR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	// The mock server always returns its pre-configured rsp_cert.
	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber, "returned cert serial should match rsp_cert")

	// Verify the certificate is signed by the test CA.
	_, err = result.Certificate.Verify(x509.VerifyOptions{Roots: srv.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate chain verification")

	t.Logf("Issued certificate: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestOpenSSLInitializeWrongSecret(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:    "test-ref",
		SrvSecret: "correct-secret",
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// OpenSSL mock server only supports PBM, not PBMAC1.
	creds, err := pkicmp.NewMACCredentials([]byte("wrong-secret"), pkicmp.WithPBM())
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	_, err = c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-wrong-secret"}),
	)

	// When using wrong secret, the client fails to verify the response protection.
	require.Error(t, err, "SendIR with wrong secret should fail")
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)

	t.Logf("Expected error: %v", err)
}

func TestOpenSSLInitializePolling(t *testing.T) {
	// Skip: OpenSSL mock server bug in crypto/cmp/cmp_server.c, function
	// process_request(), around line 609. The server checks:
	//
	//   if (srv_ctx->polling && req_type != OSSL_CMP_PKIBODY_POLLREQ
	//       && req_type != OSSL_CMP_PKIBODY_ERROR)
	//
	// This rejects certConf with CMP_R_EXPECTED_POLLREQ (status "rejection")
	// because srv_ctx->polling is never reset after delivering the certificate
	// via the final pollReq. The clean_transaction() function in
	// apps/lib/cmp_mock_srv.c only resets curr_pollCount, not the polling flag.
	t.Skip("OpenSSL mock server bug: certConf rejected during polling mode")

	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:     "test-ref",
		SrvSecret:  "enrollment-secret",
		PollCount:  2, // server returns PollRep twice before the cert
		CheckAfter: 1, // suggest 1 second between polls
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"))
	require.NoError(t, err)

	// The client sends the first poll immediately and follows server-provided
	// checkAfter for subsequent polls.
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-polling"}),
	)
	require.NoError(t, err, "SendIR with polling")
	require.NotNil(t, result.Certificate, "no certificate returned after polling")

	t.Logf("Certificate after polling: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestOpenSSLCertify(t *testing.T) {
	// No HMAC opts: signature protection only.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{})

	newKey := srv.RspKey

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	result, err := c.SendCR(context.Background(), newKey, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-certify"}),
	)
	require.NoError(t, err, "SendCR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	// The mock server always returns rsp_cert regardless of the request template.
	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber, "returned cert serial should match rsp_cert")

	// Verify the certificate is issued by the test CA.
	_, err = result.Certificate.Verify(x509.VerifyOptions{Roots: trustedCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate chain verification")

	t.Logf("Certified: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestOpenSSLKeyUpdate(t *testing.T) {
	// No HMAC opts: signature protection only.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{})

	newKey := srv.RspKey

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	result, err := c.SendKUR(context.Background(), newKey, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-keyupdate"}),
	)
	require.NoError(t, err, "SendKUR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	// The mock server always returns rsp_cert regardless of the request template.
	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber, "returned cert serial should match rsp_cert")

	// Verify the certificate is issued by the test CA.
	_, err = result.Certificate.Verify(x509.VerifyOptions{Roots: trustedCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate chain verification")

	t.Logf("Updated key: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestOpenSSLInitializeP10CR(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:    "test-ref",
		SrvSecret: "enrollment-secret",
	})

	key := srv.RspKey

	// Create PKCS#10 CSR.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "openssl-test-p10cr"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// OpenSSL mock server only supports PBM, not PBMAC1.
	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"), pkicmp.WithPBM())
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	result, err := c.SendP10CR(context.Background(), csrDER, creds)
	require.NoError(t, err, "SendP10CR")
	require.NotNil(t, result.Certificate, "no certificate returned")

	// The mock server always returns its pre-configured rsp_cert.
	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber, "returned cert serial should match rsp_cert")

	// Verify the certificate is signed by the test CA.
	_, err = result.Certificate.Verify(x509.VerifyOptions{Roots: srv.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate chain verification")

	t.Logf("Issued certificate via P10CR: %s (serial: %s)", result.Certificate.Subject, result.Certificate.SerialNumber)
}

func TestOpenSSLSpecificFailInfo(t *testing.T) {
	// Configure server to return a specific failure (badAlg = bit 0).
	// Do NOT use SendError: true, as it makes the OpenSSL mock server framework
	// return a generic badRequest error instead of the requested failInfo.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		PKIStatus: new(int(pkicmp.StatusRejection)),
		Failure:   new(0), // badAlg
	})

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Use signature protection (the mock server handles this without needing a secret).
	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	_, err = c.SendCR(context.Background(), newKey, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-failinfo"}),
	)
	require.Error(t, err)

	var statusErr *pkicmp.PKIStatusError
	require.True(t, errors.As(err, &statusErr), "error should be *pkicmp.PKIStatusError, got %T: %v", err, err)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
	assert.True(t, statusErr.FailInfo&pkicmp.FailBadAlg != 0, "FailInfo should have badAlg bit set")

	t.Logf("Expected enrollment failure with FailInfo: %v", err)
}

func TestOpenSSLDynamicPolling(t *testing.T) {
	// Skip: OpenSSL mock server bug in crypto/cmp/cmp_server.c, function
	// process_request(), around line 609. The server checks:
	//
	//   if (srv_ctx->polling && req_type != OSSL_CMP_PKIBODY_POLLREQ
	//       && req_type != OSSL_CMP_PKIBODY_ERROR)
	//
	// This rejects certConf with CMP_R_EXPECTED_POLLREQ (status "rejection")
	// because srv_ctx->polling is never reset after delivering the certificate
	// via the final pollReq. The clean_transaction() function in
	// apps/lib/cmp_mock_srv.c only resets curr_pollCount, not the polling flag.
	t.Skip("OpenSSL mock server bug: certConf rejected during polling mode")

	checkAfter := 2
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:     "test-ref",
		SrvSecret:  "enrollment-secret",
		PollCount:  1,
		CheckAfter: checkAfter,
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"))
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)

	start := time.Now()
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-dynamic-polling"}),
	)
	elapsed := time.Since(start)

	require.NoError(t, err, "SendIR with dynamic polling")
	require.NotNil(t, result.Certificate)

	assert.Equal(t, srv.RspCert.SerialNumber, result.Certificate.SerialNumber, "returned cert serial should match rsp_cert")

	// Verify the certificate is signed by the test CA.
	_, err = result.Certificate.Verify(x509.VerifyOptions{Roots: srv.TrustedCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	assert.NoError(t, err, "certificate chain verification")

	// It should have waited at least checkAfter seconds.
	assert.GreaterOrEqual(t, elapsed, time.Duration(checkAfter)*time.Second, "client should have respected server's checkAfter")

	t.Logf("Polled for %v, certificate: %s", elapsed, result.Certificate.Subject)
}

func TestOpenSSLComplexFailure(t *testing.T) {
	// Configure server to return multiple failure bits and a status string.
	// badAlg (0) | badTime (3) -> bits: 1<<0 | 1<<3 = 1 | 8 = 9.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		PKIStatus:    new(int(pkicmp.StatusRejection)),
		FailureBits:  new(9),
		StatusString: "policy violation: custom test reason",
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	_, err = c.SendCR(context.Background(), key, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-complex"}),
	)
	require.Error(t, err)

	var statusErr *pkicmp.PKIStatusError
	require.True(t, errors.As(err, &statusErr))

	// Verify both bits are reported.
	assert.True(t, statusErr.FailInfo&pkicmp.FailBadAlg != 0)
	assert.True(t, statusErr.FailInfo&pkicmp.FailBadTime != 0)
	assert.Contains(t, err.Error(), "badAlg")
	assert.Contains(t, err.Error(), "badTime")

	// Verify human readable string is preserved.
	assert.Equal(t, "policy violation: custom test reason", statusErr.StatusString)
	assert.Contains(t, err.Error(), "custom test reason")

	t.Logf("Expected complex error: %v", err)
}

func TestOpenSSLGrantedWithMods(t *testing.T) {
	// Status 1 is a success state.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		PKIStatus: new(int(pkicmp.StatusGrantedWithMods)),
	})

	newKey := srv.RspKey

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	result, err := c.SendCR(context.Background(), newKey, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-granted-mods"}),
	)

	// Should NOT return an error.
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)

	t.Logf("Issued with status 1: %s", result.Certificate.Subject)
}

func TestOpenSSLPermanentWaiting(t *testing.T) {
	// Configure server to stay in waiting state.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		PKIStatus:  new(int(pkicmp.StatusWaiting)),
		PollCount:  1, // return pollRep once, then return the waiting IP response.
		CheckAfter: 1,
	})

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)

	trustedCAs := srv.TrustedCAs()
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(trustedCAs),
		client.WithExtraCerts([]*x509.Certificate{srv.ClientCert}),
	)
	_, err = c.SendCR(context.Background(), newKey, creds,
		client.WithSender(srv.ClientCert.Subject),
		client.WithTemplateSubject(pkix.Name{CommonName: "openssl-test-permanent-waiting"}),
	)

	// Should return pkicmp.ErrWaiting.
	require.Error(t, err)
	assert.ErrorIs(t, err, pkicmp.ErrWaiting)

	t.Logf("Expected permanent waiting error: %v", err)
}

func TestOpenSSLInitializeP10CRWrongSecret(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:    "test-ref",
		SrvSecret: "correct-secret",
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create PKCS#10 CSR.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "openssl-test-p10cr-wrong-secret"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// OpenSSL mock server only supports PBM, not PBMAC1.
	creds, err := pkicmp.NewMACCredentials([]byte("wrong-secret"), pkicmp.WithPBM())
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	_, err = c.SendP10CR(context.Background(), csrDER, creds)

	require.Error(t, err, "SendP10CR with wrong secret should fail")
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)

	t.Logf("Expected error: %v", err)
}

func TestOpenSSLRevoke(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{})

	// RFC 9483 §4.2: the request is signed with the certificate being revoked.
	creds, err := pkicmp.NewSignatureCredentials(srv.RspKey, srv.RspCert)
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	err = c.SendRR(context.Background(), srv.RspCert, pkicmp.CRLReasonKeyCompromise, creds)
	require.NoError(t, err, "SendRR")
}

func TestOpenSSLRevokeRejected(t *testing.T) {
	// The mock server answers rr with the configured status in the rp body.
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		PKIStatus: new(int(pkicmp.StatusRejection)),
		Failure:   new(10), // certRevoked
	})

	creds, err := pkicmp.NewSignatureCredentials(srv.RspKey, srv.RspCert)
	require.NoError(t, err)

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	err = c.SendRR(context.Background(), srv.RspCert, pkicmp.CRLReasonSuperseded, creds)
	require.Error(t, err)

	var statusErr *pkicmp.PKIStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
	assert.True(t, pkicmp.HasFailure(err, pkicmp.FailCertRevoked), "FailInfo should have certRevoked bit set")

	t.Logf("Expected revocation failure: %v", err)
}
