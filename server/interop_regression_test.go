package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// postCMP sends a CMP message and returns the parsed response.
func postCMP(t *testing.T, ts *httptest.Server, msg *pkicmp.PKIMessage) *pkicmp.PKIMessage {
	t.Helper()
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(der)))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(body)
	require.NoError(t, err)
	return parsed
}

// newCertReqMsg builds a CertReqMsg with proof of possession for the given key.
func newCertReqMsg(t *testing.T, key *ecdsa.PrivateKey, subject string) pkicmp.CertReqMsg {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	msg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: subject}),
				PublicKey: pubDER,
			},
		},
	}
	require.NoError(t, msg.GeneratePOP(key))
	return msg
}

// Nokia's ssh-cmpclient reuses the senderNonce of its request in the following
// certConf. RFC 9483 §3.5 does not list nonce freshness among the receiver-side
// checks, and rejecting it discards a certificate the CA already issued.
func TestCertConfAcceptsRepeatedSenderNonce(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("repeated-nonce-secret")

	confirmed := false
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(_ context.Context, _ *certConfirmation) error {
			confirmed = true
			return nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	irMsg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "repeated-nonce")}),
		macMessageOpts(),
	)
	protectMAC(irMsg, secret)

	ipMsg := postCMP(t, ts, irMsg)
	require.Equal(t, pkicmp.BodyTypeIP, ipMsg.Body.Type)

	ip, err := ipMsg.Body.IP()
	require.NoError(t, err)
	require.Len(t, ip.Response, 1)
	require.NotNil(t, ip.Response[0].CertifiedKeyPair)
	issued, err := ip.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
	require.NoError(t, err)
	certHash := sha256.Sum256(issued.Raw)

	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{{CertHash: certHash[:], CertReqID: 0}}),
		macMessageOpts(),
	)
	confMsg.Header.TransactionID = irMsg.Header.TransactionID
	confMsg.Header.RecipNonce = ipMsg.Header.SenderNonce
	// The point of the test: repeat the nonce already used for the IR.
	confMsg.Header.SenderNonce = irMsg.Header.SenderNonce
	protectMAC(confMsg, secret)

	confResp := postCMP(t, ts, confMsg)
	assert.Equal(t, pkicmp.BodyTypePKIConf, confResp.Body.Type,
		"a repeated senderNonce must not fail an operation whose certificate is already issued")
	assert.True(t, confirmed)
}

// ssh-cmpclient omits its own certificate from extraCerts and relies on the
// server resolving it. The server authenticates through CertificateLookup, so
// extraCerts is not needed and must not be policed.
func TestSignatureRequestWithoutExtraCertsIsAccepted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	clientCert := &certyaml.Certificate{Subject: "CN=signature-client", Issuer: ca}
	clientX509, err := clientCert.X509Certificate()
	require.NoError(t, err)
	clientKey, err := clientCert.PrivateKey()
	require.NoError(t, err)

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler, server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "cr-subject")}),
		pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(clientX509.RawSubject)},
	)
	creds, err := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	// Protection covers header and body only, so dropping extraCerts afterwards
	// reproduces what ssh-cmpclient puts on the wire without breaking the MAC.
	msg.ExtraCerts = nil

	resp := postCMP(t, ts, msg)
	assert.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type,
		"a signature-protected request without extraCerts must still be served")
}

// A first extraCert that is not the protection certificate must also be served,
// which is what ssh-cmpclient sends when given a trust anchor.
func TestSignatureRequestWithForeignFirstExtraCertIsAccepted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	clientCert := &certyaml.Certificate{Subject: "CN=foreign-first-client", Issuer: ca}
	clientX509, err := clientCert.X509Certificate()
	require.NoError(t, err)
	clientKey, err := clientCert.PrivateKey()
	require.NoError(t, err)

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler, server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "foreign-first")}),
		pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(clientX509.RawSubject)},
	)
	creds, err := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	msg.ExtraCerts = []pkicmp.CMPCertificate{{Raw: caCert.Raw}}

	resp := postCMP(t, ts, msg)
	assert.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type,
		"the server must not require the protection certificate to lead extraCerts")
}

// RFC 9483 §3.3 puts the CMP protection certificate first, and a certificate
// configured through WithExtraCerts must neither displace nor duplicate it.
func TestResponseExtraCertsLeadWithProtectionCertificate(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	signer := &certyaml.Certificate{Subject: "CN=CMP Responder", Issuer: ca}
	signerX509, err := signer.X509Certificate()
	require.NoError(t, err)
	signerKey, err := signer.PrivateKey()
	require.NoError(t, err)

	secret := []byte("extracerts-secret")
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler,
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		// Deliberately configure the certificate the signer already contributes.
		server.WithExtraCerts([]*x509.Certificate{&signerX509, &caCert}),
		server.WithSigner(signerKey, &signerX509),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// An unknown transaction produces a signature-protected error response.
	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{{CertHash: []byte("no-such-cert"), CertReqID: 0}}),
		macMessageOpts(),
	)
	confMsg.Header.RecipNonce = make([]byte, 16)
	protectMAC(confMsg, secret)

	resp := postCMP(t, ts, confMsg)
	require.NotEmpty(t, resp.ExtraCerts)

	first, err := resp.ExtraCerts[0].Parse()
	require.NoError(t, err)
	assert.Equal(t, signerX509.Raw, first.Raw, "the CMP protection certificate must come first")

	counts := map[string]int{}
	for _, ec := range resp.ExtraCerts {
		counts[string(ec.Raw)]++
	}
	for _, count := range counts {
		assert.Equal(t, 1, count, "extraCerts must not repeat a certificate")
	}
}

// RFC 4210 §5.1.1 requires an end entity that does not know its own name to
// send a NULL-DN sender with the reference number in senderKID, which is what
// ssh-cmpclient does for a shared-secret bootstrap enrollment.
func TestMACRequestWithNullDNSenderIsAccepted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("null-dn-sender-secret")

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(server.LightweightPolicy()(handler),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "null-dn-sender")}),
		pkicmp.MessageOptions{},
	)
	msg.Header.SenderKID = []byte("39362")
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	require.Empty(t, msg.Header.Sender.DirectoryName, "the test must send a NULL-DN sender")

	resp := postCMP(t, ts, msg)
	assert.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type,
		"a NULL-DN sender with senderKID identifies the shared secret and must be served")
}

// Neither a sender name nor a senderKID leaves nothing identifying the secret.
func TestMACRequestWithoutSenderOrSenderKIDIsRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("no-identity-secret")

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(server.LightweightPolicy()(handler),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "no-identity")}),
		pkicmp.MessageOptions{},
	)
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))

	resp := postCMP(t, ts, msg)
	assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
}

// WithStrictProfileValidation restores the RFC 9483 construction checks that
// are relaxed by default, so a conformance suite can be run against it.
func TestStrictProfileValidation(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)

	clientCert := &certyaml.Certificate{Subject: "CN=strict-client", Issuer: ca}
	clientX509, err := clientCert.X509Certificate()
	require.NoError(t, err)
	clientKey, err := clientCert.PrivateKey()
	require.NoError(t, err)

	secret := []byte("strict-profile-secret")
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(_ context.Context, _ *certConfirmation) error { return nil },
	}
	srv := server.New(handler,
		server.WithStrictProfileValidation(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// newSignedCR returns a signature-protected CR with the given extraCerts.
	newSignedCR := func(t *testing.T, subject string, extraCerts []pkicmp.CMPCertificate) *pkicmp.PKIMessage {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		msg := pkicmp.NewPKIMessage(
			pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, subject)}),
			pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(clientX509.RawSubject)},
		)
		creds, err := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		msg.ExtraCerts = extraCerts
		return msg
	}

	fullChain := []pkicmp.CMPCertificate{{Raw: clientX509.Raw}, {Raw: caCert.Raw}}

	t.Run("accepts a complete chain led by the protection certificate", func(t *testing.T) {
		resp := postCMP(t, ts, newSignedCR(t, "strict-ok", fullChain))
		assert.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
	})

	t.Run("rejects a request without extraCerts", func(t *testing.T) {
		resp := postCMP(t, ts, newSignedCR(t, "strict-no-extracerts", nil))
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	})

	t.Run("rejects extraCerts not led by the protection certificate", func(t *testing.T) {
		reordered := []pkicmp.CMPCertificate{{Raw: caCert.Raw}, {Raw: clientX509.Raw}}
		resp := postCMP(t, ts, newSignedCR(t, "strict-reordered", reordered))
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	})

	// RFC 9483 section 3.3 recommends leaving self-signed certificates out of extraCerts.
	t.Run("accepts a chain without its self-signed root", func(t *testing.T) {
		resp := postCMP(t, ts, newSignedCR(t, "strict-rootless", fullChain[:1]))
		assert.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
	})

	t.Run("rejects a certificate that does not certify the one before it", func(t *testing.T) {
		other, err := (&certyaml.Certificate{Subject: "CN=Other CA"}).X509Certificate()
		require.NoError(t, err)
		unrelated := []pkicmp.CMPCertificate{{Raw: clientX509.Raw}, {Raw: other.Raw}}
		resp := postCMP(t, ts, newSignedCR(t, "strict-unrelated", unrelated))
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	})

	t.Run("rejects a MAC request with a NULL-DN sender", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		msg := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "strict-null-dn")}),
			pkicmp.MessageOptions{},
		)
		msg.Header.SenderKID = []byte(testSender.String())
		creds, err := pkicmp.NewMACCredentials(secret)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))

		resp := postCMP(t, ts, msg)
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	})

	t.Run("rejects a certConf repeating the request senderNonce", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		irMsg := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "strict-nonce")}),
			macMessageOpts(),
		)
		protectMAC(irMsg, secret)

		ipMsg := postCMP(t, ts, irMsg)
		require.Equal(t, pkicmp.BodyTypeIP, ipMsg.Body.Type)
		ip, err := ipMsg.Body.IP()
		require.NoError(t, err)
		require.Len(t, ip.Response, 1)
		require.NotNil(t, ip.Response[0].CertifiedKeyPair)
		issued, err := ip.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
		require.NoError(t, err)
		certHash := sha256.Sum256(issued.Raw)

		confMsg := pkicmp.NewPKIMessage(
			pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{{CertHash: certHash[:], CertReqID: 0}}),
			macMessageOpts(),
		)
		confMsg.Header.TransactionID = irMsg.Header.TransactionID
		confMsg.Header.RecipNonce = ipMsg.Header.SenderNonce
		confMsg.Header.SenderNonce = irMsg.Header.SenderNonce
		protectMAC(confMsg, secret)

		resp := postCMP(t, ts, confMsg)
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	})

	// newMACIR returns a MAC-protected IR after mutate adjusts its header.
	newMACIR := func(t *testing.T, subject string, mutate func(*pkicmp.PKIHeader)) *pkicmp.PKIMessage {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		msg := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, subject)}),
			macMessageOpts(),
		)
		mutate(&msg.Header)
		protectMAC(msg, secret)
		return msg
	}

	t.Run("rejects a request without transactionID", func(t *testing.T) {
		msg := newMACIR(t, "strict-no-transaction-id", func(h *pkicmp.PKIHeader) { h.TransactionID = nil })
		status := errorStatus(t, postCMP(t, ts, msg))
		assert.Equal(t, pkicmp.FailBadDataFormat, status.FailInfo)
	})

	t.Run("rejects a senderNonce shorter than 128 bits", func(t *testing.T) {
		msg := newMACIR(t, "strict-short-nonce", func(h *pkicmp.PKIHeader) { h.SenderNonce = []byte("12345678") })
		status := errorStatus(t, postCMP(t, ts, msg))
		assert.Equal(t, pkicmp.FailBadSenderNonce, status.FailInfo)
	})

	t.Run("rejects a request without senderNonce", func(t *testing.T) {
		msg := newMACIR(t, "strict-no-nonce", func(h *pkicmp.PKIHeader) { h.SenderNonce = nil })
		status := errorStatus(t, postCMP(t, ts, msg))
		assert.Equal(t, pkicmp.FailBadSenderNonce, status.FailInfo)
	})
}

// TestMessageTimeTolerance enforces badTime only when local policy configures a reliable clock window.
func TestMessageTimeTolerance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name        string
		tolerance   time.Duration
		messageTime time.Time
		wantBadTime bool
	}{
		{name: "disabled by default", messageTime: now.Add(-24 * time.Hour)},
		{name: "current time accepted", tolerance: time.Minute, messageTime: now},
		{name: "absent time accepted", tolerance: time.Minute},
		{name: "old time rejected", tolerance: time.Minute, messageTime: now.Add(-2 * time.Minute), wantBadTime: true},
		{name: "future time rejected", tolerance: time.Minute, messageTime: now.Add(2 * time.Minute), wantBadTime: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ca := &certyaml.Certificate{Subject: "CN=Test CA"}
			caCert, err := ca.X509Certificate()
			require.NoError(t, err)
			secret := []byte("message-time-secret")
			handler := &mockHandler{handleCertRequest: func(_ context.Context, request *certRequest) (*certResponse, error) {
				return &certResponse{Certificate: issueCert(ca, request), CACerts: []*x509.Certificate{&caCert}}, nil
			}}
			options := []server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}
			if test.tolerance != 0 {
				options = append(options, server.WithMessageTimeTolerance(test.tolerance))
			}
			testServer := httptest.NewServer(server.New(handler, options...))
			defer testServer.Close()

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			message := pkicmp.NewPKIMessage(
				pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, test.name)}),
				macMessageOpts(),
			)
			message.Header.MessageTime = test.messageTime
			protectMAC(message, secret)
			response := postCMP(t, testServer, message)

			if !test.wantBadTime {
				assert.Equal(t, pkicmp.BodyTypeIP, response.Body.Type)
				return
			}
			assert.Equal(t, pkicmp.BodyTypeError, response.Body.Type)
			errorContent, err := response.Body.Error()
			require.NoError(t, err)
			assert.NotZero(t, errorContent.PKIStatusInfo.FailInfo&pkicmp.FailBadTime)
		})
	}
}

// An expired certificate left in the CA's store must stop authenticating.
func TestExpiredLookedUpCertificateIsRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	notAfter := time.Now().Add(-1 * time.Hour)
	expired := &certyaml.Certificate{Subject: "CN=expired-client", Issuer: ca, NotAfter: &notAfter}

	expiredX509, err := expired.X509Certificate()
	require.NoError(t, err)
	expiredKey, err := expired.PrivateKey()
	require.NoError(t, err)

	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(expiredX509.RawSubject),
	})
	creds, err := pkicmp.NewSignatureCredentials(expiredKey, &expiredX509)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))

	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(encoded)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{TrustedCert: &expiredX509})
	require.Error(t, err)
	var verr *pkicmp.VerificationError
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, pkicmp.ReasonCertificateExpired, verr.Reason)
}

// A peer must not be able to skip the freshness check by encoding the zero
// GeneralizedTime, which parses to Go's zero time and once looked absent.
func TestZeroMessageTimeIsCheckedAgainstTolerance(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("zero-message-time-secret")
	handler := &mockHandler{handleCertRequest: func(_ context.Context, request *certRequest) (*certResponse, error) {
		return &certResponse{Certificate: issueCert(ca, request), CACerts: []*x509.Certificate{&caCert}}, nil
	}}
	testServer := httptest.NewServer(server.New(handler,
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithMessageTimeTolerance(time.Minute),
	))
	defer testServer.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	message := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "zero-message-time")}),
		macMessageOpts(),
	)
	realTime := time.Now().UTC().Truncate(time.Second)
	message.Header.MessageTime = realTime
	protectMAC(message, secret)
	der, err := message.MarshalBinary()
	require.NoError(t, err)

	// Rewrite the encoded messageTime, then re-protect so the forged value is
	// covered by a MAC the server accepts.
	patched := bytes.Replace(der, []byte(realTime.Format("20060102150405")+"Z"), []byte("00010101000000Z"), 1)
	require.NotEqual(t, der, patched, "messageTime not found in the encoding")
	forged, err := pkicmp.ParsePKIMessage(patched)
	require.NoError(t, err)
	require.True(t, forged.Header.MessageTime.IsZero())
	require.True(t, forged.Header.HasMessageTime(), "presence must survive parsing")
	protectMAC(forged, secret)

	response := postCMP(t, testServer, forged)
	assert.Equal(t, pkicmp.BodyTypeError, response.Body.Type)
	errorContent, err := response.Body.Error()
	require.NoError(t, err)
	assert.NotZero(t, errorContent.PKIStatusInfo.FailInfo&pkicmp.FailBadTime)
}
