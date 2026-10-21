package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

type mockServerConfig struct {
	ca            *certyaml.Certificate
	caCert        *x509.Certificate
	serverKey     crypto.Signer
	serverCert    *x509.Certificate
	wrongCACert   *x509.Certificate
	otherEECert   *x509.Certificate
	respProtector string // "pbm" or "sig" or "pbm-server-secret"
	postProtect   func(req, resp *pkicmp.PKIMessage)
}

// requestedPublicKey returns the public key carried in an enrollment request.
func requestedPublicKey(req *pkicmp.PKIMessage) crypto.PublicKey {
	msgs, err := req.Body.IR()
	if err != nil || msgs == nil || len(*msgs) == 0 {
		return nil
	}
	pub, err := (*msgs)[0].PublicKey()
	if err != nil {
		return nil
	}
	return pub
}

// issueForRequest mints an end-entity certificate for the key the request carried, as a real CA does.
func issueForRequest(issuer *certyaml.Certificate, subject pkix.Name, req *pkicmp.PKIMessage) *x509.Certificate {
	pub := requestedPublicKey(req)
	if pub == nil {
		return nil
	}
	issuerCert, err := issuer.X509Certificate()
	if err != nil {
		return nil
	}
	issuerKey, err := issuer.PrivateKey()
	if err != nil {
		return nil
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &issuerCert, pub, issuerKey)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func setupValidationCerts() mockServerConfig {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	caCert, _ := ca.X509Certificate()

	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverX509, _ := serverCert.X509Certificate()

	otherCA := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherEE := &certyaml.Certificate{Subject: "cn=other-ee", Issuer: otherCA}
	otherEECert, _ := otherEE.X509Certificate()

	wrongCA := &certyaml.Certificate{Subject: "cn=malicious-ca"}
	wrongCACert, _ := wrongCA.X509Certificate()

	return mockServerConfig{
		ca:          ca,
		caCert:      &caCert,
		serverKey:   serverTLS.PrivateKey.(crypto.Signer),
		serverCert:  &serverX509,
		wrongCACert: &wrongCACert,
		otherEECert: &otherEECert,
	}
}

func setupMockServer(cfg mockServerConfig, mutateResp func(req, resp *pkicmp.PKIMessage)) *httptest.Server {
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var eeRaw []byte
		if eeCert := issueForRequest(cfg.ca, pkix.Name{CommonName: "enrolled-ee"}, req); eeCert != nil {
			eeRaw = eeCert.Raw
		}

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
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeRaw}},
					},
				}},
			}),
		}

		if mutateResp != nil {
			mutateResp(req, resp)
		}

		switch cfg.respProtector {
		case "sig":
			{
				_sc, _ := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
				_ = _sc.Protect(resp)
			}
		case "pbm-server-secret":
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("server-secret"))
				_ = _mc.Protect(resp)
			}
		default:
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(resp)
			}
		}

		if cfg.postProtect != nil {
			cfg.postProtect(req, resp)
		}

		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}

	return httptest.NewServer(http.HandlerFunc(handler))
}

func TestCAPubsTrustBootstrap(t *testing.T) {
	recipient := pkix.Name{CommonName: "target-ca"}

	targetCA := &certyaml.Certificate{Subject: "cn=target-ca"}
	targetCACert, _ := targetCA.X509Certificate()

	var eeCert *x509.Certificate

	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var respMsg *pkicmp.PKIMessage
		if callCount == 1 {
			eeCert = issueForRequest(targetCA, pkix.Name{CommonName: "enrolled-ee"}, req)
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: targetCACert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
						},
					}},
				}),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(respMsg)
			}
		} else {
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
			{
				_mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
				_ = _mc.Protect(respMsg)
			}
		}

		der, _ := respMsg.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))

	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.Equal(t, eeCert.SerialNumber, result.Certificate.SerialNumber)

	require.Len(t, result.CAPubs, 1)
	assert.Equal(t, targetCACert.Raw, result.CAPubs[0].Raw)
}

// caPubsServer answers an ir with a certificate from issuer and issuer's certificate in caPubs, both
// MAC-protected with the secret "secret", and a certConf with pkiConf.
func caPubsServer(issuer *certyaml.Certificate) *httptest.Server {
	issuerCert, _ := issuer.X509Certificate()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respBody := pkicmp.NewPKIConfBody()
		if req.Body.Type == pkicmp.BodyTypeIR {
			eeCert := issueForRequest(issuer, pkix.Name{CommonName: "enrolled-ee"}, req)
			respBody = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				CAPubs: []pkicmp.CMPCertificate{{Raw: issuerCert.Raw}},
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
					},
				}},
			})
		}
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: respBody,
		}
		mc, _ := pkicmp.NewMACCredentials([]byte("secret"))
		_ = mc.Protect(resp)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
}

// TestWithoutCAPubsTrust checks that the option keeps caPubs of a MAC-protected response from
// trusting an issuer outside the configured trusted CAs.
func TestWithoutCAPubsTrust(t *testing.T) {
	pinned := &certyaml.Certificate{Subject: "cn=pinned-ca"}
	pinnedCert, _ := pinned.X509Certificate()
	other := &certyaml.Certificate{Subject: "cn=other-ca"}

	tests := []struct {
		name    string
		issuer  *certyaml.Certificate
		opts    []client.Option
		wantErr bool
	}{
		{"default trusts caPubs", other, nil, false},
		{"caPubs CA not trusted", other, []client.Option{client.WithoutCAPubsTrust()}, true},
		{"issuer among the trusted CAs", pinned, []client.Option{client.WithoutCAPubsTrust()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := caPubsServer(tt.issuer)
			defer server.Close()

			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			creds, err := pkicmp.NewMACCredentials([]byte("secret"))
			require.NoError(t, err)
			trusted := x509.NewCertPool()
			trusted.AddCert(&pinnedCert)
			c := client.NewClient(server.URL, append([]client.Option{client.WithTrustedCAs(trusted)}, tt.opts...)...)

			result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
			if tt.wantErr {
				var ce *client.Error
				require.ErrorAs(t, err, &ce)
				assert.Equal(t, "verify certificate trust", ce.Op)
				return
			}
			require.NoError(t, err)
			issuerCert, _ := tt.issuer.X509Certificate()
			require.Len(t, result.CAPubs, 1)
			assert.Equal(t, issuerCert.Raw, result.CAPubs[0].Raw)
		})
	}
}

func TestResponseValidationRejectsMismatchedIssuer(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		ipBody, _ := resp.Body.IP()
		ipBody.CAPubs = []pkicmp.CMPCertificate{{Raw: cfg.wrongCACert.Raw}}
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithRecipient(pkix.Name{CommonName: "target-ca"}))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
}

func TestResponseValidationRejectsMismatchedTransactionID(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		resp.Header.TransactionID = []byte("evil-transaction-id")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify response", ce.Op)
	var inner *client.Error
	require.ErrorAs(t, ce.Err, &inner)
	assert.Equal(t, "transaction ID mismatch", inner.Op)
}

func TestResponseValidationRejectsMismatchedNonce(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		resp.Header.RecipNonce = []byte("evil-nonce")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify response", ce.Op)
	var inner *client.Error
	require.ErrorAs(t, ce.Err, &inner)
	assert.Equal(t, "recipient nonce mismatch", inner.Op)
}

func TestResponseValidationRejectsInvalidMAC(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.postProtect = func(req, resp *pkicmp.PKIMessage) {
		resp.Protection[0] ^= 0xFF
	}
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestResponseValidationRejectsInvalidSignature(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	cfg.postProtect = func(req, resp *pkicmp.PKIMessage) {
		resp.Protection[0] ^= 0xFF
	}
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Signature credentials, because a client that started the operation with a
	// shared secret now refuses a signature-protected response outright and would
	// never reach the signature check.
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonSignatureFailed, ve.Reason)
}

func TestResponseValidationRejectsUntrustedCA(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		ipBody, _ := resp.Body.IP()
		ipBody.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate = &pkicmp.CMPCertificate{Raw: cfg.otherEECert.Raw}
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.Contains(t, ce.Err.Error(), "certificate signed by unknown authority")
}

func TestResponseValidationRejectsSignatureWithoutTrustedCAs(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)
}

func TestResponseValidationRejectsPBMResponseWithoutSecret(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "pbm-server-secret"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	// Signature protection for request, but response uses PBM with unknown secret.
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	// The client holds no shared secret, so there is nothing to verify the MAC with.
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingSharedSecret, ve.Reason)
}

// A caller that pins signature protection refuses a MAC-protected response
// before the missing shared secret is ever relevant.
func TestResponseValidationRejectsMACResponseWhenSignaturePinned(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "pbm-server-secret"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	c := client.NewClient(
		server.URL,
		client.WithTrustedCAs(trustedCAs),
		client.WithResponseProtection(pkicmp.ProtectionSignature),
	)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonUnexpectedProtection, ve.Reason)
}

// A certificate issued for a key the client does not hold is unusable, and the
// substitution would otherwise surface far away from this exchange.
func TestResponseValidationRejectsCertificateForDifferentKey(t *testing.T) {
	cfg := setupValidationCerts()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		caCert, _ := cfg.ca.X509Certificate()
		caKey, _ := cfg.ca.PrivateKey()
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "enrolled-ee"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, &caCert, &otherKey.PublicKey, caKey)
		ipBody, _ := resp.Body.IP()
		ipBody.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate = &pkicmp.CMPCertificate{Raw: der}
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "does not certify the requested public key")
}

// A caller that pins MAC protection must not accept a signature-protected
// response, even when it also configured trust anchors for validating the
// issued certificate.
func TestResponseValidationRejectsProtectionMechanismSwitch(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(
		server.URL,
		client.WithTrustedCAs(trustedCAs),
		client.WithResponseProtection(pkicmp.ProtectionMAC),
	)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonUnexpectedProtection, ve.Reason)
}

// A CA may authenticate a shared-secret request and answer with a signature,
// which is a supported configuration in deployed CAs, so the default must not
// reject it.
func TestResponseValidationAcceptsSignedResponseToMACRequestByDefault(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=mixed-protection-ca"}
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
		extraCertsOnPKIConf: []*x509.Certificate{&cmpSignerCert},
		protect:             signatureProtector(cmpSignerTLS.PrivateKey.(crypto.Signer), &cmpSignerCert),
	}
	server := exchange.start(t)

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(&caCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
}

// A response whose senderKID names none of its certificates is refused by default and accepted with
// WithSenderKIDMismatch, as some CAs copy the senderKID of the request into their responses.
func TestResponseValidationMismatchedSenderKID(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		if req.Body.Type == pkicmp.BodyTypeCertConf {
			resp.Body = pkicmp.NewPKIConfBody()
		}
		resp.Header.Sender = pkicmp.NewDirectoryName(pkix.Name{CommonName: "cmp-server"})
		resp.Header.SenderKID = []byte("wrong-sender-kid")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)

	c := client.NewClient(
		server.URL,
		client.WithTrustedCAs(trustedCAs),
		client.WithRecipient(pkix.Name{CommonName: "cmp-server"}),
	)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	// No certificate carries the key the senderKID names, so none is tried.
	assert.Equal(t, pkicmp.ReasonSenderKIDMismatch, ve.Reason)
	assert.ErrorContains(t, err, "WithSenderKIDMismatch")

	// The response is signed by the certificate it carries, which the option lets the client try.
	c = client.NewClient(
		server.URL,
		client.WithTrustedCAs(trustedCAs),
		client.WithRecipient(pkix.Name{CommonName: "cmp-server"}),
		client.WithSenderKIDMismatch(),
	)
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
}

func TestResponseValidationRejectsOversizedHTTPResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(make([]byte, 129))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(128))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "response body too large")
}

func TestResponseValidationCustomResponseLimitAllowsSmallResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write([]byte{0x00})
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(1024))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var pe *pkicmp.ParseError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Detail, "invalid PKIMessage sequence")
}
