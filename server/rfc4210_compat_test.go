package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- builds deprecated SHA-1 signatures that the server must refuse by default
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// oidECDSAWithSHA1 is ecdsa-with-SHA1, which RFC 4210 era devices may still sign with.
var oidECDSAWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

// confirmingCA issues like recordingCA and records every confirmation it receives.
type confirmingCA struct {
	recordingCA
	statuses []server.ConfirmStatus
}

func (c *confirmingCA) ConfirmCertificate(_ context.Context, _ *x509.Certificate, status server.ConfirmStatus, _ any) error {
	c.statuses = append(c.statuses, status)
	return nil
}

// issuedCertificate returns the certificate carried in an ip, cp or kup.
func issuedCertificate(t *testing.T, msg *pkicmp.PKIMessage) *x509.Certificate {
	t.Helper()
	var rep *pkicmp.CertRepMessage
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIP:
		rep, err = msg.Body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = msg.Body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = msg.Body.KUP()
	default:
		t.Fatalf("expected ip, cp or kup, got %s", msg.Body.Type)
	}
	require.NoError(t, err)
	require.Len(t, rep.Response, 1)
	require.NotNil(t, rep.Response[0].CertifiedKeyPair)
	cert, err := rep.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
	require.NoError(t, err)
	return cert
}

// certConfFor builds a certConf accepting cert that continues the transaction resp belongs to.
func certConfFor(t *testing.T, resp *pkicmp.PKIMessage, cert *x509.Certificate, sender pkix.Name) *pkicmp.PKIMessage {
	t.Helper()
	status, err := pkicmp.NewCertStatus(cert, 0)
	require.NoError(t, err)
	return pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{status}), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(sender),
		TransactionID: resp.Header.TransactionID,
		RecipNonce:    resp.Header.SenderNonce,
	})
}

// macProtect applies PasswordBasedMac protection with secret and leaves senderKID as the caller set it.
func macProtect(t *testing.T, msg *pkicmp.PKIMessage, secret []byte) {
	t.Helper()
	creds, err := pkicmp.NewMACCredentials(secret, pkicmp.WithPBM())
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
}

// signWithSHA1 protects msg with ecdsa-with-SHA1 and returns the message as a receiver parses it.
func signWithSHA1(t *testing.T, msg *pkicmp.PKIMessage, key *ecdsa.PrivateKey) *pkicmp.PKIMessage {
	t.Helper()
	msg.Header.ProtectionAlg = &pkicmp.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA1}
	msg.Protection = []byte{0}
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	data, err := parsed.ProtectedData()
	require.NoError(t, err)
	digest := sha1.Sum(data) // #nosec G401 -- the point of the test
	parsed.Protection, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	return parsed
}

// certReqMsgWithSHA1POP builds a request for key whose proof of possession is signed with ecdsa-with-SHA1.
func certReqMsgWithSHA1POP(t *testing.T, key *ecdsa.PrivateKey, subject string) pkicmp.CertReqMsg {
	t.Helper()
	// Round trip a request with an ordinary proof so the parsed CertRequest
	// carries the DER the proof must sign, then replace the proof.
	built := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, subject)}), pkicmp.MessageOptions{})
	der, err := built.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	msgs, err := parsed.Body.IR()
	require.NoError(t, err)
	req := (*msgs)[0]
	digest := sha1.Sum(req.CertReq.Raw) // #nosec G401 -- the point of the test
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	req.Popo.Signature.Algorithm = pkicmp.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA1}
	req.Popo.Signature.Signature = sig
	return req
}

// RFC 4210 §5.1.1 lets a MAC client identify its secret by sender name alone.
// Two such clients with different secrets must not share one transaction
// namespace or quota.
func TestMACCredentialSeparatesNameOnlyClients(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secrets := map[string][]byte{"dev-a": []byte("secret-a"), "dev-b": []byte("secret-b")}
	lookup := server.SecretLookupFunc(func(sender pkix.Name, _ []byte) ([]byte, error) {
		if s, ok := secrets[sender.CommonName]; ok {
			return s, nil
		}
		return nil, errors.New("unknown sender")
	})

	var confirmed []string
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
		handleCertConfirm: func(_ context.Context, confirm *certConfirmation) error {
			confirmed = append(confirmed, confirm.Sender.Sender.CommonName)
			return nil
		},
	}
	srv := server.New(handler, server.WithSecretLookup(lookup), server.WithMaxTransactionsPerCredential(1))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enroll := func(name string) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ir := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, name)}),
			pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(pkix.Name{CommonName: name})},
		)
		macProtect(t, ir, secrets[name])
		require.Empty(t, ir.Header.SenderKID)
		return postCMP(t, ts, ir)
	}

	ipA := enroll("dev-a")
	require.Equal(t, pkicmp.BodyTypeIP, ipA.Body.Type)
	ipB := enroll("dev-b")
	require.Equal(t, pkicmp.BodyTypeIP, ipB.Body.Type, "dev-b has its own transaction quota")

	certA := issuedCertificate(t, ipA)
	crossConf := certConfFor(t, ipA, certA, pkix.Name{CommonName: "dev-b"})
	macProtect(t, crossConf, secrets["dev-b"])
	resp := postCMP(t, ts, crossConf)
	assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type, "dev-b must not confirm dev-a's certificate")
	assert.Empty(t, confirmed)

	ownConf := certConfFor(t, ipA, certA, pkix.Name{CommonName: "dev-a"})
	macProtect(t, ownConf, secrets["dev-a"])
	resp = postCMP(t, ts, ownConf)
	assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
	assert.Equal(t, []string{"dev-a"}, confirmed)
}

// RFC 4210 and RFC 9810 §5.1.1 let a client omit transactionID from its first
// request and have the server assign one.
func TestMissingTransactionIDIsAssigned(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("assigned-transaction-id")

	var seenID []byte
	confirmed := false
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			seenID = req.TransactionID
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
	ir := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "no-transaction-id")}),
		macMessageOpts(),
	)
	ir.Header.TransactionID = nil
	protectMAC(ir, secret)

	ip := postCMP(t, ts, ir)
	require.Equal(t, pkicmp.BodyTypeIP, ip.Body.Type)
	require.Len(t, ip.Header.TransactionID, 16)
	assert.Equal(t, ip.Header.TransactionID, seenID, "the handler sees the assigned transactionID")
	cert := issuedCertificate(t, ip)

	t.Run("a certConf without transactionID is rejected", func(t *testing.T) {
		conf := certConfFor(t, ip, cert, testSender)
		conf.Header.TransactionID = nil
		protectMAC(conf, secret)
		status := errorStatus(t, postCMP(t, ts, conf))
		assert.Equal(t, pkicmp.FailBadDataFormat, status.FailInfo)
		assert.False(t, confirmed)
	})

	t.Run("a certConf with the assigned transactionID completes the transaction", func(t *testing.T) {
		conf := certConfFor(t, ip, cert, testSender)
		protectMAC(conf, secret)
		resp := postCMP(t, ts, conf)
		assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
		assert.True(t, confirmed)
	})
}

// RFC 4210 and RFC 9810 §5.1.1 make senderNonce optional and only typically 128 bits.
func TestShortOrMissingSenderNonceIsAccepted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("short-nonce-secret")

	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{name: "64-bit senderNonce", nonce: []byte("12345678")},
		{name: "no senderNonce", nonce: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			ir := pkicmp.NewPKIMessage(
				pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "short-nonce")}),
				macMessageOpts(),
			)
			ir.Header.SenderNonce = tc.nonce
			protectMAC(ir, secret)

			resp := postCMP(t, ts, ir)
			require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
			assert.Equal(t, len(tc.nonce), len(resp.Header.RecipNonce))
			assert.Equal(t, tc.nonce, resp.Header.RecipNonce)
		})
	}
}

// RFC 4210 and RFC 9810 §5.3.18: an empty certConf rejects every certificate.
func TestEmptyCertConfRejectsCertificate(t *testing.T) {
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	secret := []byte("empty-certconf-secret")
	srv := server.NewCAServer(ca, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ir := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "empty-certconf")}),
		macMessageOpts(),
	)
	protectMAC(ir, secret)
	ip := postCMP(t, ts, ir)
	require.Equal(t, pkicmp.BodyTypeIP, ip.Body.Type)

	empty := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{}), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: ip.Header.TransactionID,
		RecipNonce:    ip.Header.SenderNonce,
	})
	protectMAC(empty, secret)
	resp := postCMP(t, ts, empty)
	assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, ca.statuses)

	// The rejection closes the transaction, so a later acceptance finds nothing.
	conf := certConfFor(t, ip, issuedCertificate(t, ip), testSender)
	protectMAC(conf, secret)
	assert.Equal(t, pkicmp.BodyTypeError, postCMP(t, ts, conf).Body.Type)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmRejected}, ca.statuses)
}

// SHA-1 signatures are refused with badAlg unless WithSHA1Signatures is set,
// in the message protection and in the CRMF proof of possession.
func TestSHA1Signatures(t *testing.T) {
	issuer := &certyaml.Certificate{Subject: "CN=Test CA"}
	clientCert := &certyaml.Certificate{Subject: "CN=legacy-client", Issuer: issuer}
	clientX509, err := clientCert.X509Certificate()
	require.NoError(t, err)
	clientSigner, err := clientCert.PrivateKey()
	require.NoError(t, err)
	clientKey, ok := clientSigner.(*ecdsa.PrivateKey)
	require.True(t, ok, "the test signs with an ECDSA client key")
	secret := []byte("sha1-pop-secret")

	serve := func(t *testing.T, opts ...server.Option) (*httptest.Server, *recordingCA) {
		ca := &recordingCA{ca: issuer}
		opts = append(opts,
			server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}),
			server.WithSecretLookup(&staticMACLookup{secret: secret}),
		)
		ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), opts...))
		t.Cleanup(ts.Close)
		return ts, ca
	}
	sha1ProtectedCR := func(t *testing.T) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		cr := pkicmp.NewPKIMessage(
			pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "legacy-client")}),
			pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(clientX509.RawSubject)},
		)
		return signWithSHA1(t, cr, clientKey)
	}
	sha1POPIR := func(t *testing.T) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ir := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsgWithSHA1POP(t, key, "legacy-pop")}),
			macMessageOpts(),
		)
		protectMAC(ir, secret)
		return ir
	}

	t.Run("protection refused by default", func(t *testing.T) {
		ts, ca := serve(t)
		status := errorStatus(t, postCMP(t, ts, sha1ProtectedCR(t)))
		assert.Equal(t, pkicmp.FailBadAlg, status.FailInfo)
		assert.False(t, ca.called)
	})

	t.Run("protection accepted with WithSHA1Signatures", func(t *testing.T) {
		ts, ca := serve(t, server.WithSHA1Signatures())
		resp := postCMP(t, ts, sha1ProtectedCR(t))
		assert.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
		assert.True(t, ca.called)
	})

	t.Run("proof of possession refused by default", func(t *testing.T) {
		ts, ca := serve(t)
		resp := postCMP(t, ts, sha1POPIR(t))
		assert.Equal(t, pkicmp.FailBadAlg, statusInfoOf(t, resp).FailInfo)
		assert.False(t, ca.called)
	})

	t.Run("proof of possession accepted with WithSHA1Signatures", func(t *testing.T) {
		ts, ca := serve(t, server.WithSHA1Signatures())
		resp := postCMP(t, ts, sha1POPIR(t))
		require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
		assert.Equal(t, pkicmp.StatusAccepted, statusInfoOf(t, resp).Status)
		assert.True(t, ca.called)
	})
}

// A MAC algorithm the server does not implement is reported as badAlg (RFC 9810
// §5.2.3), which tells a legacy client why it failed.
func TestUnsupportedMACAlgorithmIsBadAlg(t *testing.T) {
	secret := []byte("unsupported-mac-secret")
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	oidMD5 := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidHMACWithSHA1 := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	params, err := asn1.Marshal(struct {
		Salt           []byte
		OWF            algID
		IterationCount int
		MAC            algID
	}{make([]byte, 16), algID{Algorithm: oidMD5}, 1000, algID{Algorithm: oidHMACWithSHA1}})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ir := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "md5-owf")}),
		macMessageOpts(),
	)
	protectMAC(ir, secret)
	ir.Header.ProtectionAlg = &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}, Parameters: params}

	status := errorStatus(t, postCMP(t, ts, ir))
	assert.Equal(t, pkicmp.FailBadAlg, status.FailInfo)
}

// A transaction started with a short senderNonce and no senderKID survives a
// snapshot, so a restarted server still accepts its certConf.
func TestSnapshotRestoresLegacyTransaction(t *testing.T) {
	issuer := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Recovery CA"}}
	secret := []byte("legacy-snapshot-secret")
	fresh := func() *server.Server {
		return server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	}

	first := fresh()
	ts := httptest.NewServer(first)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ir := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "legacy-snapshot")}),
		macMessageOpts(),
	)
	ir.Header.SenderNonce = []byte("12345678")
	macProtect(t, ir, secret)
	ip := postCMP(t, ts, ir)
	ts.Close()
	require.Equal(t, pkicmp.BodyTypeIP, ip.Body.Type)

	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)
	restored := fresh()
	require.NoError(t, restored.RestoreTransactions(snapshot, nil))
	ts = httptest.NewServer(restored)
	defer ts.Close()

	conf := certConfFor(t, ip, issuedCertificate(t, ip), testSender)
	macProtect(t, conf, secret)
	assert.Equal(t, pkicmp.BodyTypePKIConf, postCMP(t, ts, conf).Body.Type)
}

// A client using the RFC 4210 Appendix D.2 PasswordBasedMac profile enrolls
// and the server answers with the same profile.
func TestRFC4210PasswordBasedMacEnrollment(t *testing.T) {
	issuer := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	secret := []byte("rfc4210-pbm-secret")
	srv := server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))

	var responseAlgs []*pkicmp.AlgorithmIdentifier
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		if resp, err := pkicmp.ParsePKIMessage(rec.Body.Bytes()); err == nil {
			responseAlgs = append(responseAlgs, resp.Header.ProtectionAlg)
		}
		w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials(secret, pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1))
	require.NoError(t, err)
	result, err := client.NewClient(ts.URL).SendIR(t.Context(), key, creds, client.WithSenderKID([]byte("device")), client.WithTemplateSubject(pkix.Name{CommonName: "legacy.example.test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)

	// The echoed parameters must name SHA-1 and the RFC 4210 HMAC-SHA1 identifier.
	oidSHA1 := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHMACSHA1 := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	require.Len(t, responseAlgs, 2)
	for _, alg := range responseAlgs {
		require.NotNil(t, alg)
		assert.True(t, alg.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}))
		var params struct {
			Salt           []byte
			OWF            pkix.AlgorithmIdentifier
			IterationCount int
			MAC            pkix.AlgorithmIdentifier
		}
		_, err := asn1.Unmarshal(alg.Parameters, &params)
		require.NoError(t, err)
		assert.True(t, params.OWF.Algorithm.Equal(oidSHA1), "OWF %v", params.OWF.Algorithm)
		assert.True(t, params.MAC.Algorithm.Equal(oidHMACSHA1), "MAC %v", params.MAC.Algorithm)
	}
}
