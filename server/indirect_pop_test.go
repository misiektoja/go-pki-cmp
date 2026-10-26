package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// popConfirmation is one ConfirmCertificate call that popCA received.
type popConfirmation struct {
	status server.ConfirmStatus
	method server.POPMethod
}

// popCA certifies RSA, ECDSA and ML-KEM keys for encryption and records the
// proof-of-possession method of every call. With delay set it answers each
// request with a waiting response first and issues on the poll.
type popCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	delay bool

	mu            sync.Mutex
	issueMethods  []server.POPMethod
	confirmations []popConfirmation
	waiting       map[string]*x509.Certificate
}

// newPOPCA creates a self-signed ECDSA CA.
func newPOPCA(t *testing.T) *popCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "POP test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &popCA{cert: cert, key: key, waiting: map[string]*x509.Certificate{}}
}

// IssueCertificate certifies the requested key for key encipherment or key agreement.
func (c *popCA) IssueCertificate(ctx context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	c.issueMethods = append(c.issueMethods, server.POPMethodFromContext(ctx))
	c.mu.Unlock()

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageKeyEncipherment
	if _, ok := tmpl.PublicKey.(*ecdsa.PublicKey); ok {
		tmpl.KeyUsage = x509.KeyUsageKeyAgreement
	}
	var der []byte
	if pkicmp.IsKEMKey(tmpl.PublicKey) {
		spki, err := pkicmp.MarshalPublicKey(tmpl.PublicKey)
		if err != nil {
			return nil, err
		}
		der, err = kemcert.CreateCertificate(tmpl, c.cert, spki, c.key)
		if err != nil {
			return nil, err
		}
	} else {
		der, err = x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
		if err != nil {
			return nil, err
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if c.delay {
		c.mu.Lock()
		defer c.mu.Unlock()
		ref := serial.String()
		c.waiting[ref] = cert
		return &server.Response{Waiting: &server.WaitingResponse{PollRef: ref}}, nil
	}
	return &server.Response{Certificate: cert, CACerts: []*x509.Certificate{c.cert}}, nil
}

// CheckPending returns the certificate held back for pollRef.
func (c *popCA) CheckPending(ctx context.Context, pollRef string, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issueMethods = append(c.issueMethods, server.POPMethodFromContext(ctx))
	return &server.Response{Certificate: c.waiting[pollRef], CACerts: []*x509.Certificate{c.cert}}, nil
}

// ConfirmCertificate records the confirmation status and the proof-of-possession method.
func (c *popCA) ConfirmCertificate(ctx context.Context, _ *x509.Certificate, status server.ConfirmStatus, _ any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.confirmations = append(c.confirmations, popConfirmation{status: status, method: server.POPMethodFromContext(ctx)})
	return nil
}

// recorded returns copies of the methods and confirmations seen so far.
func (c *popCA) recorded() ([]server.POPMethod, []popConfirmation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]server.POPMethod(nil), c.issueMethods...), append([]popConfirmation(nil), c.confirmations...)
}

// popKey is a requested key and the private key that decrypts for it.
type popKey struct {
	name string
	pub  crypto.PublicKey
	priv any
	// agreement asks with the keyAgreement variant of popo.
	agreement bool
}

// popKeys returns one key of every type the server can encrypt for.
func popKeys(t *testing.T) []popKey {
	t.Helper()
	kem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	kem1024, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return []popKey{
		{name: "ML-KEM-768", pub: kem768.EncapsulationKey(), priv: kem768},
		{name: "ML-KEM-1024", pub: kem1024.EncapsulationKey(), priv: kem1024},
		{name: "RSA", pub: &rsaKey.PublicKey, priv: rsaKey},
		{name: "ECDH P-256", pub: &p256.PublicKey, priv: p256, agreement: true},
		{name: "ECDH P-384", pub: &p384.PublicKey, priv: p384, agreement: true},
	}
}

// indirectPOPRequest builds an ir for key that proves possession with the subsequentMessage method.
func indirectPOPRequest(t *testing.T, key popKey, method int64, implicit bool) *pkicmp.PKIMessage {
	t.Helper()
	pubDER, err := pkicmp.MarshalPublicKey(key.pub)
	require.NoError(t, err)
	req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
		Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "indirect " + key.name}),
		PublicKey: pubDER,
	}}}
	if key.agreement {
		req.Popo = pkicmp.NewKeyAgreementPOP(&method)
	} else {
		req.Popo = pkicmp.NewKeyEnciphermentPOP(&method)
	}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), macMessageOpts())
	if implicit {
		msg.Header.GeneralInfo = append(msg.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	return msg
}

// followUp builds the next message of the transaction that prev answered.
func followUp(body *pkicmp.PKIBody, prev *pkicmp.PKIMessage) *pkicmp.PKIMessage {
	opts := macMessageOpts()
	opts.TransactionID = prev.Header.TransactionID
	opts.RecipNonce = prev.Header.SenderNonce
	return pkicmp.NewPKIMessage(body, opts)
}

// exchange MAC-protects msg with secret, posts it and returns the response.
func exchange(t *testing.T, ts *httptest.Server, msg *pkicmp.PKIMessage, secret []byte) *pkicmp.PKIMessage {
	t.Helper()
	protectMAC(msg, secret)
	return postCMP(t, ts, msg)
}

// popCertConf builds a certConf that accepts cert, or names a wrong hash with badHash.
func popCertConf(t *testing.T, cert *x509.Certificate, badHash bool, prev *pkicmp.PKIMessage) *pkicmp.PKIMessage {
	t.Helper()
	status := pkicmp.CertStatus{CertReqID: 0}
	hash, err := status.CertificateHash(cert)
	require.NoError(t, err)
	if badHash {
		hash[0] ^= 0xff
	}
	status.CertHash = hash
	return followUp(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{status}), prev)
}

// grantsImplicit reports whether a response grants implicit confirmation.
func grantsImplicit(msg *pkicmp.PKIMessage) bool {
	for _, info := range msg.Header.GeneralInfo {
		if info.InfoType.Equal(pkicmp.ImplicitConfirmInfoValue().InfoType) {
			return true
		}
	}
	return false
}

// decryptIssued returns the certificate in the ip resp, decrypting it for key.
func decryptIssued(t *testing.T, resp *pkicmp.PKIMessage, key popKey) *x509.Certificate {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type, "%+v", statusInfoOf(t, resp))
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	require.Equal(t, pkicmp.StatusAccepted, rep.Response[0].Status.Status)
	ckp := rep.Response[0].CertifiedKeyPair
	require.NotNil(t, ckp)
	assert.Nil(t, ckp.CertOrEncCert.Certificate, "the certificate must not travel in plaintext")
	var der []byte
	if value := ckp.CertOrEncCert.EncryptedValueCertificate(); value != nil {
		der, err = cms.DecryptEncryptedValue(value, key.priv)
	} else {
		envelope := ckp.CertOrEncCert.EncryptedCertificate()
		require.NotNil(t, envelope)
		der, err = cms.Decrypt(envelope, key.priv)
	}
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	assert.True(t, pkicmp.PublicKeysEqual(pub, key.pub), "the certificate certifies the requested key")
	return cert
}

// encryptedForm names the EncryptedKey choice that carries the certificate of the ip resp.
func encryptedForm(t *testing.T, resp *pkicmp.PKIMessage) string {
	t.Helper()
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	certOrEncCert := rep.Response[0].CertifiedKeyPair.CertOrEncCert
	switch {
	case certOrEncCert.EncryptedValueCertificate() != nil:
		return "EncryptedValue"
	case certOrEncCert.EncryptedCertificate() != nil:
		return "EnvelopedData"
	default:
		return "plaintext"
	}
}

// answerChallenge decrypts the popdecc resp for key, checks its witness and sender, and returns the popdecr.
func answerChallenge(t *testing.T, resp *pkicmp.PKIMessage, key popKey) *pkicmp.PKIMessage {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypePopDecC, resp.Body.Type)
	challenges, err := resp.Body.PopDecC()
	require.NoError(t, err)
	require.Len(t, *challenges, 1)
	ch := (*challenges)[0]
	require.NotNil(t, ch.OWF)
	content, err := cms.Decrypt(ch.EncryptedRand, key.priv)
	require.NoError(t, err)
	r, err := pkicmp.ParseRand(content)
	require.NoError(t, err)
	assert.Equal(t, pkicmp.ChallengeWitness(crypto.SHA256, r.Int), ch.Witness)
	assert.Equal(t, fmt.Sprint(resp.Header.Sender), fmt.Sprint(r.Sender), "Rand names the popdecc sender")
	return followUp(pkicmp.NewPopDecRBody(&pkicmp.POPODecKeyRespContent{r.Int}), resp)
}

// The certificate is encrypted for its key and confirmed by the certConf. A
// pvno 2 request for an RSA key gets the EncryptedValue of CMP version 2.
// EnvelopedData is cmp2021 syntax and raises the response to pvno 3, which is
// the only form other keys can take.
func TestEncryptedCertificatePOP(t *testing.T) {
	secret := []byte("encrypted-certificate-pop")
	for _, pvno := range []int{pkicmp.PVNO2, pkicmp.PVNO3} {
		for _, key := range popKeys(t) {
			t.Run(fmt.Sprintf("pvno %d/%s", pvno, key.name), func(t *testing.T) {
				testEncryptedCertificatePOP(t, secret, key, pvno)
			})
		}
	}
}

// testEncryptedCertificatePOP enrolls key with an encrypted certificate in a request of version pvno.
func testEncryptedCertificatePOP(t *testing.T, secret []byte, key popKey, pvno int) {
	ca := newPOPCA(t)
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithEncryptedCertificatePOP(),
		server.WithImplicitConfirm(),
	))
	defer ts.Close()

	// Implicit confirmation is asked for and allowed, but the certConf is the proof.
	ir := indirectPOPRequest(t, key, pkicmp.SubsequentMessageEncrCert, true)
	ir.Header.PVNO = pvno
	ip := exchange(t, ts, ir, secret)
	cert := decryptIssued(t, ip, key)
	assert.False(t, grantsImplicit(ip), "an encrypted certificate needs an explicit certConf")
	if _, isRSA := key.pub.(*rsa.PublicKey); isRSA && pvno == pkicmp.PVNO2 {
		assert.Equal(t, "EncryptedValue", encryptedForm(t, ip))
		assert.Equal(t, pkicmp.PVNO2, ip.Header.PVNO)
	} else {
		assert.Equal(t, "EnvelopedData", encryptedForm(t, ip))
		assert.Equal(t, pkicmp.PVNO3, ip.Header.PVNO)
	}

	methods, confirmations := ca.recorded()
	assert.Equal(t, []server.POPMethod{server.POPEncryptedCertificate}, methods)
	assert.Empty(t, confirmations, "nothing is confirmed before the certConf")

	conf := exchange(t, ts, popCertConf(t, cert, false, ip), secret)
	require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type, "%+v", conf.Body.Type)
	_, confirmations = ca.recorded()
	assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPEncryptedCertificate}}, confirmations)
}

// WithEnvelopedDataForVersion2 sends EnvelopedData and a pvno 3 response to a
// pvno 2 request for an RSA key, for clients that read only EnvelopedData.
func TestEnvelopedDataForVersion2(t *testing.T) {
	secret := []byte("enveloped-data-version-2")
	for _, key := range popKeys(t) {
		t.Run(key.name, func(t *testing.T) {
			ca := newPOPCA(t)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithEncryptedCertificatePOP(),
				server.WithEnvelopedDataForVersion2(),
			))
			defer ts.Close()

			ir := indirectPOPRequest(t, key, pkicmp.SubsequentMessageEncrCert, false)
			ir.Header.PVNO = pkicmp.PVNO2
			ip := exchange(t, ts, ir, secret)
			cert := decryptIssued(t, ip, key)
			assert.Equal(t, "EnvelopedData", encryptedForm(t, ip))
			assert.Equal(t, pkicmp.PVNO3, ip.Header.PVNO)

			conf := exchange(t, ts, popCertConf(t, cert, false, ip), secret)
			require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type, "%+v", conf.Body.Type)
			_, confirmations := ca.recorded()
			assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPEncryptedCertificate}}, confirmations)
		})
	}
}

// A wrong hash fails the proof and keeps the transaction, so a right certConf
// can still follow and a certificate that gets none expires unconfirmed.
func TestEncryptedCertificateWrongHash(t *testing.T) {
	secret := []byte("encrypted-certificate-wrong-hash")
	key := popKeys(t)[0]
	newServer := func(t *testing.T, confirmWait time.Duration) (*server.Server, *httptest.Server, *popCA) {
		t.Helper()
		ca := newPOPCA(t)
		srv := server.NewCAServer(ca, server.LightweightPolicy(),
			server.WithSecretLookup(&staticMACLookup{secret: secret}),
			server.WithEncryptedCertificatePOP(),
			server.WithConfirmWaitTime(confirmWait),
		)
		ts := httptest.NewServer(srv)
		t.Cleanup(ts.Close)
		return srv, ts, ca
	}

	t.Run("a right certConf follows", func(t *testing.T) {
		_, ts, ca := newServer(t, time.Minute)
		ip := exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageEncrCert, false), secret)
		cert := decryptIssued(t, ip, key)

		resp := exchange(t, ts, popCertConf(t, cert, true, ip), secret)
		si := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
		_, confirmations := ca.recorded()
		assert.Empty(t, confirmations)

		conf := exchange(t, ts, popCertConf(t, cert, false, ip), secret)
		assert.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
		_, confirmations = ca.recorded()
		assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPEncryptedCertificate}}, confirmations)
	})

	t.Run("no certConf follows", func(t *testing.T) {
		// The sleep outlasts the confirm wait whatever the load, so the expiry
		// is not racing a certConf. Its refusal is covered above.
		srv, ts, ca := newServer(t, time.Millisecond)
		ip := exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageEncrCert, false), secret)
		decryptIssued(t, ip, key)

		time.Sleep(10 * time.Millisecond)
		srv.CleanupExpired()
		_, confirmations := ca.recorded()
		assert.Equal(t, []popConfirmation{{server.ConfirmExpired, server.POPEncryptedCertificate}}, confirmations)
	})
}

// A waiting request delivers the encrypted certificate on the poll that
// collects it, in the form the version of the pollReq allows.
func TestEncryptedCertificatePOPAfterPolling(t *testing.T) {
	secret := []byte("encrypted-certificate-poll")
	keys := popKeys(t)
	for _, tc := range []struct {
		key  popKey
		form string
	}{
		{keys[0], "EnvelopedData"},
		{keys[2], "EncryptedValue"},
	} {
		t.Run(tc.key.name, func(t *testing.T) {
			ca := newPOPCA(t)
			ca.delay = true
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithEncryptedCertificatePOP(),
			))
			defer ts.Close()

			waiting := exchange(t, ts, indirectPOPRequest(t, tc.key, pkicmp.SubsequentMessageEncrCert, false), secret)
			require.Equal(t, pkicmp.StatusWaiting, statusInfoOf(t, waiting).Status)

			ip := exchange(t, ts, followUp(pkicmp.NewPollReqBody(&pkicmp.PollReqContent{0}), waiting), secret)
			cert := decryptIssued(t, ip, tc.key)
			assert.Equal(t, tc.form, encryptedForm(t, ip))
			conf := exchange(t, ts, popCertConf(t, cert, false, ip), secret)
			require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)

			methods, confirmations := ca.recorded()
			assert.Equal(t, []server.POPMethod{server.POPEncryptedCertificate, server.POPEncryptedCertificate}, methods)
			assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPEncryptedCertificate}}, confirmations)
		})
	}
}

func TestChallengeResponsePOP(t *testing.T) {
	secret := []byte("challenge-response-pop")
	for _, key := range popKeys(t) {
		t.Run(key.name, func(t *testing.T) {
			ca := newPOPCA(t)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithChallengeResponsePOP(),
				server.WithImplicitConfirm(),
			))
			defer ts.Close()

			popdecc := exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageChallengeResp, true), secret)
			methods, _ := ca.recorded()
			assert.Empty(t, methods, "the CA sees the request only after the proof")

			popdecr := answerChallenge(t, popdecc, key)
			ip := exchange(t, ts, popdecr, secret)
			requirePlaintextCertificate(t, ip)
			assert.Equal(t, popdecr.Header.SenderNonce, ip.Header.RecipNonce, "the ip answers the popdecr")
			assert.True(t, grantsImplicit(ip), "possession is proven, so implicit confirmation is allowed")

			methods, confirmations := ca.recorded()
			assert.Equal(t, []server.POPMethod{server.POPChallengeResponse}, methods)
			assert.Equal(t, []popConfirmation{{server.ConfirmImplicit, server.POPChallengeResponse}}, confirmations)
		})
	}
}

// requirePlaintextCertificate checks that resp is an ip that accepts the request with a plaintext certificate.
func requirePlaintextCertificate(t *testing.T, resp *pkicmp.PKIMessage) {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	require.Equal(t, pkicmp.StatusAccepted, rep.Response[0].Status.Status, "%+v", rep.Response[0].Status)
	require.NotNil(t, rep.Response[0].CertifiedKeyPair)
	require.NotNil(t, rep.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate, "the proven key gets a plaintext certificate")
}

// A wrong answer ends the transaction with badPOP before the CA sees the request.
func TestChallengeResponseWrongAnswer(t *testing.T) {
	secret := []byte("challenge-response-wrong-answer")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithChallengeResponsePOP(),
	))
	defer ts.Close()

	popdecc := exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageChallengeResp, false), secret)
	require.Equal(t, pkicmp.BodyTypePopDecC, popdecc.Body.Type)
	wrong := followUp(pkicmp.NewPopDecRBody(&pkicmp.POPODecKeyRespContent{big.NewInt(42)}), popdecc)
	resp := exchange(t, ts, wrong, secret)
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
	si := statusInfoOf(t, resp)
	assert.Equal(t, pkicmp.StatusRejection, si.Status)
	assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)

	// The transaction is over, so the right answer comes too late.
	again := exchange(t, ts, answerChallenge(t, popdecc, key), secret)
	assert.Equal(t, pkicmp.BodyTypeError, again.Body.Type)
	methods, confirmations := ca.recorded()
	assert.Empty(t, methods)
	assert.Empty(t, confirmations)
}

// A popdecr must answer the popdecc it names through recipNonce.
func TestChallengeResponseRecipNonce(t *testing.T) {
	secret := []byte("challenge-response-recip-nonce")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithChallengeResponsePOP(),
	))
	defer ts.Close()

	popdecc := exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageChallengeResp, false), secret)
	popdecr := answerChallenge(t, popdecc, key)
	popdecr.Header.RecipNonce = make([]byte, 16)
	resp := exchange(t, ts, popdecr, secret)
	assert.Equal(t, pkicmp.FailBadRecipientNonce, statusInfoOf(t, resp).FailInfo)
	methods, _ := ca.recorded()
	assert.Empty(t, methods)
}

// Each indirect method is refused unless its option is on. The strict profile
// keeps them for keys that cannot sign (RFC 9483 §4.1.1).
func TestIndirectPOPRefusals(t *testing.T) {
	secret := []byte("indirect-pop-refusals")
	keys := popKeys(t)
	kem, rsaKey := keys[0], keys[2]
	for _, tc := range []struct {
		name    string
		key     popKey
		method  int64
		options []server.Option
		fail    pkicmp.PKIFailureInfo
	}{
		{name: "encrypted certificate off", key: kem, method: pkicmp.SubsequentMessageEncrCert,
			options: []server.Option{server.WithChallengeResponsePOP()}, fail: pkicmp.FailBadPOP},
		{name: "challenge-response off", key: kem, method: pkicmp.SubsequentMessageChallengeResp,
			options: []server.Option{server.WithEncryptedCertificatePOP()}, fail: pkicmp.FailBadPOP},
		{name: "strict profile refuses a signing key", key: rsaKey, method: pkicmp.SubsequentMessageEncrCert,
			options: []server.Option{server.WithEncryptedCertificatePOP(), server.WithStrictProfileValidation()}, fail: pkicmp.FailBadPOP},
		{name: "strict profile accepts ML-KEM", key: kem, method: pkicmp.SubsequentMessageEncrCert,
			options: []server.Option{server.WithEncryptedCertificatePOP(), server.WithStrictProfileValidation()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newPOPCA(t)
			options := append([]server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}, tc.options...)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), options...))
			defer ts.Close()

			resp := exchange(t, ts, indirectPOPRequest(t, tc.key, tc.method, false), secret)
			methods, _ := ca.recorded()
			if tc.fail == 0 {
				decryptIssued(t, resp, tc.key)
				return
			}
			si := statusInfoOf(t, resp)
			assert.Equal(t, pkicmp.StatusRejection, si.Status)
			assert.Equal(t, tc.fail, si.FailInfo, "%v", si.StatusString)
			assert.Empty(t, methods)
		})
	}
}

// A challenged transaction and an issued encrypted certificate survive a
// snapshot, so another server instance continues them.
func TestIndirectPOPSnapshot(t *testing.T) {
	secret := []byte("indirect-pop-snapshot")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	newServer := func() *server.Server {
		return server.NewCAServer(ca, server.LightweightPolicy(),
			server.WithSecretLookup(&staticMACLookup{secret: secret}),
			server.WithEncryptedCertificatePOP(),
			server.WithChallengeResponsePOP(),
		)
	}
	first := newServer()
	ts1 := httptest.NewServer(first)
	defer ts1.Close()

	challenged := exchange(t, ts1, indirectPOPRequest(t, key, pkicmp.SubsequentMessageChallengeResp, false), secret)
	encrypted := exchange(t, ts1, indirectPOPRequest(t, key, pkicmp.SubsequentMessageEncrCert, false), secret)
	cert := decryptIssued(t, encrypted, key)
	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)

	second := newServer()
	require.NoError(t, second.RestoreTransactions(snapshot, nil))
	ts2 := httptest.NewServer(second)
	defer ts2.Close()

	ip := exchange(t, ts2, answerChallenge(t, challenged, key), secret)
	requirePlaintextCertificate(t, ip)

	// The restored entry still knows that its certConf is the proof.
	wrong := exchange(t, ts2, popCertConf(t, cert, true, encrypted), secret)
	assert.Equal(t, pkicmp.FailBadPOP, statusInfoOf(t, wrong).FailInfo)
	conf := exchange(t, ts2, popCertConf(t, cert, false, encrypted), secret)
	require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
}

// A snapshot whose challenged entry lacks its answer is refused.
func TestIndirectPOPSnapshotValidation(t *testing.T) {
	secret := []byte("indirect-pop-snapshot-validation")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	newServer := func() *server.Server {
		return server.NewCAServer(ca, server.LightweightPolicy(),
			server.WithSecretLookup(&staticMACLookup{secret: secret}),
			server.WithChallengeResponsePOP(),
		)
	}
	first := newServer()
	ts := httptest.NewServer(first)
	defer ts.Close()
	exchange(t, ts, indirectPOPRequest(t, key, pkicmp.SubsequentMessageChallengeResp, false), secret)
	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(snapshot, &decoded))
	entries := decoded["Entries"].([]any)
	require.Len(t, entries, 1)
	for _, field := range []string{"ChallengeAnswer", "ChallengeRequest", "POPMethod"} {
		t.Run(field, func(t *testing.T) {
			var copied map[string]any
			require.NoError(t, json.Unmarshal(snapshot, &copied))
			delete(copied["Entries"].([]any)[0].(map[string]any), field)
			broken, err := json.Marshal(copied)
			require.NoError(t, err)
			assert.Error(t, newServer().RestoreTransactions(broken, nil))
		})
	}
}
