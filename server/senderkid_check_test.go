package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// A present senderKID must identify the key that verifies the signature (RFC 9483 section 3.5),
// also when the certificate lookup finds the certificate without it.
func TestSignatureSenderKIDMustIdentifyProtectionKey(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	deviceCert, deviceKey := protectionCertificate(t, ca, []byte{0xc5, 0xb3, 0xef, 0x0c, 0x01, 0x02, 0x03, 0x04})
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wrongKID := bytes.Clone(deviceCert.SubjectKeyId)
	wrongKID[0] ^= 0xff

	// The lookup ignores senderKID, as a host that finds the signer through extraCerts does.
	newServer := func(t *testing.T, issuer *recordingCA, opts ...server.Option) *httptest.Server {
		opts = append(opts, server.WithCertificateLookup(&staticCertLookup{cert: deviceCert}))
		ts := httptest.NewServer(server.NewCAServer(issuer, server.LightweightPolicy(), opts...))
		t.Cleanup(ts.Close)
		return ts
	}
	// Protect takes senderKID from the certificate's key identifier, so the request is signed
	// with a copy that carries senderKID instead. The real certificate still goes in extraCerts.
	request := func(t *testing.T, senderKID []byte) *pkicmp.PKIMessage {
		body := pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, newKey, "device-1")})
		msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(deviceCert.RawSubject)})
		signing := *deviceCert
		signing.SubjectKeyId = senderKID
		creds, err := pkicmp.NewSignatureCredentials(deviceKey, &signing)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		require.Equal(t, senderKID, msg.Header.SenderKID)
		return msg
	}

	for _, profile := range []struct {
		name string
		opts []server.Option
	}{
		{name: "Default"},
		{name: "Strict", opts: []server.Option{server.WithStrictProfileValidation()}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			t.Run("OtherKeyRefused", func(t *testing.T) {
				issuer := &recordingCA{ca: ca}
				resp := postCMP(t, newServer(t, issuer, profile.opts...), request(t, wrongKID))
				require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
				si := statusInfoOf(t, resp)
				assert.Equal(t, pkicmp.StatusRejection, si.Status)
				assert.Equal(t, pkicmp.FailBadMessageCheck, si.FailInfo)
				assert.False(t, issuer.called, "no certificate may be issued")
			})
			t.Run("ProtectionKeyAccepted", func(t *testing.T) {
				issuer := &recordingCA{ca: ca}
				resp := postCMP(t, newServer(t, issuer, profile.opts...), request(t, deviceCert.SubjectKeyId))
				require.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
				si := statusInfoOf(t, resp)
				assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
			})
			t.Run("AbsentAccepted", func(t *testing.T) {
				issuer := &recordingCA{ca: ca}
				resp := postCMP(t, newServer(t, issuer, profile.opts...), request(t, nil))
				require.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
				si := statusInfoOf(t, resp)
				assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
			})
		})
	}
}

// A certificate without a subject key identifier cannot be matched against senderKID, so a
// senderKID does not refuse it.
func TestSignatureSenderKIDWithoutSubjectKeyIdentifier(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	deviceCert, deviceKey := protectionCertificate(t, ca, nil)

	issuer := &recordingCA{ca: ca}
	ts := httptest.NewServer(server.NewCAServer(issuer, server.LightweightPolicy(), server.WithCertificateLookup(&staticCertLookup{cert: deviceCert})))
	t.Cleanup(ts.Close)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	body := pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, newKey, "device-1")})
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(deviceCert.RawSubject)})
	msg.Header.SenderKID = []byte("unmatched")
	creds, err := pkicmp.NewSignatureCredentials(deviceKey, deviceCert)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))

	resp := postCMP(t, ts, msg)
	require.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
	si := statusInfoOf(t, resp)
	assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
}

// protectionCertificate issues a P-256 certificate for CN=device-1 from ca with the given subject
// key identifier. A nil ski gives a certificate without one.
func protectionCertificate(t *testing.T, ca *certyaml.Certificate, ski []byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := server.GenerateSerial()
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "device-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski,
	}, &caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, ski, cert.SubjectKeyId)
	return cert, key
}
