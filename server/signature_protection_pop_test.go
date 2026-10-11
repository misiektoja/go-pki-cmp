package server_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// noPOPRequest returns a request of bodyType for the key in spki that carries
// no proof of possession, as a key update that keeps the existing key does.
func noPOPRequest(bodyType pkicmp.BodyType, cert *x509.Certificate, spki []byte, opts pkicmp.MessageOptions) *pkicmp.PKIMessage {
	msgs := &pkicmp.CertReqMessages{{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
		Subject:   pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject),
		PublicKey: spki,
	}}}}
	body := pkicmp.NewKURBody(msgs)
	if bodyType == pkicmp.BodyTypeIR {
		body = pkicmp.NewIRBody(msgs)
	}
	return pkicmp.NewPKIMessage(body, opts)
}

// WithSignatureProtectionPOP accepts a request without popo only when its
// protection signature was made with the requested key.
func TestSignatureProtectionPOP(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	device := &certyaml.Certificate{Subject: "CN=device-1", Issuer: ca}
	deviceCert, err := device.X509Certificate()
	require.NoError(t, err)
	deviceKey, err := device.PrivateKey()
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSPKI, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	require.NoError(t, err)

	newServer := func(t *testing.T, opts ...server.Option) *httptest.Server {
		opts = append(opts,
			server.WithCertificateLookup(&staticCertLookup{cert: &deviceCert}),
			server.WithSecretLookup(&staticMACLookup{secret: []byte("pop-secret")}),
		)
		ts := httptest.NewServer(server.NewCAServer(&recordingCA{ca: ca}, server.LightweightPolicy(), opts...))
		t.Cleanup(ts.Close)
		return ts
	}
	signed := func(t *testing.T, spki []byte, signer crypto.Signer) *pkicmp.PKIMessage {
		msg := noPOPRequest(pkicmp.BodyTypeKUR, &deviceCert, spki, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(deviceCert.RawSubject)})
		creds, err := pkicmp.NewSignatureCredentials(signer, &deviceCert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		return msg
	}

	t.Run("RefusedByDefault", func(t *testing.T) {
		si := statusInfoOf(t, postCMP(t, newServer(t), signed(t, deviceCert.RawSubjectPublicKeyInfo, deviceKey)))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"proof of possession by signature required"}, si.StatusString)
	})
	t.Run("SameKeyAccepted", func(t *testing.T) {
		resp := postCMP(t, newServer(t, server.WithSignatureProtectionPOP()), signed(t, deviceCert.RawSubjectPublicKeyInfo, deviceKey))
		require.Equal(t, pkicmp.BodyTypeKUP, resp.Body.Type)
		si := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
	})
	t.Run("OtherKeyRefused", func(t *testing.T) {
		si := statusInfoOf(t, postCMP(t, newServer(t, server.WithSignatureProtectionPOP()), signed(t, otherSPKI, deviceKey)))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
	})
	t.Run("MACProtectionRefused", func(t *testing.T) {
		msg := noPOPRequest(pkicmp.BodyTypeIR, &deviceCert, deviceCert.RawSubjectPublicKeyInfo, macMessageOpts())
		protectMAC(msg, []byte("pop-secret"))
		si := statusInfoOf(t, postCMP(t, newServer(t, server.WithSignatureProtectionPOP()), msg))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
	})
	t.Run("RefusedUnderStrictProfile", func(t *testing.T) {
		ts := newServer(t, server.WithSignatureProtectionPOP(), server.WithStrictProfileValidation())
		si := statusInfoOf(t, postCMP(t, ts, signed(t, deviceCert.RawSubjectPublicKeyInfo, deviceKey)))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"proof of possession by signature required"}, si.StatusString)
	})
}
