package server_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// A key update that keeps the key is confirmed with the old certificate,
// which certifies the same key as the new one. RFC 9483 §4.1.1 requires the
// certConf to use the request's credentials, so the new certificate is refused.
func TestSameKeyUpdateConfirmation(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	device := &certyaml.Certificate{Subject: "CN=device-1", Issuer: ca}
	deviceCert, err := device.X509Certificate()
	require.NoError(t, err)
	signer, err := device.PrivateKey()
	require.NoError(t, err)
	deviceKey, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "certyaml default key is ECDSA")

	// current is the certificate the server's lookup returns for the signer.
	var current *x509.Certificate
	lookup := server.CertificateLookupFunc(func(pkix.Name, pkix.Name, []byte) (*x509.Certificate, error) {
		return current, nil
	})
	sign := func(t *testing.T, msg *pkicmp.PKIMessage, cert *x509.Certificate) {
		creds, err := pkicmp.NewSignatureCredentials(deviceKey, cert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		msg.ExtraCerts = append(msg.ExtraCerts, pkicmp.CMPCertificate{Raw: caCert.Raw})
	}
	update := func(t *testing.T) (*httptest.Server, *pkicmp.PKIMessage, *x509.Certificate) {
		current = &deviceCert
		ts := httptest.NewServer(server.NewCAServer(&recordingCA{ca: ca}, server.LightweightPolicy(), server.WithCertificateLookup(lookup)))
		t.Cleanup(ts.Close)
		req := pkicmp.NewPKIMessage(
			pkicmp.NewKURBody(&pkicmp.CertReqMessages{newCertReqMsg(t, deviceKey, "device-1")}),
			pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(deviceCert.RawSubject)},
		)
		sign(t, req, &deviceCert)
		resp := postCMP(t, ts, req)
		issued := issuedCertificate(t, resp)
		require.Equal(t, deviceCert.RawSubjectPublicKeyInfo, issued.RawSubjectPublicKeyInfo)
		return ts, resp, issued
	}

	t.Run("OldCertificateAccepted", func(t *testing.T) {
		ts, resp, issued := update(t)
		conf := certConfFor(t, resp, issued, deviceCert.Subject)
		sign(t, conf, &deviceCert)
		out := postCMP(t, ts, conf)
		assert.Equal(t, pkicmp.BodyTypePKIConf, out.Body.Type, "status %+v", statusOrNil(t, out))
	})
	t.Run("NewCertificateRefused", func(t *testing.T) {
		ts, resp, issued := update(t)
		current = issued
		conf := certConfFor(t, resp, issued, deviceCert.Subject)
		sign(t, conf, issued)
		si := statusInfoOf(t, postCMP(t, ts, conf))
		assert.Equal(t, pkicmp.StatusRejection, si.Status)
		assert.Equal(t, pkicmp.PKIFreeText{"unknown transaction"}, si.StatusString)
	})
}

// statusOrNil returns the status of an error message for failure output and nil for any other body.
func statusOrNil(t *testing.T, msg *pkicmp.PKIMessage) *pkicmp.PKIStatusInfo {
	t.Helper()
	if msg.Body.Type != pkicmp.BodyTypeError {
		return nil
	}
	si := statusInfoOf(t, msg)
	return &si
}
