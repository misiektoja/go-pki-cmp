package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// malformedAfterHeader returns the DER of a message whose header decodes and whose body does not.
func malformedAfterHeader(t *testing.T) []byte {
	t.Helper()
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(pkix.Name{CommonName: "malformed"})})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	var outer asn1.RawValue
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	// A protection field that holds a NULL instead of a BIT STRING follows the
	// header and the body.
	protection, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x05, 0x00}})
	require.NoError(t, err)
	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(outer.Bytes, protection...)})
	require.NoError(t, err)
	return out
}

// postDER posts raw DER to the server and parses the response.
func postDER(t *testing.T, ts *httptest.Server, der []byte) *pkicmp.PKIMessage {
	t.Helper()
	resp, err := http.Post(ts.URL, "application/pkixcmp", bytes.NewReader(der))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(body)
	require.NoError(t, err)
	return parsed
}

// Errors raised before authentication are signed by default and carry no
// protection with WithUnprotectedErrorsBeforeAuthentication. An error after
// authentication keeps its protection either way.
func TestUnprotectedErrorsBeforeAuthentication(t *testing.T) {
	secret := []byte("unprotected-errors-secret")
	ca := &certyaml.Certificate{Subject: "CN=Test CA", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)

	newIR := func(t *testing.T) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "unprotected-errors")}), macMessageOpts())
	}
	marshal := func(t *testing.T, msg *pkicmp.PKIMessage) []byte {
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		return der
	}
	refusals := []struct {
		name     string
		der      func(t *testing.T) []byte
		failInfo pkicmp.PKIFailureInfo
		text     string
	}{
		{
			name:     "unprotected request",
			der:      func(t *testing.T) []byte { return marshal(t, newIR(t)) },
			failInfo: pkicmp.FailBadMessageCheck,
			text:     "message not protected",
		},
		{
			name: "wrong secret",
			der: func(t *testing.T) []byte {
				msg := newIR(t)
				protectMAC(msg, []byte("another-secret"))
				return marshal(t, msg)
			},
			failInfo: pkicmp.FailBadMessageCheck,
			text:     "MAC verification failed",
		},
		{
			name:     "malformed body",
			der:      malformedAfterHeader,
			failInfo: pkicmp.FailBadDataFormat,
			text:     "malformed message",
		},
	}

	servers := []struct {
		name      string
		opts      []server.Option
		protected bool
	}{
		{name: "signed by default", protected: true},
		{name: "unprotected with the option", opts: []server.Option{server.WithUnprotectedErrorsBeforeAuthentication()}},
	}
	for _, tc := range servers {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]server.Option{
				server.WithSigner(caKey, &caCert),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
			}, tc.opts...)
			srv := server.NewCAServer(&generalCA{}, server.LightweightPolicy(), opts...)
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			t.Cleanup(ts.Close)

			for _, r := range refusals {
				t.Run(r.name, func(t *testing.T) {
					resp := postDER(t, ts, r.der(t))
					status := errorStatus(t, resp)
					assert.Equal(t, r.failInfo, status.FailInfo)
					assert.Equal(t, pkicmp.PKIFreeText{r.text}, status.StatusString)
					if tc.protected {
						_, err := resp.Verify(pkicmp.VerifyOptions{TrustedCert: &caCert})
						assert.NoError(t, err)
						return
					}
					assert.Nil(t, resp.Header.ProtectionAlg)
					assert.Empty(t, resp.Protection)
					assert.Empty(t, resp.Header.SenderKID)
					assert.Empty(t, resp.ExtraCerts)
				})
			}

			t.Run("authenticated error stays protected", func(t *testing.T) {
				msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), macMessageOpts())
				protectMAC(msg, secret)
				resp := postCMP(t, ts, msg)
				status := errorStatus(t, resp)
				assert.Equal(t, pkicmp.FailBadRequest, status.FailInfo)
				_, err := resp.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
				assert.NoError(t, err)
			})
		})
	}
}

// A request forwarded by an authenticated registration authority is answered
// with a protected error even when its own protection fails and
// WithUnprotectedErrorsBeforeAuthentication is set.
func TestForwardedErrorStaysProtected(t *testing.T) {
	f := newNestedFixture(t)
	ts := f.serve(t, server.WithRAAuthorizer(f), server.WithUnprotectedErrorsBeforeAuthentication())

	inner := f.innerIR(t)
	protectMAC(inner, []byte("some-other-secret"))
	resp := postCMP(t, ts, wrap(t, f.ra, inner))
	status := errorStatus(t, resp)
	assert.Equal(t, pkicmp.FailBadMessageCheck, status.FailInfo)
	_, err := resp.Verify(pkicmp.VerifyOptions{TrustedCert: f.caCert})
	assert.NoError(t, err)
}
