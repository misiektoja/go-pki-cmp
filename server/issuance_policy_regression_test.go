package server_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// recordingCA issues whatever it is handed and records that it was reached,
// which is what distinguishes a check that rejected a request from one that
// merely happened to produce no certificate.
type recordingCA struct {
	ca       *certyaml.Certificate
	called   bool
	template *x509.Certificate
}

func (c *recordingCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.called = true
	c.template = tmpl

	caCert, err := c.ca.X509Certificate()
	if err != nil {
		return nil, err
	}
	caKey, err := c.ca.PrivateKey()
	if err != nil {
		return nil, err
	}
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	// The request's own extensions are deliberately not forwarded, because a
	// malformed one must be rejected before it reaches a CA rather than be
	// filtered by the CA's own encoder.
	tmpl.ExtraExtensions = nil

	der, err := x509.CreateCertificate(rand.Reader, tmpl, &caCert, tmpl.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: issued, CACerts: []*x509.Certificate{&caCert}}, nil
}

// certReqMsgWithoutPOP builds a request for a public key with no proof of possession at all.
func certReqMsgWithoutPOP(t *testing.T, pub any, subject string) pkicmp.CertReqMsg {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: subject}),
				PublicKey: pubDER,
			},
		},
	}
}

// rejectionStatus returns the PKIStatusInfo of an ip response, requiring the response to be one.
func rejectionStatus(t *testing.T, resp *pkicmp.PKIMessage) pkicmp.PKIStatusInfo {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type)
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	require.Len(t, rep.Response, 1)
	return rep.Response[0].Status
}

// A server built without a policy wrapper still has to prove that the requester
// holds the private key, otherwise anyone can obtain a certificate for a public
// key they merely copied.
func TestProofOfPossessionEnforcedWithoutPolicy(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	secret := []byte("pop-without-policy")

	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := &recordingCA{ca: ca}
	srv := server.NewCAServer(issuer, nil, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{certReqMsgWithoutPOP(t, &victimKey.PublicKey, "victim-key")}),
		macMessageOpts(),
	)
	protectMAC(msg, secret)

	status := rejectionStatus(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.StatusRejection, status.Status)
	assert.NotZero(t, status.FailInfo&pkicmp.FailBadPOP)
	assert.False(t, issuer.called, "the CA must not be reached by a request that proves nothing")
}

// The PKCS#10 self-signature is the proof of possession for a p10cr, so a
// request whose signature does not verify must be refused without a policy too.
func TestP10CRSignatureEnforcedWithoutPolicy(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	secret := []byte("p10cr-without-policy")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "tampered-csr"},
	}, key)
	require.NoError(t, err)
	// Flip a byte inside the signature so the request no longer proves possession.
	csrDER[len(csrDER)-1] ^= 0xff
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	issuer := &recordingCA{ca: ca}
	srv := server.NewCAServer(issuer, nil, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(csr), macMessageOpts())
	protectMAC(msg, secret)

	resp := postCMP(t, ts, msg)
	require.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
	rep, err := resp.Body.CP()
	require.NoError(t, err)
	require.Len(t, rep.Response, 1)
	assert.Equal(t, pkicmp.StatusRejection, rep.Response[0].Status.Status)
	assert.NotZero(t, rep.Response[0].Status.FailInfo&pkicmp.FailBadPOP)
	assert.False(t, issuer.called)
}

// A request that does prove possession still has to be issued, so the check
// above is not simply refusing everything.
func TestProofOfPossessionAcceptedWithoutPolicy(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	secret := []byte("pop-accepted")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := &recordingCA{ca: ca}
	srv := server.NewCAServer(issuer, nil, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "holds-the-key")}),
		macMessageOpts(),
	)
	protectMAC(msg, secret)

	status := rejectionStatus(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.StatusAccepted, status.Status)
	assert.True(t, issuer.called)
}

// basicConstraintsExtension builds a BasicConstraints extension from a raw value.
func basicConstraintsExtension(value []byte) pkix.Extension {
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    value,
	}
}

// certReqMsgWithExtensions builds a request carrying the given extensions and a valid proof of possession.
func certReqMsgWithExtensions(t *testing.T, key *ecdsa.PrivateKey, subject string, exts []pkix.Extension) pkicmp.CertReqMsg {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	encoded, err := asn1.Marshal(exts)
	require.NoError(t, err)

	msg := pkicmp.CertReqMsg{
		CertReq: pkicmp.CertRequest{
			CertReqID: 0,
			CertTemplate: pkicmp.CertTemplate{
				Subject:    pkicmp.NewDirectoryName(pkix.Name{CommonName: subject}),
				PublicKey:  pubDER,
				Extensions: encoded,
			},
		},
	}
	require.NoError(t, msg.GeneratePOP(key))
	return msg
}

// Go's encoding/asn1 accepts only 00 and FF for a BOOLEAN, so a cA value of 01
// fails to decode. Reading that failure as "the extension is absent" let a
// request for a CA certificate past the check while the extension itself
// travelled on to the CA unchanged.
func TestMalformedBasicConstraintsRejected(t *testing.T) {
	// SEQUENCE { BOOLEAN 01 }, a cA value encoding/asn1 refuses to decode.
	nonCanonicalCA := []byte{0x30, 0x03, 0x01, 0x01, 0x01}
	// SEQUENCE { BOOLEAN FF }, the canonical form of the same request.
	canonicalCA := []byte{0x30, 0x03, 0x01, 0x01, 0xff}

	tests := []struct {
		name         string
		value        []byte
		policy       func(server.Handler) server.Handler
		wantFailInfo pkicmp.PKIFailureInfo
	}{
		{name: "non-canonical cA under policy", value: nonCanonicalCA, policy: server.LightweightPolicy(), wantFailInfo: pkicmp.FailBadCertTemplate},
		{name: "canonical cA under policy", value: canonicalCA, policy: server.LightweightPolicy(), wantFailInfo: pkicmp.FailNotAuthorized},
		{name: "non-canonical cA without policy", value: nonCanonicalCA, policy: nil, wantFailInfo: pkicmp.FailBadCertTemplate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &certyaml.Certificate{Subject: "CN=Test CA"}
			secret := []byte("basic-constraints")

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			issuer := &recordingCA{ca: ca}
			srv := server.NewCAServer(issuer, tt.policy, server.WithSecretLookup(&staticMACLookup{secret: secret}))
			ts := httptest.NewServer(srv)
			defer ts.Close()

			msg := pkicmp.NewPKIMessage(
				pkicmp.NewIRBody(&pkicmp.CertReqMessages{
					certReqMsgWithExtensions(t, key, "ca-request", []pkix.Extension{basicConstraintsExtension(tt.value)}),
				}),
				macMessageOpts(),
			)
			protectMAC(msg, secret)

			status := rejectionStatus(t, postCMP(t, ts, msg))
			assert.Equal(t, pkicmp.StatusRejection, status.Status)
			assert.NotZero(t, status.FailInfo&tt.wantFailInfo)
			assert.False(t, issuer.called, "the CA must not receive an extension no check understood")
		})
	}
}

// A negative pathLenConstraint is invalid under RFC 5280 §4.2.1.9 whether or not
// the same extension also asks for a CA certificate.
func TestNegativePathLengthRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	secret := []byte("path-length")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// SEQUENCE { BOOLEAN FF, INTEGER -1 }
	value, err := asn1.Marshal(struct {
		IsCA       bool
		MaxPathLen int
	}{IsCA: true, MaxPathLen: -1})
	require.NoError(t, err)

	issuer := &recordingCA{ca: ca}
	srv := server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{
			certReqMsgWithExtensions(t, key, "negative-path-length", []pkix.Extension{basicConstraintsExtension(value)}),
		}),
		macMessageOpts(),
	)
	protectMAC(msg, secret)

	status := rejectionStatus(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.StatusRejection, status.Status)
	assert.NotZero(t, status.FailInfo&pkicmp.FailBadCertTemplate)
	assert.False(t, issuer.called)
}

// A well-formed non-CA BasicConstraints must still be accepted, so the strict
// decode does not reject ordinary requests.
func TestWellFormedBasicConstraintsAccepted(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	secret := []byte("well-formed-basic-constraints")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// SEQUENCE {}, the DER form of cA FALSE with no path length.
	value := []byte{0x30, 0x00}

	issuer := &recordingCA{ca: ca}
	srv := server.NewCAServer(issuer, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{
			certReqMsgWithExtensions(t, key, "end-entity", []pkix.Extension{basicConstraintsExtension(value)}),
		}),
		macMessageOpts(),
	)
	protectMAC(msg, secret)

	status := rejectionStatus(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.StatusAccepted, status.Status)
	assert.True(t, issuer.called)
}

// A certificate resolved from the server's own store proves only that the server
// knows it. Without binding it to the header sender, a lookup keyed on senderKID
// hands the CA a genuine certificate paired with a sender name the peer chose.
func TestSignatureSenderMustMatchLookedUpCertificate(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}

	clientCert := &certyaml.Certificate{Subject: "CN=real-client", Issuer: ca}
	clientX509, err := clientCert.X509Certificate()
	require.NoError(t, err)
	clientKey, err := clientCert.PrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name       string
		sender     pkicmp.GeneralName
		wantIssued bool
	}{
		{
			name:       "sender names the certificate subject",
			sender:     pkicmp.NewDirectoryNameFromRawDER(clientX509.RawSubject),
			wantIssued: true,
		},
		{
			name:       "sender names somebody else",
			sender:     pkicmp.NewDirectoryName(pkix.Name{CommonName: "privileged-client"}),
			wantIssued: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := &recordingCA{ca: ca}
			srv := server.NewCAServer(issuer, nil, server.WithCertificateLookup(&staticCertLookup{cert: &clientX509}))
			ts := httptest.NewServer(srv)
			defer ts.Close()

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			msg := pkicmp.NewPKIMessage(
				pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "sender-binding")}),
				pkicmp.MessageOptions{Sender: tt.sender},
			)
			creds, err := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
			require.NoError(t, err)
			require.NoError(t, creds.Protect(msg))

			resp := postCMP(t, ts, msg)
			if tt.wantIssued {
				require.Equal(t, pkicmp.BodyTypeCP, resp.Body.Type)
				rep, err := resp.Body.CP()
				require.NoError(t, err)
				assert.Equal(t, pkicmp.StatusAccepted, rep.Response[0].Status.Status)
				assert.True(t, issuer.called)
				return
			}

			// The message never authenticates, so the server answers with an
			// error rather than a rejected certificate response.
			require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
			errContent, err := resp.Body.Error()
			require.NoError(t, err)
			assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
			assert.False(t, issuer.called, "the CA must not see a sender the message did not authenticate")
		})
	}
}

// A request without a verified proof must be refused instead of reaching the CA.
// The indirect methods of RFC 9810 §5.2.8.3 are off by default, and with them
// on the server still refuses a key it cannot encrypt for, such as X25519.
func TestProofOfPossessionRequiredForKeysThatCannotSign(t *testing.T) {
	secret := []byte("pop-non-signing-key")
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	subsequent := int64(0)

	requests := map[string]struct {
		msg     func(t *testing.T) pkicmp.CertReqMsg
		options []server.Option
		fail    pkicmp.PKIFailureInfo
		text    string
	}{
		"NoPOP": {
			msg: func(t *testing.T) pkicmp.CertReqMsg {
				return certReqMsgWithoutPOP(t, key.PublicKey(), "x25519-no-pop")
			},
			fail: pkicmp.FailBadPOP,
			text: "proof of possession by signature required",
		},
		"KeyEnciphermentPOP": {
			msg: func(t *testing.T) pkicmp.CertReqMsg {
				msg := certReqMsgWithoutPOP(t, key.PublicKey(), "x25519-key-encipherment")
				msg.Popo = pkicmp.NewKeyEnciphermentPOP(&subsequent)
				return msg
			},
			fail: pkicmp.FailBadPOP,
			text: "encrypted certificate proof of possession is not accepted",
		},
		"KeyEnciphermentPOPEnabled": {
			msg: func(t *testing.T) pkicmp.CertReqMsg {
				msg := certReqMsgWithoutPOP(t, key.PublicKey(), "x25519-key-encipherment-enabled")
				msg.Popo = pkicmp.NewKeyEnciphermentPOP(&subsequent)
				return msg
			},
			options: []server.Option{server.WithEncryptedCertificatePOP()},
			fail:    pkicmp.FailBadAlg,
			text:    "the server cannot encrypt for the requested key",
		},
	}
	policies := map[string]func(server.Handler) server.Handler{
		"LightweightPolicy": server.LightweightPolicy(),
		"NoPolicy":          nil,
	}

	for reqName, request := range requests {
		for policyName, policy := range policies {
			t.Run(reqName+"/"+policyName, func(t *testing.T) {
				issuer := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
				options := append([]server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}, request.options...)
				ts := httptest.NewServer(server.NewCAServer(issuer, policy, options...))
				defer ts.Close()

				msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{request.msg(t)}), macMessageOpts())
				protectMAC(msg, secret)

				status := rejectionStatus(t, postCMP(t, ts, msg))
				assert.Equal(t, pkicmp.StatusRejection, status.Status)
				assert.Equal(t, request.fail, status.FailInfo)
				assert.Equal(t, pkicmp.PKIFreeText{request.text}, status.StatusString)
				assert.False(t, issuer.called, "the CA must not be reached without a verified proof")
			})
		}
	}
}

// A template without a public key asks for central key generation, which is not supported.
func TestCertRequestWithoutPublicKeyRejected(t *testing.T) {
	secret := []byte("no-public-key")
	issuer := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	ts := httptest.NewServer(server.NewCAServer(issuer, nil, server.WithSecretLookup(&staticMACLookup{secret: secret})))
	defer ts.Close()

	req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
		Subject: pkicmp.NewDirectoryName(pkix.Name{CommonName: "central-keygen"}),
	}}}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), macMessageOpts())
	protectMAC(msg, secret)

	status := rejectionStatus(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.FailBadCertTemplate, status.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"public key required"}, status.StatusString)
	assert.False(t, issuer.called)
}
