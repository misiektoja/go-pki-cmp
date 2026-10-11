package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// raIssuingCA issues certificates and records the sender of every request it receives.
type raIssuingCA struct {
	*recordingCA
	mu      sync.Mutex
	senders []*server.SenderIdentity
}

// IssueCertificate records sender and issues the certificate.
func (c *raIssuingCA) IssueCertificate(ctx context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	c.senders = append(c.senders, sender)
	c.mu.Unlock()
	return c.recordingCA.IssueCertificate(ctx, reqType, tmpl, sender)
}

// raAuthorization records what the server asked the RA authorizer.
type raAuthorization struct {
	ra     *server.SenderIdentity
	req    *pkicmp.PKIMessage
	sender *server.SenderIdentity
}

// nestedFixture is a CA server that trusts one registration authority.
type nestedFixture struct {
	secret  []byte
	ra      revocationEntity
	other   revocationEntity
	issuer  *raIssuingCA
	caCert  *x509.Certificate
	mu      sync.Mutex
	calls   []raAuthorization
	decide  func(ra *server.SenderIdentity) error
	lookups *revokingCA
}

// newNestedFixture issues the RA certificate and a certificate for an entity that is not an RA.
func newNestedFixture(t *testing.T) *nestedFixture {
	t.Helper()
	ca := &certyaml.Certificate{Subject: "CN=Nested CA", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	entity := func(subject string) revocationEntity {
		c := &certyaml.Certificate{Subject: subject, Issuer: ca}
		cert, err := c.X509Certificate()
		require.NoError(t, err)
		key, err := c.PrivateKey()
		require.NoError(t, err)
		return revocationEntity{cert: &cert, key: key}
	}
	f := &nestedFixture{
		secret: []byte("nested-ee-secret"),
		ra:     entity("CN=nested-ra"),
		other:  entity("CN=nested-other"),
		issuer: &raIssuingCA{recordingCA: &recordingCA{ca: ca}},
		caCert: &caCert,
	}
	f.lookups = &revokingCA{issued: []*x509.Certificate{f.ra.cert, f.other.cert}}
	// The Lightweight CMP Profile rule: only a signature from the RA certificate approves a request.
	f.decide = func(ra *server.SenderIdentity) error {
		if ra.MACVerified {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailWrongIntegrity, StatusText: "RA must sign"}
		}
		if !ra.Certificate.Equal(f.ra.cert) {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not a registration authority"}
		}
		return nil
	}
	return f
}

// AuthorizeRA records the call and applies the fixture's decision.
func (f *nestedFixture) AuthorizeRA(_ context.Context, ra *server.SenderIdentity, req *pkicmp.PKIMessage, sender *server.SenderIdentity) error {
	f.mu.Lock()
	f.calls = append(f.calls, raAuthorization{ra: ra, req: req, sender: sender})
	f.mu.Unlock()
	return f.decide(ra)
}

// serve starts a server with the fixture's lookups and any extra options.
func (f *nestedFixture) serve(t *testing.T, opts ...server.Option) *httptest.Server {
	t.Helper()
	caKey, err := f.issuer.ca.PrivateKey()
	require.NoError(t, err)
	opts = append([]server.Option{
		server.WithSigner(caKey, f.caCert),
		server.WithSecretLookup(&staticMACLookup{secret: f.secret}),
		server.WithCertificateLookup(f.lookups),
	}, opts...)
	srv := server.NewCAServer(f.issuer, server.LightweightPolicy(), opts...)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// innerIR returns an IR that the end entity protected with its shared secret.
func (f *nestedFixture) innerIR(t *testing.T) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "nested-ee")}), macMessageOpts())
	protectMAC(msg, f.secret)
	return msg
}

// wrap puts msgs in a nested message that copies the first message's transactionID and senderNonce and is signed by signer.
func wrap(t *testing.T, signer revocationEntity, msgs ...*pkicmp.PKIMessage) *pkicmp.PKIMessage {
	t.Helper()
	outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(msgs...), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryNameFromRawDER(signer.cert.RawSubject),
		TransactionID: msgs[0].Header.TransactionID,
		SenderNonce:   msgs[0].Header.SenderNonce,
	})
	creds, err := pkicmp.NewSignatureCredentials(signer.key, signer.cert)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(outer))
	return outer
}

// errorStatus returns the status of an error message, requiring the response to be one.
func errorStatus(t *testing.T, msg *pkicmp.PKIMessage) pkicmp.PKIStatusInfo {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeError, msg.Body.Type, "expected error, got %s", msg.Body.Type)
	return statusInfoOf(t, msg)
}

// RFC 9483 §5.2.2.1: a request an authorized RA wraps is answered like the request itself.
func TestNestedRequestFromAuthorizedRA(t *testing.T) {
	f := newNestedFixture(t)
	ts := f.serve(t, server.WithRAAuthorizer(f))

	inner := f.innerIR(t)
	resp := postCMP(t, ts, wrap(t, f.ra, inner))

	status := rejectionStatus(t, resp)
	require.Equal(t, pkicmp.StatusAccepted, status.Status, "status: %+v", status)
	assert.Equal(t, inner.Header.TransactionID, resp.Header.TransactionID)
	assert.Equal(t, inner.Header.SenderNonce, resp.Header.RecipNonce)
	// The response goes to the end entity, so it uses the end entity's shared secret.
	_, err := resp.Verify(pkicmp.VerifyOptions{SharedSecret: f.secret, RequiredProtection: pkicmp.ProtectionMAC})
	require.NoError(t, err)

	require.Len(t, f.calls, 1)
	call := f.calls[0]
	assert.True(t, call.ra.Certificate.Equal(f.ra.cert))
	assert.Equal(t, pkicmp.BodyTypeIR, call.req.Body.Type)
	assert.True(t, call.sender.MACVerified)

	require.Len(t, f.issuer.senders, 1)
	sender := f.issuer.senders[0]
	assert.True(t, sender.MACVerified)
	require.NotNil(t, sender.RA)
	assert.True(t, sender.RA.Certificate.Equal(f.ra.cert))
}

// RFC 9483 §3.1: the response carries the pvno of the request it answers, not of the wrapper.
func TestNestedResponseUsesInnerVersion(t *testing.T) {
	f := newNestedFixture(t)
	ts := f.serve(t, server.WithRAAuthorizer(f))

	inner := f.innerIR(t)
	inner.Header.PVNO = pkicmp.PVNO3
	protectMAC(inner, f.secret)
	outer := wrap(t, f.ra, inner)
	require.Equal(t, pkicmp.PVNO2, outer.Header.PVNO)

	resp := postCMP(t, ts, outer)
	assert.Equal(t, pkicmp.StatusAccepted, rejectionStatus(t, resp).Status)
	assert.Equal(t, pkicmp.PVNO3, resp.Header.PVNO)
}

// Follow-up messages of a forwarded transaction can be forwarded as well.
func TestNestedCertConf(t *testing.T) {
	f := newNestedFixture(t)
	ts := f.serve(t, server.WithRAAuthorizer(f))

	inner := f.innerIR(t)
	resp := postCMP(t, ts, wrap(t, f.ra, inner))
	require.Equal(t, pkicmp.StatusAccepted, rejectionStatus(t, resp).Status)
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(rep.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate.Raw)
	require.NoError(t, err)

	certStatus, err := pkicmp.NewCertStatus(cert, 0)
	require.NoError(t, err)
	conf := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{certStatus}), macMessageOpts())
	conf.Header.TransactionID = inner.Header.TransactionID
	conf.Header.RecipNonce = resp.Header.SenderNonce
	protectMAC(conf, f.secret)

	confResp := postCMP(t, ts, wrap(t, f.ra, conf))
	assert.Equal(t, pkicmp.BodyTypePKIConf, confResp.Body.Type, "got %s", confResp.Body.Type)
	require.Len(t, f.calls, 2)
	assert.Equal(t, pkicmp.BodyTypeCertConf, f.calls[1].req.Body.Type)
}

// Without WithRAAuthorizer nested messages are refused as before.
func TestNestedRejectedWithoutAuthorizer(t *testing.T) {
	f := newNestedFixture(t)
	ts := f.serve(t)

	status := errorStatus(t, postCMP(t, ts, wrap(t, f.ra, f.innerIR(t))))
	assert.Equal(t, pkicmp.StatusRejection, status.Status)
	assert.Equal(t, pkicmp.FailBadRequest, status.FailInfo)
	assert.False(t, f.issuer.called)
}

// The authorizer's refusal is reported to the RA in an error message.
func TestNestedRAAuthorization(t *testing.T) {
	macWrap := func(t *testing.T, f *nestedFixture, inner *pkicmp.PKIMessage) *pkicmp.PKIMessage {
		outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner), pkicmp.MessageOptions{
			Sender:        pkicmp.NewDirectoryName(pkix.Name{CommonName: "mac-ra"}),
			TransactionID: inner.Header.TransactionID,
			SenderNonce:   inner.Header.SenderNonce,
		})
		outer.Header.SenderKID = []byte("mac-ra")
		creds, err := pkicmp.NewMACCredentials(f.secret)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(outer))
		return outer
	}
	tests := []struct {
		name     string
		wrap     func(t *testing.T, f *nestedFixture, inner *pkicmp.PKIMessage) *pkicmp.PKIMessage
		decide   func(ra *server.SenderIdentity) error
		failInfo pkicmp.PKIFailureInfo
		text     bool
	}{
		{
			name: "signer is not an RA",
			wrap: func(t *testing.T, f *nestedFixture, inner *pkicmp.PKIMessage) *pkicmp.PKIMessage {
				return wrap(t, f.other, inner)
			},
			failInfo: pkicmp.FailNotAuthorized,
			text:     true,
		},
		{
			name:     "MAC-protected wrapper",
			wrap:     macWrap,
			failInfo: pkicmp.FailWrongIntegrity,
			text:     true,
		},
		{
			name: "authorizer failure",
			wrap: func(t *testing.T, f *nestedFixture, inner *pkicmp.PKIMessage) *pkicmp.PKIMessage {
				return wrap(t, f.ra, inner)
			},
			decide:   func(*server.SenderIdentity) error { return errors.New("database unavailable") },
			failInfo: pkicmp.FailSystemFailure,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newNestedFixture(t)
			if tc.decide != nil {
				f.decide = tc.decide
			}
			ts := f.serve(t, server.WithRAAuthorizer(f))

			outer := tc.wrap(t, f, f.innerIR(t))
			resp := postCMP(t, ts, outer)
			status := errorStatus(t, resp)
			assert.Equal(t, pkicmp.StatusRejection, status.Status)
			assert.Equal(t, tc.failInfo, status.FailInfo)
			assert.Equal(t, tc.text, len(status.StatusString) > 0, "status text: %v", status.StatusString)
			der, err := outer.MarshalBinary()
			require.NoError(t, err)
			sent, err := pkicmp.ParsePKIMessage(der)
			require.NoError(t, err)
			assert.Equal(t, sent.Header.Sender.Raw, resp.Header.Recipient.Raw, "the refusal is addressed to the RA")
			require.Len(t, f.calls, 1)
			assert.False(t, f.issuer.called)
		})
	}
}

// RFC 9483 §5.2.2.1: the wrapper must copy transactionID and senderNonce and wrap one request.
func TestNestedMessageStructure(t *testing.T) {
	tests := []struct {
		name     string
		build    func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage
		failInfo pkicmp.PKIFailureInfo
	}{
		{
			name: "senderNonce not copied",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				inner := f.innerIR(t)
				outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner), pkicmp.MessageOptions{
					Sender:        pkicmp.NewDirectoryNameFromRawDER(f.ra.cert.RawSubject),
					TransactionID: inner.Header.TransactionID,
				})
				creds, err := pkicmp.NewSignatureCredentials(f.ra.key, f.ra.cert)
				require.NoError(t, err)
				require.NoError(t, creds.Protect(outer))
				return outer
			},
			failInfo: pkicmp.FailBadSenderNonce,
		},
		{
			name: "transactionID not copied",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				inner := f.innerIR(t)
				outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner), pkicmp.MessageOptions{
					Sender:      pkicmp.NewDirectoryNameFromRawDER(f.ra.cert.RawSubject),
					SenderNonce: inner.Header.SenderNonce,
				})
				creds, err := pkicmp.NewSignatureCredentials(f.ra.key, f.ra.cert)
				require.NoError(t, err)
				require.NoError(t, creds.Protect(outer))
				return outer
			},
			failInfo: pkicmp.FailBadRequest,
		},
		{
			name: "batch of two requests",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				return wrap(t, f.ra, f.innerIR(t), f.innerIR(t))
			},
			failInfo: pkicmp.FailBadRequest,
		},
		{
			name: "nested message inside a nested message",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				return wrap(t, f.ra, wrap(t, f.ra, f.innerIR(t)))
			},
			failInfo: pkicmp.FailBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newNestedFixture(t)
			ts := f.serve(t, server.WithRAAuthorizer(f))

			status := errorStatus(t, postCMP(t, ts, tc.build(t, f)))
			assert.Equal(t, pkicmp.StatusRejection, status.Status)
			assert.Equal(t, tc.failInfo, status.FailInfo)
			assert.Empty(t, f.calls)
			assert.False(t, f.issuer.called)
		})
	}
}

// Both protections are verified, so neither the RA nor the end entity can be impersonated.
func TestNestedProtectionVerified(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage
	}{
		{
			name: "wrapper signature invalid",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				outer := wrap(t, f.ra, f.innerIR(t))
				outer.Protection[len(outer.Protection)-1] ^= 0xff
				return outer
			},
		},
		{
			name: "inner MAC invalid",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				inner := f.innerIR(t)
				protectMAC(inner, []byte("some-other-secret"))
				return wrap(t, f.ra, inner)
			},
		},
		{
			name: "inner unprotected",
			build: func(t *testing.T, f *nestedFixture) *pkicmp.PKIMessage {
				inner := f.innerIR(t)
				inner.Header.ProtectionAlg = nil
				inner.Protection = nil
				return wrap(t, f.ra, inner)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newNestedFixture(t)
			ts := f.serve(t, server.WithRAAuthorizer(f))

			status := errorStatus(t, postCMP(t, ts, tc.build(t, f)))
			assert.Equal(t, pkicmp.StatusRejection, status.Status)
			assert.NotZero(t, status.FailInfo&(pkicmp.FailBadMessageCheck|pkicmp.FailSignerNotTrusted), "failInfo: %s", status.FailInfo)
			assert.Empty(t, f.calls)
			assert.False(t, f.issuer.called)
		})
	}
}

// Strict profile validation requires the wrapper's extraCerts (RFC 9483 §5.2.2) but ignores its sender (§5.2.2.1).
func TestNestedStrictProfile(t *testing.T) {
	signedWithChain := func(t *testing.T, f *nestedFixture, inner *pkicmp.PKIMessage) *pkicmp.PKIMessage {
		outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner), pkicmp.MessageOptions{
			Sender:        pkicmp.NewDirectoryNameFromRawDER(f.ra.cert.RawSubject),
			TransactionID: inner.Header.TransactionID,
			SenderNonce:   inner.Header.SenderNonce,
		})
		creds, err := pkicmp.NewSignatureCredentials(f.ra.key, f.ra.cert, f.caCert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(outer))
		return outer
	}

	t.Run("chain present", func(t *testing.T) {
		f := newNestedFixture(t)
		ts := f.serve(t, server.WithRAAuthorizer(f), server.WithStrictProfileValidation())
		resp := postCMP(t, ts, signedWithChain(t, f, f.innerIR(t)))
		assert.Equal(t, pkicmp.StatusAccepted, rejectionStatus(t, resp).Status)
	})

	t.Run("extraCerts missing", func(t *testing.T) {
		f := newNestedFixture(t)
		ts := f.serve(t, server.WithRAAuthorizer(f), server.WithStrictProfileValidation())
		outer := signedWithChain(t, f, f.innerIR(t))
		outer.ExtraCerts = nil
		status := errorStatus(t, postCMP(t, ts, outer))
		assert.Equal(t, pkicmp.FailBadMessageCheck, status.FailInfo)
		assert.Empty(t, f.calls)
		assert.False(t, f.issuer.called)
	})
	t.Run("MAC wrapper without sender name", func(t *testing.T) {
		f := newNestedFixture(t)
		ts := f.serve(t, server.WithRAAuthorizer(f), server.WithStrictProfileValidation())
		inner := f.innerIR(t)
		outer := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner), pkicmp.MessageOptions{
			TransactionID: inner.Header.TransactionID,
			SenderNonce:   inner.Header.SenderNonce,
		})
		outer.Header.SenderKID = []byte("mac-ra")
		creds, err := pkicmp.NewMACCredentials(f.secret)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(outer))

		status := errorStatus(t, postCMP(t, ts, outer))
		assert.Equal(t, pkicmp.FailWrongIntegrity, status.FailInfo, "the authorizer, not the sender rule, decides")
		require.Len(t, f.calls, 1)
		assert.False(t, f.issuer.called)
	})
}
