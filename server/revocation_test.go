package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// revokingCA revokes the certificates it knows and records what it was asked.
type revokingCA struct {
	mu      sync.Mutex
	issued  []*x509.Certificate
	revoked map[string]pkicmp.CRLReason
	calls   int
}

// IssueCertificate refuses every request, since these tests exercise revocation only.
func (c *revokingCA) IssueCertificate(context.Context, server.RequestType, *x509.Certificate, *server.SenderIdentity) (*server.Response, error) {
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
}

// RevokeCertificate revokes a known certificate once and reports certRevoked afterwards.
func (c *revokingCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, _ *server.SenderIdentity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	var cert *x509.Certificate
	for _, issued := range c.issued {
		if issued.SerialNumber.Cmp(req.SerialNumber) == 0 {
			cert = issued
		}
	}
	if err := req.Match(cert); err != nil {
		return err
	}
	if _, ok := c.revoked[cert.SerialNumber.String()]; ok {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailCertRevoked, StatusText: "certificate already revoked"}
	}
	c.revoked[cert.SerialNumber.String()] = req.Reason
	return nil
}

// LookupCertificate finds a known certificate by its subject name.
func (c *revokingCA) LookupCertificate(_ pkix.Name, subject pkix.Name, _ []byte) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// certyaml issues end-entity certificates without a subject key identifier.
	for _, cert := range c.issued {
		if cert.Subject.String() == subject.String() {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// authorizingCA lets a registration authority revoke on behalf of end entities.
type authorizingCA struct {
	*revokingCA
	ra      *x509.Certificate
	request *server.RevocationRequest
	sender  *server.SenderIdentity
}

// AuthorizeRevocation allows requests signed by the registration authority only.
func (c *authorizingCA) AuthorizeRevocation(_ context.Context, req *server.RevocationRequest, sender *server.SenderIdentity) error {
	c.request, c.sender = req, sender
	if sender.Certificate != nil && sender.Certificate.Equal(c.ra) {
		return nil
	}
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not a registration authority"}
}

// revocationEntity is a certificate and key issued by the test CA.
type revocationEntity struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// revocationFixture is a CA with one end entity and one registration authority.
type revocationFixture struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	ee      revocationEntity
	ra      revocationEntity
	backend *revokingCA
}

// newRevocationFixture issues the end entity and registration authority certificates.
func newRevocationFixture(t *testing.T) *revocationFixture {
	t.Helper()
	ca := &certyaml.Certificate{Subject: "CN=Revocation CA", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)

	entity := func(subject string) revocationEntity {
		c := &certyaml.Certificate{Subject: subject, Issuer: ca}
		cert, err := c.X509Certificate()
		require.NoError(t, err)
		key, err := c.PrivateKey()
		require.NoError(t, err)
		return revocationEntity{cert: &cert, key: key}
	}
	f := &revocationFixture{
		caCert: &caCert,
		caKey:  caKey,
		ee:     entity("CN=revocation-ee"),
		ra:     entity("CN=revocation-ra"),
	}
	f.backend = &revokingCA{issued: []*x509.Certificate{f.ee.cert, f.ra.cert}, revoked: map[string]pkicmp.CRLReason{}}
	return f
}

// serve starts a server for ca protected with the CA key.
func (f *revocationFixture) serve(t *testing.T, ca server.CA, policy func(server.Handler) server.Handler, opts ...server.Option) *httptest.Server {
	t.Helper()
	opts = append([]server.Option{
		server.WithSigner(f.caKey, f.caCert),
		server.WithCertificateLookup(f.backend),
		server.WithSecretLookup(&staticMACLookup{secret: []byte("revocation-secret")}),
	}, opts...)
	srv := server.NewCAServer(ca, policy, opts...)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// details returns RevDetails naming cert with the given reason.
func revDetails(t *testing.T, cert *x509.Certificate, reason pkicmp.CRLReason) pkicmp.RevDetails {
	t.Helper()
	details, err := pkicmp.NewRevDetails(cert, reason)
	require.NoError(t, err)
	return details
}

// signedRR builds an rr carrying content and signed by signer.
func signedRR(t *testing.T, signer revocationEntity, content pkicmp.RevReqContent, opts pkicmp.MessageOptions) *pkicmp.PKIMessage {
	t.Helper()
	opts.Sender = pkicmp.NewDirectoryNameFromRawDER(signer.cert.RawSubject)
	msg := pkicmp.NewPKIMessage(pkicmp.NewRRBody(&content), opts)
	creds, err := pkicmp.NewSignatureCredentials(signer.key, signer.cert)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	return msg
}

// rpStatus returns the single status of an rp.
func rpStatus(t *testing.T, msg *pkicmp.PKIMessage) pkicmp.PKIStatusInfo {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeRP, msg.Body.Type, "expected rp, got %s", msg.Body.Type)
	rep, err := msg.Body.RP()
	require.NoError(t, err)
	require.Len(t, rep.Status, 1)
	return rep.Status[0]
}

// RFC 9483 §4.2: an end entity revokes its own certificate with a signed rr.
func TestRevocationOfOwnCertificate(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, f.backend, server.LightweightPolicy())

	req := signedRR(t, f.ee, pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonKeyCompromise)}, pkicmp.MessageOptions{})
	resp := postCMP(t, ts, req)

	si := rpStatus(t, resp)
	assert.Equal(t, pkicmp.StatusAccepted, si.Status)
	assert.Zero(t, si.FailInfo, "RFC 9483 §4.2 forbids failInfo in an accepted rp")
	assert.Equal(t, pkicmp.CRLReasonKeyCompromise, f.backend.revoked[f.ee.cert.SerialNumber.String()])

	// RFC 9483 §3.3: the rp carries the CMP protection certificate first.
	assert.Equal(t, req.Header.TransactionID, resp.Header.TransactionID)
	assert.Equal(t, req.Header.SenderNonce, resp.Header.RecipNonce)
	require.NotEmpty(t, resp.ExtraCerts)
	first, err := resp.ExtraCerts[0].Parse()
	require.NoError(t, err)
	assert.True(t, first.Equal(f.caCert))
	_, err = resp.Verify(pkicmp.VerifyOptions{RequiredProtection: pkicmp.ProtectionSignature, TrustedCert: f.caCert})
	assert.NoError(t, err)

	// RFC 9483 §5.1.3: a second revocation is rejected with certRevoked.
	again := postCMP(t, ts, signedRR(t, f.ee, pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonKeyCompromise)}, pkicmp.MessageOptions{}))
	si = rpStatus(t, again)
	assert.Equal(t, pkicmp.StatusRejection, si.Status)
	assert.Equal(t, pkicmp.FailCertRevoked, si.FailInfo)
}

// Only the certificate being revoked may sign the rr unless the CA authorizes other signers.
func TestRevocationBySignerOtherThanTarget(t *testing.T) {
	f := newRevocationFixture(t)
	content := pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonSuperseded)}

	t.Run("NoAuthorizer", func(t *testing.T) {
		ts := f.serve(t, f.backend, server.LightweightPolicy())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ra, content, pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.StatusRejection, si.Status)
		assert.Equal(t, pkicmp.FailNotAuthorized, si.FailInfo)
		assert.Zero(t, f.backend.calls, "an unauthorized request must not reach the CA")
	})

	t.Run("AuthorizerAllows", func(t *testing.T) {
		ca := &authorizingCA{revokingCA: f.backend, ra: f.ra.cert}
		ts := f.serve(t, ca, server.LightweightPolicy())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ra, content, pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status)

		require.NotNil(t, ca.request)
		assert.Equal(t, 0, ca.request.SerialNumber.Cmp(f.ee.cert.SerialNumber))
		assert.Equal(t, f.ee.cert.RawIssuer, ca.request.RawIssuer)
		assert.Equal(t, "Revocation CA", ca.request.Issuer.CommonName)
		assert.Equal(t, pkicmp.CRLReasonSuperseded, ca.request.Reason)
		require.Len(t, ca.request.Extensions, 1)
		assert.True(t, ca.sender.Certificate.Equal(f.ra.cert))
		assert.Equal(t, pkicmp.CRLReasonSuperseded, f.backend.revoked[f.ee.cert.SerialNumber.String()])
	})

	t.Run("AuthorizerDenies", func(t *testing.T) {
		other := newRevocationFixture(t)
		ca := &authorizingCA{revokingCA: other.backend, ra: other.ra.cert}
		ts := other.serve(t, ca, server.LightweightPolicy())
		// The end entity names the registration authority's certificate.
		content := pkicmp.RevReqContent{revDetails(t, other.ra.cert, pkicmp.CRLReasonUnspecified)}
		si := rpStatus(t, postCMP(t, ts, signedRR(t, other.ee, content, pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.FailNotAuthorized, si.FailInfo)
		assert.Zero(t, other.backend.calls)
	})
}

// RFC 9483 §4.2 requires signature protection, and without the policy MAC senders still need authorization.
func TestRevocationWithMACProtection(t *testing.T) {
	f := newRevocationFixture(t)
	secret := []byte("revocation-secret")
	newMsg := func() *pkicmp.PKIMessage {
		msg := pkicmp.NewPKIMessage(pkicmp.NewRRBody(&pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonKeyCompromise)}), macMessageOpts())
		protectMAC(msg, secret)
		return msg
	}

	t.Run("LightweightPolicy", func(t *testing.T) {
		ts := f.serve(t, f.backend, server.LightweightPolicy())
		si := rpStatus(t, postCMP(t, ts, newMsg()))
		assert.Equal(t, pkicmp.FailWrongIntegrity, si.FailInfo)
	})

	t.Run("NoPolicy", func(t *testing.T) {
		ts := f.serve(t, f.backend, nil)
		si := rpStatus(t, postCMP(t, ts, newMsg()))
		assert.Equal(t, pkicmp.FailNotAuthorized, si.FailInfo)
	})

	assert.Zero(t, f.backend.calls)
}

// RFC 9483 §4.2 content rules, reported in the rp as §3.6.2 asks for body problems.
func TestRevocationRequestValidation(t *testing.T) {
	f := newRevocationFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSPKI, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	require.NoError(t, err)

	reasonExtension := func(t *testing.T, codes ...int) []byte {
		exts := make([]pkix.Extension, 0, len(codes))
		for _, code := range codes {
			value, err := asn1.Marshal(asn1.Enumerated(code))
			require.NoError(t, err)
			exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: value})
		}
		der, err := asn1.Marshal(exts)
		require.NoError(t, err)
		return der
	}

	tests := []struct {
		name     string
		policy   func(server.Handler) server.Handler
		content  func(t *testing.T) pkicmp.RevReqContent
		wantFail pkicmp.PKIFailureInfo
		wantText string
	}{
		{
			name: "MissingSerial",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CertDetails.SerialNumber = nil
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailAddInfoNotAvailable,
			wantText: "serialNumber required",
		},
		{
			name: "MissingIssuer",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CertDetails.Issuer = nil
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailAddInfoNotAvailable,
			wantText: "issuer required",
		},
		{
			name: "EmptyIssuer",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CertDetails.Issuer = []byte{0x30, 0x00}
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailAddInfoNotAvailable,
			wantText: "issuer required",
		},
		{
			name: "MultipleRevDetails",
			content: func(t *testing.T) pkicmp.RevReqContent {
				return pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified), revDetails(t, f.ra.cert, pkicmp.CRLReasonUnspecified)}
			},
			wantFail: pkicmp.FailBadRequest,
			wantText: "multiple RevDetails not supported",
		},
		{
			name: "TwoReasonCodes",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CRLEntryDetails = reasonExtension(t, 6, 8)
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailBadRequest,
			wantText: "more than one reasonCode",
		},
		{
			name: "UnusedReasonCode",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CRLEntryDetails = reasonExtension(t, 7)
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailBadDataFormat,
			wantText: "invalid reasonCode",
		},
		{
			name: "MissingReasonCode",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CRLEntryDetails = nil
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailBadRequest,
			wantText: "reasonCode required",
		},
		{
			name: "SubjectMismatch",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CertDetails.Subject = pkicmp.NewDirectoryName(pkix.Name{CommonName: "someone-else"})
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailBadCertId,
			wantText: "subject does not match the certificate",
		},
		{
			name: "PublicKeyMismatch",
			content: func(t *testing.T) pkicmp.RevReqContent {
				d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
				d.CertDetails.PublicKey = otherSPKI
				return pkicmp.RevReqContent{d}
			},
			wantFail: pkicmp.FailBadCertId,
			wantText: "public key does not match the certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := f.serve(t, f.backend, server.LightweightPolicy())
			si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, tt.content(t), pkicmp.MessageOptions{})))
			assert.Equal(t, pkicmp.StatusRejection, si.Status)
			assert.Equal(t, tt.wantFail, si.FailInfo)
			assert.Equal(t, pkicmp.PKIFreeText{tt.wantText}, si.StatusString)
		})
	}
	assert.Empty(t, f.backend.revoked)
}

// The template may repeat the subject and public key of the certificate being revoked.
func TestRevocationWithMatchingTemplateHints(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, f.backend, nil)

	d := revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)
	d.CertDetails.Subject = pkicmp.NewDirectoryName(f.ee.cert.Subject)
	d.CertDetails.PublicKey = f.ee.cert.RawSubjectPublicKeyInfo
	// Without LightweightPolicy a request without a reason code is accepted as unspecified.
	d.CRLEntryDetails = nil

	si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, pkicmp.RevReqContent{d}, pkicmp.MessageOptions{})))
	assert.Equal(t, pkicmp.StatusAccepted, si.Status)
	reason, ok := f.backend.revoked[f.ee.cert.SerialNumber.String()]
	require.True(t, ok)
	assert.Equal(t, pkicmp.CRLReasonUnspecified, reason)
}

// An issuer encoded with other string types than the certificate still names the same CA.
func TestRevocationIssuerStringTypes(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, f.backend, server.LightweightPolicy())

	var issuer pkix.RDNSequence
	_, err := asn1.Unmarshal(f.ee.cert.RawIssuer, &issuer)
	require.NoError(t, err)
	for i := range issuer {
		for j := range issuer[i] {
			if s, ok := issuer[i][j].Value.(string); ok {
				issuer[i][j].Value = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(s)}
			}
		}
	}
	utf8Issuer, err := asn1.Marshal(issuer)
	require.NoError(t, err)
	require.NotEqual(t, f.ee.cert.RawIssuer, utf8Issuer)

	d := revDetails(t, f.ee.cert, pkicmp.CRLReasonAffiliationChanged)
	d.CertDetails.Issuer = utf8Issuer
	si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, pkicmp.RevReqContent{d}, pkicmp.MessageOptions{})))
	assert.Equal(t, pkicmp.StatusAccepted, si.Status)
	assert.Equal(t, pkicmp.CRLReasonAffiliationChanged, f.backend.revoked[f.ee.cert.SerialNumber.String()])
}

// A CA that does not implement server.Revoker rejects every rr.
func TestRevocationNotSupported(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, &issueOnlyCA{}, server.LightweightPolicy())

	si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)}, pkicmp.MessageOptions{})))
	assert.Equal(t, pkicmp.FailBadRequest, si.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"revocation not supported"}, si.StatusString)
}

// Custom handlers decide how an rr is answered through their error or response.
func TestRevocationHandlerResults(t *testing.T) {
	f := newRevocationFixture(t)
	serve := func(t *testing.T, h server.HandlerFunc) *httptest.Server {
		srv := server.New(h, server.WithSigner(f.caKey, f.caCert), server.WithCertificateLookup(f.backend))
		require.NoError(t, srv.Err())
		ts := httptest.NewServer(srv)
		t.Cleanup(ts.Close)
		return ts
	}
	rr := func(t *testing.T) *pkicmp.PKIMessage {
		return signedRR(t, f.ee, pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)}, pkicmp.MessageOptions{})
	}

	t.Run("WaitingIsNotSupported", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: 10}}, nil
		})
		si := rpStatus(t, postCMP(t, ts, rr(t)))
		assert.Equal(t, pkicmp.StatusRejection, si.Status)
		assert.Equal(t, pkicmp.FailSystemFailure, si.FailInfo)
	})

	t.Run("MessageCheckFailureUsesErrorMessage", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck}
		})
		resp := postCMP(t, ts, rr(t))
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadMessageCheck, statusInfoOf(t, resp).FailInfo)
	})

	t.Run("OtherFailureUsesRP", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertId}
		})
		assert.Equal(t, pkicmp.FailBadCertId, rpStatus(t, postCMP(t, ts, rr(t))).FailInfo)
	})
}

// An rr starts a transaction, so the RFC 9483 §3.5 header rules for first messages apply.
func TestRevocationTransactionRules(t *testing.T) {
	f := newRevocationFixture(t)
	content := pkicmp.RevReqContent{revDetails(t, f.ee.cert, pkicmp.CRLReasonUnspecified)}

	t.Run("TransactionIDReuse", func(t *testing.T) {
		ts := f.serve(t, &revokingCA{issued: f.backend.issued, revoked: map[string]pkicmp.CRLReason{}}, nil)
		txnID := []byte("revocation-transaction-id")
		first := postCMP(t, ts, signedRR(t, f.ee, content, pkicmp.MessageOptions{TransactionID: txnID}))
		assert.Equal(t, pkicmp.StatusAccepted, rpStatus(t, first).Status)

		second := postCMP(t, ts, signedRR(t, f.ee, content, pkicmp.MessageOptions{TransactionID: txnID}))
		require.Equal(t, pkicmp.BodyTypeError, second.Body.Type)
		assert.Equal(t, pkicmp.FailTransactionIdInUse, statusInfoOf(t, second).FailInfo)
	})

	t.Run("RecipNonce", func(t *testing.T) {
		ts := f.serve(t, f.backend, nil)
		resp := postCMP(t, ts, signedRR(t, f.ee, content, pkicmp.MessageOptions{RecipNonce: make([]byte, 16)}))
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, statusInfoOf(t, resp).FailInfo)
	})

	t.Run("StrictProfileRequiresExtraCerts", func(t *testing.T) {
		ts := f.serve(t, f.backend, server.LightweightPolicy(), server.WithStrictProfileValidation())
		msg := signedRR(t, f.ee, content, pkicmp.MessageOptions{})
		msg.ExtraCerts = nil
		resp := postCMP(t, ts, msg)
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadMessageCheck, statusInfoOf(t, resp).FailInfo)
	})

	assert.Empty(t, f.backend.revoked)
}

// A Match against a missing certificate reports badCertId.
func TestRevocationRequestMatchNil(t *testing.T) {
	req := &server.RevocationRequest{SerialNumber: big.NewInt(1)}
	err := req.Match(nil)
	var srvErr *server.Error
	require.ErrorAs(t, err, &srvErr)
	assert.Equal(t, pkicmp.FailBadCertId, srvErr.FailureInfo)
}
