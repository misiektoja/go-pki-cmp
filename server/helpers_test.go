package server_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// requestType identifies the CMP operation type (test-only equivalent of the removed server.RequestType).
type requestType int

const (
	requestIR    requestType = 0
	requestCR    requestType = 2
	requestP10CR requestType = 4
	requestKUR   requestType = 7
)

// certRequest is the parsed enrollment request (test-only equivalent of the removed server.CertRequest).
type certRequest struct {
	Type          requestType
	Subject       pkix.Name
	PublicKey     crypto.PublicKey
	Extensions    []pkix.Extension
	CertReqID     int64
	Sender        *server.SenderIdentity
	TransactionID []byte
	CertProfile   string
	Raw           *pkicmp.PKIMessage
}

// certResponse is what the test handler returns (test-only equivalent of the removed server.CertResponse).
type certResponse struct {
	Certificate *x509.Certificate
	CACerts     []*x509.Certificate
	Waiting     *server.WaitingResponse
}

// pollRequest is presented when the client polls (test-only).
type pollRequest struct {
	TransactionID   []byte
	CertReqID       int64
	OriginalRequest requestType
	Sender          *server.SenderIdentity
	Raw             *pkicmp.PKIMessage
}

// certConfirmation is presented when the client sends certConf (test-only).
type certConfirmation struct {
	TransactionID []byte
	Sender        *server.SenderIdentity
	Accepted      []int64
	Rejected      []int64
	Raw           *pkicmp.PKIMessage
}

// mockHandler implements server.Handler for testing using the old callback pattern.
type mockHandler struct {
	handleCertRequest func(ctx context.Context, req *certRequest) (*certResponse, error)
	handleCertConfirm func(ctx context.Context, confirm *certConfirmation) error
	handlePollRequest func(ctx context.Context, poll *pollRequest) (*certResponse, error)
}

func (m *mockHandler) HandleCMP(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return m.doCertRequest(ctx, msg, sender)
	case pkicmp.BodyTypeCertConf:
		return m.doCertConf(ctx, msg, sender)
	case pkicmp.BodyTypePollReq:
		return m.doPollReq(ctx, msg, sender)
	default:
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	}
}

func (m *mockHandler) doCertRequest(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
	if m.handleCertRequest == nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemFailure}
	}

	var rt requestType
	var certReqID int64
	var subject pkix.Name
	var pubKey crypto.PublicKey
	var extensions []pkix.Extension

	switch msg.Body.Type {
	case pkicmp.BodyTypeP10CR:
		rt = requestP10CR
		certReqID = -1
		csr, err := msg.Body.P10CR()
		if err != nil {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
		}
		subject = csr.Subject
		pubKey = csr.PublicKey
		extensions = csr.Extensions
	default:
		rt = requestType(msg.Body.Type & 0x1f)
		msgs, err := getCRMFMessages(msg)
		if err != nil || msgs == nil || len(*msgs) == 0 {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
		}
		reqMsg := (*msgs)[0]
		certReqID = reqMsg.CertReq.CertReqID
		if len(reqMsg.CertReq.CertTemplate.Subject.DirectoryName) > 0 {
			subject.FillFromRDNSequence(&reqMsg.CertReq.CertTemplate.Subject.DirectoryName)
		}
		if len(reqMsg.CertReq.CertTemplate.PublicKey) > 0 {
			pubKey, _ = x509.ParsePKIXPublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
		}
		if len(reqMsg.CertReq.CertTemplate.Extensions) > 0 {
			asn1.Unmarshal(reqMsg.CertReq.CertTemplate.Extensions, &extensions)
		}
	}

	req := &certRequest{
		Type:          rt,
		Subject:       subject,
		PublicKey:     pubKey,
		Extensions:    extensions,
		CertReqID:     certReqID,
		Sender:        sender,
		TransactionID: msg.Header.TransactionID,
		CertProfile:   msg.Header.CertProfile(),
		Raw:           msg,
	}

	resp, err := m.handleCertRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return &server.Response{
		Certificate: resp.Certificate,
		CACerts:     resp.CACerts,
		Waiting:     resp.Waiting,
	}, nil
}

func (m *mockHandler) doCertConf(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
	if m.handleCertConfirm == nil {
		return nil, nil
	}

	conf, err := msg.Body.CertConf()
	if err != nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
	}

	confirmation := &certConfirmation{
		TransactionID: msg.Header.TransactionID,
		Sender:        sender,
		Raw:           msg,
	}

	issuedCert := server.IssuedCertFromContext(ctx)

	if len(*conf) == 0 {
		confirmation.Rejected = []int64{0}
	} else {
		for _, cs := range *conf {
			accepted := true
			if issuedCert != nil {
				var hash crypto.Hash
				switch issuedCert.SignatureAlgorithm {
				case x509.ECDSAWithSHA256, x509.SHA256WithRSA:
					hash = crypto.SHA256
				case x509.ECDSAWithSHA384, x509.SHA384WithRSA:
					hash = crypto.SHA384
				case x509.ECDSAWithSHA512, x509.SHA512WithRSA:
					hash = crypto.SHA512
				default:
					// hash stays zero, which skips the certHash check below.
				}
				if hash != 0 {
					h := hash.New()
					h.Write(issuedCert.Raw)
					expected := h.Sum(nil)
					if !bytes.Equal(cs.CertHash, expected) {
						accepted = false
					}
				}
			}
			if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusRejection {
				accepted = false
			}
			if accepted {
				confirmation.Accepted = append(confirmation.Accepted, cs.CertReqID)
			} else {
				confirmation.Rejected = append(confirmation.Rejected, cs.CertReqID)
			}
		}
	}

	if err := m.handleCertConfirm(ctx, confirmation); err != nil {
		return nil, err
	}
	return nil, nil
}

func (m *mockHandler) doPollReq(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
	if m.handlePollRequest == nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemFailure}
	}

	pollReqContent, err := msg.Body.PollReq()
	if err != nil {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
	}

	var certReqID int64
	if len(*pollReqContent) > 0 {
		certReqID = (*pollReqContent)[0]
	}

	poll := &pollRequest{
		TransactionID: msg.Header.TransactionID,
		CertReqID:     certReqID,
		Sender:        sender,
		Raw:           msg,
	}

	resp, err := m.handlePollRequest(ctx, poll)
	if err != nil {
		return nil, err
	}
	return &server.Response{
		Certificate: resp.Certificate,
		CACerts:     resp.CACerts,
		Waiting:     resp.Waiting,
	}, nil
}

// staticMACLookup implements server.SecretLookup with a fixed secret.
type staticMACLookup struct {
	secret []byte
}

func (l *staticMACLookup) LookupSecret(_ pkix.Name, senderKID []byte) ([]byte, error) {
	return l.secret, nil
}

// emptySecretLookup returns an empty secret.
type emptySecretLookup struct{}

func (l *emptySecretLookup) LookupSecret(_ pkix.Name, senderKID []byte) ([]byte, error) {
	return []byte{}, nil
}

// failingLookup returns an error from LookupSecret.
type failingLookup struct{}

func (l *failingLookup) LookupSecret(_ pkix.Name, senderKID []byte) ([]byte, error) {
	return nil, assert.AnError
}

// staticCertLookup implements server.CertificateLookup.
type staticCertLookup struct {
	cert *x509.Certificate
}

func (l *staticCertLookup) LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return l.cert, nil
}

// failingCertLookup returns an error.
type failingCertLookup struct{}

func (l *failingCertLookup) LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return nil, assert.AnError
}

// getCRMFMessages extracts CertReqMessages from a PKIMessage.
func getCRMFMessages(msg *pkicmp.PKIMessage) (*pkicmp.CertReqMessages, error) {
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		return msg.Body.IR()
	case pkicmp.BodyTypeCR:
		return msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		return msg.Body.KUR()
	default:
		return nil, nil
	}
}

// issueCert creates a certificate signed by the CA for the given request.
func issueCert(ca *certyaml.Certificate, req *certRequest) *x509.Certificate {
	caCert, _ := ca.X509Certificate()
	caKey, _ := ca.PrivateKey()

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, &caCert, req.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// statusInfoOf extracts the PKIStatusInfo from an error or cert response body.
func statusInfoOf(t *testing.T, msg *pkicmp.PKIMessage) pkicmp.PKIStatusInfo {
	t.Helper()
	switch msg.Body.Type {
	case pkicmp.BodyTypeError:
		content, err := msg.Body.Error()
		require.NoError(t, err)
		return content.PKIStatusInfo
	case pkicmp.BodyTypeIP:
		rep, err := msg.Body.IP()
		require.NoError(t, err)
		require.NotEmpty(t, rep.Response)
		return rep.Response[0].Status
	case pkicmp.BodyTypeCP:
		rep, err := msg.Body.CP()
		require.NoError(t, err)
		require.NotEmpty(t, rep.Response)
		return rep.Response[0].Status
	case pkicmp.BodyTypeKUP:
		rep, err := msg.Body.KUP()
		require.NoError(t, err)
		require.NotEmpty(t, rep.Response)
		return rep.Response[0].Status
	default:
		t.Fatalf("no status in body type %s", msg.Body.Type)
		return pkicmp.PKIStatusInfo{}
	}
}

// testSender is the default sender name used in MAC-protected test messages.
var testSender = pkix.Name{CommonName: "test"}

// macMessageOpts returns MessageOptions with a directoryName sender for MAC tests.
func macMessageOpts() pkicmp.MessageOptions {
	return pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryName(testSender),
	}
}

// protectMAC sets senderKID and applies MAC protection to a message.
func protectMAC(msg *pkicmp.PKIMessage, secret []byte) {
	msg.Header.SenderKID = []byte(testSender.String())
	{
		_mc, _ := pkicmp.NewMACCredentials(secret)
		_ = _mc.Protect(msg)
	}
}
