package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// subjectShape is how a request without a subject name leaves it out.
type subjectShape int

const (
	// absentSubject is an ir whose template has no subject field.
	absentSubject subjectShape = iota
	// nullDNSubject is an ir whose template subject is an empty RDNSequence.
	nullDNSubject
	// p10crSubject is a p10cr, whose subject is an empty RDNSequence.
	p10crSubject
)

// subjectlessRequest returns a MAC-protected request of the given shape. It
// requests a subjectAltName with one DNS name unless withSAN is false, and
// leaves that extension non-critical as many requesters do.
func subjectlessRequest(t *testing.T, secret []byte, shape subjectShape, withSAN bool) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var body *pkicmp.PKIBody
	if shape == p10crSubject {
		tmpl := &x509.CertificateRequest{}
		if withSAN {
			tmpl.DNSNames = []string{"device.example.test"}
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		body = pkicmp.NewP10CRBody(csr)
	} else {
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)
		request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{PublicKey: pub}}}
		if shape == nullDNSubject {
			request.CertReq.CertTemplate.Subject = pkicmp.NewDirectoryNameFromRawDER([]byte{0x30, 0x00})
		}
		if withSAN {
			names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("device.example.test")}})
			require.NoError(t, err)
			exts, err := asn1.Marshal([]pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: names}})
			require.NoError(t, err)
			request.CertReq.CertTemplate.Extensions = exts
		}
		require.NoError(t, request.GeneratePOP(key))
		body = pkicmp.NewIRBody(&pkicmp.CertReqMessages{request})
	}
	msg := pkicmp.NewPKIMessage(body, macMessageOpts())
	protectMAC(msg, secret)
	return msg
}

// subjectCase is one request shape under one server configuration.
type subjectCase struct {
	name     string
	shape    subjectShape
	opts     []server.Option
	withSAN  bool
	wantText string // status text of a badCertTemplate refusal, empty for issuance
}

// RFC 9483 §4.1.1 lets a request name the entity only in subjectAltName when
// its subject is a NULL-DN. WithOptionalSubject also accepts a CRMF template
// that leaves the subject field out, which RFC 4211 permits and RFC 9483 does not.
func TestOptionalSubject(t *testing.T) {
	secret := []byte("optional-subject-secret")
	optional := []server.Option{server.WithOptionalSubject()}
	strict := []server.Option{server.WithOptionalSubject(), server.WithStrictProfileValidation()}
	tests := []subjectCase{
		{name: "AbsentRefusedByDefault", shape: absentSubject, withSAN: true, wantText: "subject required"},
		{name: "AbsentAcceptedWithOption", shape: absentSubject, opts: optional, withSAN: true},
		{name: "AbsentWithOptionNeedsSubjectAltName", shape: absentSubject, opts: optional, wantText: "subject or subjectAltName required"},
		{name: "AbsentRefusedUnderStrictProfile", shape: absentSubject, opts: strict, withSAN: true, wantText: "subject required"},
		{name: "NullDNAcceptedByDefault", shape: nullDNSubject, withSAN: true},
		{name: "NullDNAcceptedUnderStrictProfile", shape: nullDNSubject, opts: strict, withSAN: true},
		{name: "NullDNNeedsSubjectAltName", shape: nullDNSubject, wantText: "subject or subjectAltName required"},
		{name: "PKCS10AcceptedByDefault", shape: p10crSubject, withSAN: true},
		{name: "PKCS10AcceptedUnderStrictProfile", shape: p10crSubject, opts: strict, withSAN: true},
		{name: "PKCS10NeedsSubjectAltName", shape: p10crSubject, wantText: "subject or subjectAltName required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &extensionRecordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
			opts := append([]server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}, tt.opts...)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), opts...))
			t.Cleanup(ts.Close)
			si := statusInfoOf(t, postCMP(t, ts, subjectlessRequest(t, secret, tt.shape, tt.withSAN)))
			if tt.wantText == "" {
				require.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
				assert.Empty(t, ca.template.Subject.String())
				// RFC 5280 §4.2.1.6: with an empty subject the subjectAltName is critical.
				i := slices.IndexFunc(ca.extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) })
				require.GreaterOrEqual(t, i, 0, "subjectAltName did not reach the CA")
				assert.True(t, ca.extensions[i].Critical, "subjectAltName not marked critical")
				return
			}
			assert.False(t, ca.called, "the CA saw a refused request")
			assert.Equal(t, pkicmp.FailBadCertTemplate, si.FailInfo)
			assert.Equal(t, pkicmp.PKIFreeText{tt.wantText}, si.StatusString)
		})
	}
}

// extensionRecordingCA keeps the requested extensions the template carried,
// which recordingCA clears before signing.
type extensionRecordingCA struct {
	confirmingCA
	extensions []pkix.Extension
}

// IssueCertificate records the template's extensions and issues as confirmingCA does.
func (c *extensionRecordingCA) IssueCertificate(ctx context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	c.extensions = slices.Clone(tmpl.ExtraExtensions)
	return c.confirmingCA.IssueCertificate(ctx, reqType, tmpl, sender)
}
