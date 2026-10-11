package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// subjectlessRequest returns a MAC-protected request without a subject, a
// p10cr when p10cr is set and an ir otherwise. It requests a subjectAltName
// with one DNS name unless withSAN is false.
func subjectlessRequest(t *testing.T, secret []byte, p10cr, withSAN bool) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var body *pkicmp.PKIBody
	if p10cr {
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
		if withSAN {
			names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("device.example.test")}})
			require.NoError(t, err)
			exts, err := asn1.Marshal([]pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: names}})
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

// RFC 9483 §4.1.1 requires a subject. WithOptionalSubject accepts its absence
// when the request names the entity in subjectAltName, as RFC 5280 §4.1.2.6 allows.
func TestOptionalSubject(t *testing.T) {
	secret := []byte("optional-subject-secret")
	for _, p10cr := range []bool{false, true} {
		name := "CRMF"
		if p10cr {
			name = "PKCS10"
		}
		t.Run(name, func(t *testing.T) {
			tests := []struct {
				name     string
				opts     []server.Option
				withSAN  bool
				wantText string // status text of a badCertTemplate refusal, empty for issuance
			}{
				{name: "RefusedByDefault", withSAN: true, wantText: "subject required"},
				{name: "AcceptedWithOption", opts: []server.Option{server.WithOptionalSubject()}, withSAN: true},
				{name: "OptionStillNeedsSubjectAltName", opts: []server.Option{server.WithOptionalSubject()}, wantText: "subject or subjectAltName required"},
				{name: "RefusedUnderStrictProfile", opts: []server.Option{server.WithOptionalSubject(), server.WithStrictProfileValidation()}, withSAN: true, wantText: "subject required"},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					ts, ca := newConfirmingServer(t, secret, tt.opts...)
					si := statusInfoOf(t, postCMP(t, ts, subjectlessRequest(t, secret, p10cr, tt.withSAN)))
					if tt.wantText == "" {
						require.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
						assert.Empty(t, ca.template.Subject.String())
						return
					}
					assert.Equal(t, pkicmp.FailBadCertTemplate, si.FailInfo)
					assert.Equal(t, pkicmp.PKIFreeText{tt.wantText}, si.StatusString)
				})
			}
		})
	}
}
