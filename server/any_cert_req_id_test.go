package server_test

import (
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

// numberedIR builds a MAC-protected ir with the given certReqId.
func numberedIR(t *testing.T, secret []byte, certReqID int64) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{
		CertReqID:    certReqID,
		CertTemplate: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(testSender), PublicKey: pub},
	}}
	require.NoError(t, request.GeneratePOP(key))
	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{request}), macMessageOpts())
	protectMAC(msg, secret)
	return msg
}

// RFC 9483 §4.1.3 requires certReqId 0. WithAnyCertReqID accepts other values and the response
// repeats them, unless the strict profile is on.
func TestAnyCertReqID(t *testing.T) {
	secret := []byte("cert-req-id-secret")
	tests := []struct {
		name      string
		opts      []server.Option
		certReqID int64
		wantText  string // status text of the refusal, empty for issuance
	}{
		{name: "ZeroAcceptedByDefault"},
		{name: "OtherRefusedByDefault", certReqID: 1023, wantText: "certReqId must be 0"},
		{name: "OtherAcceptedWithOption", opts: []server.Option{server.WithAnyCertReqID()}, certReqID: 1023},
		{name: "OtherRefusedUnderStrictProfile", opts: []server.Option{server.WithAnyCertReqID(), server.WithStrictProfileValidation()}, certReqID: 1023, wantText: "certReqId must be 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &recordingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
			opts := append([]server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}, tt.opts...)
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), opts...))
			t.Cleanup(ts.Close)
			resp := postCMP(t, ts, numberedIR(t, secret, tt.certReqID))
			si := statusInfoOf(t, resp)
			if tt.wantText != "" {
				assert.False(t, ca.called, "the CA saw a refused request")
				assert.Equal(t, pkicmp.FailBadRequest, si.FailInfo)
				assert.Equal(t, pkicmp.PKIFreeText{tt.wantText}, si.StatusString)
				return
			}
			require.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
			rep, err := resp.Body.IP()
			require.NoError(t, err)
			require.Len(t, rep.Response, 1)
			assert.Equal(t, tt.certReqID, rep.Response[0].CertReqID, "the response repeats the certReqId")
		})
	}
}
