package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// The per-credential limit counts the shared secret, not the sender name or
// senderKID the request carries, so one secret cannot escape its quota by
// naming a different sender in every request.
func TestPerCredentialLimitBindsToSharedSecret(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secrets := map[string][]byte{"kid-a": []byte("secret-a"), "kid-b": []byte("secret-b")}
	// The lookup ignores the sender name, as the package documentation shows.
	lookup := server.SecretLookupFunc(func(_ pkix.Name, kid []byte) ([]byte, error) {
		if s, ok := secrets[string(kid)]; ok {
			return s, nil
		}
		return nil, assert.AnError
	})
	handler := &mockHandler{
		handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
		},
	}
	srv := server.New(handler, server.WithSecretLookup(lookup), server.WithMaxTransactionsPerCredential(1))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enroll := func(kid, name string) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ir := pkicmp.NewPKIMessage(
			pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, name)}),
			pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(pkix.Name{CommonName: name})},
		)
		ir.Header.SenderKID = []byte(kid)
		macProtect(t, ir, secrets[kid])
		return postCMP(t, ts, ir)
	}

	// The issued certificate waits for its certConf, so the transaction holds
	// the single slot of kid-a.
	require.Equal(t, pkicmp.BodyTypeIP, enroll("kid-a", "device-1").Body.Type)

	resp := enroll("kid-a", "device-2")
	require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type, "a second sender name does not get a second quota")
	si := statusInfoOf(t, resp)
	assert.Equal(t, pkicmp.FailSystemUnavail, si.FailInfo)
	assert.Contains(t, strings.Join(si.StatusString, " "), "per-credential transaction limit reached")

	require.Equal(t, pkicmp.BodyTypeIP, enroll("kid-b", "device-3").Body.Type, "another secret has its own quota")
}
