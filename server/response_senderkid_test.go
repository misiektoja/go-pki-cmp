package server_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// RFC 9810 §5.1.1: a MAC-protected response names the shared secret that
// protects it, even when the server also has a signing key. Clients that check
// senderKID refuse a response naming the signer's key instead.
func TestMACResponseRepeatsSenderKIDWithSigner(t *testing.T) {
	secret := []byte("senderkid-secret")
	signer := &certyaml.Certificate{Subject: "CN=Response Signer"}
	cert, err := signer.X509Certificate()
	require.NoError(t, err)
	key, err := signer.PrivateKey()
	require.NoError(t, err)
	require.NotEmpty(t, cert.SubjectKeyId)

	ts, _ := newConfirmingServer(t, secret, server.WithSigner(key, &cert))
	subject, subjectDER := requestedSubject(t)
	req := rawSubjectRequest(t, secret, subject, subjectDER, false)
	resp := postCMP(t, ts, req)

	require.Equal(t, pkicmp.StatusAccepted, statusInfoOf(t, resp).Status)
	assert.Equal(t, req.Header.SenderKID, resp.Header.SenderKID)
	_, err = resp.Verify(pkicmp.VerifyOptions{SharedSecret: secret, RequiredProtection: pkicmp.ProtectionMAC})
	assert.NoError(t, err)
}
