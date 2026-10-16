package server_test

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// modifyingCA issues like confirmingCA and reports that it changed the request.
type modifyingCA struct {
	confirmingCA
}

// IssueCertificate issues the certificate and marks the response as granted with modifications.
func (c *modifyingCA) IssueCertificate(ctx context.Context, kind server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	resp, err := c.confirmingCA.IssueCertificate(ctx, kind, tmpl, sender)
	if err != nil {
		return nil, err
	}
	resp.GrantedWithMods = true
	resp.StatusText = "requested extension 1.2.3.4 left out"
	return resp, nil
}

// RFC 9810 §5.2.3: grantedWithMods delivers the certificate like accepted, with the CA's
// explanation, and the transaction is confirmed as usual.
func TestIssuedCertificateGrantedWithMods(t *testing.T) {
	secret := []byte("granted-with-mods-secret")
	ca := &modifyingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(), server.WithSecretLookup(&staticMACLookup{secret: secret})))
	t.Cleanup(ts.Close)

	ip, cert := enrollForCertConf(t, ts, secret, false)
	rep, err := ip.Body.IP()
	require.NoError(t, err)
	status := rep.Response[0].Status
	assert.Equal(t, pkicmp.StatusGrantedWithMods, status.Status)
	assert.Equal(t, pkicmp.PKIFreeText{"requested extension 1.2.3.4 left out"}, status.StatusString)
	assert.NoError(t, status.AsError())

	resp := sendCertConf(t, ts, ip, secret, certStatus(t, cert, 0, false))
	assert.Equal(t, pkicmp.BodyTypePKIConf, resp.Body.Type)
	assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
}

// An issued certificate without GrantedWithMods keeps the plain accepted status.
func TestIssuedCertificateAccepted(t *testing.T) {
	secret := []byte("accepted-secret")
	ts, _ := newConfirmingServer(t, secret)
	ip, _ := enrollForCertConf(t, ts, secret, false)
	rep, err := ip.Body.IP()
	require.NoError(t, err)
	assert.Equal(t, pkicmp.StatusAccepted, rep.Response[0].Status.Status)
	assert.Empty(t, rep.Response[0].Status.StatusString)
}
