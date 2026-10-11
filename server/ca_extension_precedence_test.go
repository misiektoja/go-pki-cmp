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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// oidKeyUsageExt identifies the RFC 5280 §4.2.1.3 keyUsage extension.
var oidKeyUsageExt = asn1.ObjectIdentifier{2, 5, 29, 15}

// keyUsageExtension builds a critical keyUsage extension carrying a single named bit.
func keyUsageExtension(t *testing.T, bit int) pkix.Extension {
	t.Helper()
	// KeyUsage is a BIT STRING; bit 5 is keyCertSign.
	der, err := asn1.Marshal(asn1.BitString{Bytes: []byte{byte(0x80 >> bit)}, BitLength: bit + 1})
	require.NoError(t, err)
	return pkix.Extension{Id: oidKeyUsageExt, Critical: true, Value: der}
}

// keyUsageCA issues a certificate after assigning KeyUsage, optionally dropping a requested keyUsage first.
type keyUsageCA struct {
	ca              *certyaml.Certificate
	stripRequestedX bool
	gotExtraExts    []pkix.Extension
}

func (c *keyUsageCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.gotExtraExts = slices.Clone(tmpl.ExtraExtensions)

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

	if c.stripRequestedX {
		tmpl.ExtraExtensions = slices.DeleteFunc(tmpl.ExtraExtensions, func(e pkix.Extension) bool {
			return e.Id.Equal(oidKeyUsageExt)
		})
	}
	// The assignment the package documentation warns about: it only takes effect
	// when no requested keyUsage extension remains in ExtraExtensions.
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature

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

func (c *keyUsageCA) LookupSecret(_ pkix.Name, _ []byte) ([]byte, error) {
	return []byte("ku-secret"), nil
}

// enrollRequestingKeyCertSign enrolls once with a requested keyUsage of keyCertSign.
func enrollRequestingKeyCertSign(t *testing.T, ca *keyUsageCA) *x509.Certificate {
	t.Helper()
	// No policy wrapper: this pins what a bare CA server does on its own. The
	// response is MAC-protected in reply to the MAC-protected request, so the
	// client needs no trust anchors.
	srv := server.NewCAServer(ca, nil,
		server.WithSecretLookup(ca),
		server.WithImplicitConfirm(),
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("ku-secret"))
	require.NoError(t, err)

	result, err := client.NewClient(ts.URL).SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "ku-test"}),
		client.WithTemplateExtension(keyUsageExtension(t, 5)),
		client.WithSender(pkix.Name{CommonName: "ku-test"}),
	)
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
	return result.Certificate
}

// TestRequestedKeyUsageReachesTheCAUnvetted pins that requested extensions are handed to the CA rather than filtered.
func TestRequestedKeyUsageReachesTheCAUnvetted(t *testing.T) {
	ca := &keyUsageCA{ca: &certyaml.Certificate{Subject: "CN=KU Test CA"}, stripRequestedX: true}
	enrollRequestingKeyCertSign(t, ca)

	assert.True(t, slices.ContainsFunc(ca.gotExtraExts, func(e pkix.Extension) bool {
		return e.Id.Equal(oidKeyUsageExt)
	}), "the requested keyUsage must reach the CA so it can vet or drop it")
}

// TestRequestedKeyUsageOverridesTheCAAssignment pins the precedence trap the package documentation describes.
func TestRequestedKeyUsageOverridesTheCAAssignment(t *testing.T) {
	ca := &keyUsageCA{ca: &certyaml.Certificate{Subject: "CN=KU Test CA"}, stripRequestedX: false}
	issued := enrollRequestingKeyCertSign(t, ca)

	// The CA assigned digitalSignature, yet the requested keyCertSign is issued.
	// If this ever stops holding, the warning in server/doc.go must be revisited.
	assert.Equal(t, x509.KeyUsageCertSign, issued.KeyUsage,
		"a requested keyUsage extension takes precedence over the assigned template field")
}

// TestDroppingRequestedKeyUsageRestoresCAControl pins the remedy the package documentation prescribes.
func TestDroppingRequestedKeyUsageRestoresCAControl(t *testing.T) {
	ca := &keyUsageCA{ca: &certyaml.Certificate{Subject: "CN=KU Test CA"}, stripRequestedX: true}
	issued := enrollRequestingKeyCertSign(t, ca)

	assert.Equal(t, x509.KeyUsageDigitalSignature, issued.KeyUsage,
		"dropping the requested keyUsage lets the CA decide the key usage")
	assert.Zero(t, issued.KeyUsage&x509.KeyUsageCertSign, "keyCertSign must not survive")
}
