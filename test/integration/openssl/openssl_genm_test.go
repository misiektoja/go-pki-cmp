//go:build integration

package openssl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// genmRoot is a CA certificate and its key.
type genmRoot struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newGenMRoot returns a self-signed root CA.
func newGenMRoot(t *testing.T, name string) genmRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return genmRoot{cert: signGenMCert(t, name, key.Public(), nil, key), key: key}
}

// signGenMCert issues a CA certificate for pub, self-signed when parent is nil.
func signGenMCert(t *testing.T, name string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// genmCRL returns a CRL issued by root with the given thisUpdate.
func genmCRL(t *testing.T, root genmRoot, thisUpdate time.Time) *x509.RevocationList {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(thisUpdate.Unix()),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(24 * time.Hour),
	}, root.cert, root.key)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}

// rootRollover is an old root, a new root and the RFC 4210 §4.4 link certificates.
type rootRollover struct {
	oldRoot, newRoot genmRoot
	update           *pkicmp.RootCAKeyUpdate
}

// newRootRollover builds a complete root CA key update. The root keeps its
// name across the key change, as in RFC 4210 §4.4, and the OpenSSL mock
// server answers only a request for a root of the same name.
func newRootRollover(t *testing.T) rootRollover {
	t.Helper()
	oldRoot, newRoot := newGenMRoot(t, "Test Root"), newGenMRoot(t, "Test Root")
	return rootRollover{
		oldRoot: oldRoot,
		newRoot: newRoot,
		update: &pkicmp.RootCAKeyUpdate{
			NewWithNew: newRoot.cert,
			NewWithOld: signGenMCert(t, "Test Root", newRoot.key.Public(), oldRoot.cert, oldRoot.key),
			OldWithNew: signGenMCert(t, "Test Root", oldRoot.key.Public(), newRoot.cert, newRoot.key),
		},
	}
}

// RFC 9483 §4.3 against the OpenSSL mock server.
func TestOpenSSLSupportMessages(t *testing.T) {
	r := newRootRollover(t)
	crlIssuer := newGenMRoot(t, "CRL Issuer")
	crlTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	crl := genmCRL(t, crlIssuer, crlTime)
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		RspNewWithNew: r.update.NewWithNew,
		RspNewWithOld: r.update.NewWithOld,
		RspOldWithNew: r.update.OldWithNew,
		RspCRL:        crl,
		RefCert:       true,
	})

	creds, err := pkicmp.NewSignatureCredentials(srv.ClientKey, srv.ClientCert)
	require.NoError(t, err)
	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	ctx := context.Background()

	t.Run("CACertificates", func(t *testing.T) {
		certs, err := c.GetCACertificates(ctx, creds)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.True(t, certs[0].Equal(srv.CACert))
	})

	t.Run("RootCAUpdate", func(t *testing.T) {
		update, err := c.GetRootCAUpdate(ctx, r.oldRoot.cert, creds)
		require.NoError(t, err)
		require.NotNil(t, update)
		assert.True(t, update.NewWithNew.Equal(r.update.NewWithNew))
		assert.True(t, update.NewWithOld.Equal(r.update.NewWithOld))
		assert.True(t, update.OldWithNew.Equal(r.update.OldWithNew))
	})

	t.Run("CertReqTemplate", func(t *testing.T) {
		if opensslMajorVersion(t) < 4 {
			t.Skip("the OpenSSL 3 mock server crashes on a certReqTemplate request")
		}
		// The mock server names the issuer of the reference certificate and
		// accepts EC keys and 4096-bit RSA keys.
		tmpl, err := c.GetCertReqTemplate(ctx, creds)
		require.NoError(t, err)
		require.NotNil(t, tmpl)
		assert.Equal(t, srv.RspCert.RawIssuer, tmpl.Template.Issuer)
		require.Len(t, tmpl.KeySpec, 2)
		assert.True(t, tmpl.KeySpec[0].Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 11}), "id-regCtrl-algId")
		assert.True(t, tmpl.KeySpec[1].Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 12}), "id-regCtrl-rsaKeyLen")
	})

	t.Run("CRLUpdate", func(t *testing.T) {
		source := pkicmp.NewCRLIssuerSource(crl.RawIssuer)
		got, err := c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: source}, creds)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, crl.Raw, got.Raw)

		got, err = c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: source, ThisUpdate: crlTime.Add(-time.Hour)}, creds)
		require.NoError(t, err)
		require.NotNil(t, got, "an older CRL is held")

		got, err = c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: source, ThisUpdate: crlTime}, creds)
		require.NoError(t, err)
		assert.Nil(t, got, "the CRL held is current")
	})
}

// opensslMajorVersion returns the major version of the openssl binary in PATH.
func opensslMajorVersion(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("openssl", "version").Output()
	require.NoError(t, err)
	// The output starts with "OpenSSL 3.5.6 7 Apr 2026".
	fields := strings.Fields(string(out))
	require.GreaterOrEqual(t, len(fields), 2, "openssl version output %q", out)
	major, _, _ := strings.Cut(fields[1], ".")
	n, err := strconv.Atoi(major)
	require.NoError(t, err, "openssl version output %q", out)
	return n
}

// supportCA answers general messages and authenticates its one end entity.
type supportCA struct {
	revocationCA
	caCerts  []*x509.Certificate
	update   *pkicmp.RootCAKeyUpdate
	template *pkicmp.CertReqTemplate
	crl      *x509.RevocationList

	oldRoot *x509.Certificate
	source  pkicmp.CRLSource
}

// CACertificates returns the configured CA certificates.
func (c *supportCA) CACertificates(context.Context, *server.SenderIdentity) ([]*x509.Certificate, error) {
	return c.caCerts, nil
}

// RootCAUpdate records the root the client names and returns the configured update.
func (c *supportCA) RootCAUpdate(_ context.Context, oldRoot *x509.Certificate, _ *server.SenderIdentity) (*pkicmp.RootCAKeyUpdate, error) {
	c.oldRoot = oldRoot
	return c.update, nil
}

// CertReqTemplate returns the configured template.
func (c *supportCA) CertReqTemplate(context.Context, string, *server.SenderIdentity) (*pkicmp.CertReqTemplate, error) {
	return c.template, nil
}

// LatestCRL records the requested source and returns the configured CRL.
func (c *supportCA) LatestCRL(_ context.Context, source pkicmp.CRLSource, _ *server.SenderIdentity) (*x509.RevocationList, error) {
	c.source = source
	return c.crl, nil
}

// readDERFile returns the DER in file, decoding the first PEM block if there is one.
func readDERFile(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes
	}
	return data
}

// RFC 9483 §4.3 with the OpenSSL client against the server package.
func TestOpenSSLClientSupportMessagesAtServer(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	dir := t.TempDir()

	ca := &certyaml.Certificate{Subject: "cn=openssl-genm-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	ee := &certyaml.Certificate{Subject: "cn=openssl-genm-ee", Issuer: ca}
	for _, c := range []*certyaml.Certificate{ca, ee} {
		require.NoError(t, c.Generate(), "generate cert for %s", c.Subject)
	}
	caFile := filepath.Join(dir, "ca.pem")
	eeCertFile := filepath.Join(dir, "ee.pem")
	eeKeyFile := filepath.Join(dir, "ee-key.pem")
	writeCertPEM(t, ca, caFile)
	writeCertPEM(t, ee, eeCertFile)
	writeKeyPEM(t, ee, eeKeyFile)
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	eeCert, err := ee.X509Certificate()
	require.NoError(t, err)

	r := newRootRollover(t)
	crlIssuer := newGenMRoot(t, "CRL Issuer")
	crlTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	backend := &supportCA{
		issued:  []*x509.Certificate{&eeCert},
		caCerts: []*x509.Certificate{&caCert},
		update:  r.update,
		template: &pkicmp.CertReqTemplate{
			Template: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(pkix.Name{Organization: []string{"Example"}})},
		},
		crl: genmCRL(t, crlIssuer, crlTime),
	}
	srv := server.NewCAServer(backend, server.LightweightPolicy(),
		server.WithSigner(caKey, &caCert),
		server.WithCertificateLookup(backend),
	)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	genm := func(t *testing.T, args ...string) string {
		t.Helper()
		out, err := runOpenSSLCMPClient(t, append([]string{
			"-cmd", "genm",
			"-server", strings.TrimPrefix(ts.URL, "http://"),
			"-path", "/",
			"-cert", eeCertFile,
			"-key", eeKeyFile,
			"-trusted", caFile,
		}, args...)...)
		require.NoError(t, err, "openssl cmp genm")
		return out
	}

	t.Run("CACertificates", func(t *testing.T) {
		out := filepath.Join(dir, "cacerts.pem")
		genm(t, "-infotype", "caCerts", "-cacertsout", out)
		assert.Equal(t, caCert.Raw, readDERFile(t, out))
	})

	t.Run("RootCAUpdate", func(t *testing.T) {
		oldFile := filepath.Join(dir, "old-root.pem")
		writePEM(t, oldFile, "CERTIFICATE", r.oldRoot.cert.Raw)
		newWithNew := filepath.Join(dir, "newwithnew.pem")
		newWithOld := filepath.Join(dir, "newwithold.pem")
		oldWithNew := filepath.Join(dir, "oldwithnew.pem")
		genm(t, "-infotype", "rootCaCert", "-oldwithold", oldFile,
			"-newwithnew", newWithNew, "-newwithold", newWithOld, "-oldwithnew", oldWithNew)
		assert.Equal(t, r.update.NewWithNew.Raw, readDERFile(t, newWithNew))
		assert.Equal(t, r.update.NewWithOld.Raw, readDERFile(t, newWithOld))
		assert.Equal(t, r.update.OldWithNew.Raw, readDERFile(t, oldWithNew))
		assert.True(t, backend.oldRoot.Equal(r.oldRoot.cert))
	})

	t.Run("CertReqTemplate", func(t *testing.T) {
		out := filepath.Join(dir, "template.der")
		genm(t, "-infotype", "certReqTemplate", "-template", out)
		info, err := os.Stat(out)
		require.NoError(t, err)
		assert.Positive(t, info.Size())
	})

	t.Run("CRLUpdateFromOldCRL", func(t *testing.T) {
		oldCRL := filepath.Join(dir, "old.crl")
		writePEM(t, oldCRL, "X509 CRL", genmCRL(t, crlIssuer, crlTime.Add(-time.Hour)).Raw)
		out := filepath.Join(dir, "new.crl")
		genm(t, "-infotype", "crlStatusList", "-oldcrl", oldCRL, "-crlout", out)
		assert.Equal(t, backend.crl.Raw, readDERFile(t, out))
		assert.Equal(t, [][]byte{crlIssuer.cert.RawSubject}, backend.source.DirectoryNames())
	})

	t.Run("UnsupportedInfoType", func(t *testing.T) {
		out := genm(t, "-infotype", "signKeyPairTypes")
		assert.Contains(t, out, "infoType=id-it-unsupportedOIDs")
	})
}
