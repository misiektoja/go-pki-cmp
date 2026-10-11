//go:build integration

// Package certifier runs the Insta Certifier CMP clients against this
// repository's server. Both clients deviate from the RFCs in places, so the
// tests check that the server defaults refuse those requests and that only the
// documented compatibility options accept them.
package certifier

import (
	"crypto"
	"crypto/x509"
	"path"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// macArgs authenticate a cmpclient request with the shared secret.
var macArgs = []string{"--kid", pskReference, "--psk", pskSecret}

// cmpclient runs "cmpclient req" against ts and writes its output files to dir/out.
func cmpclient(t *testing.T, c *clientContainer, ts *testServer, dir, out string, args ...string) string {
	t.Helper()
	c.docker(t, "exec", c.id, "mkdir", "-p", path.Join(dir, out))
	full := append([]string{"cmpclient", "req", "--url", ts.url, "--dir", out, "--recipient", caName}, args...)
	return c.run(t, dir, full...)
}

// requireIssued checks that dir/file holds a certificate for key that the
// server issued and that the client then accepted with certConf.
func requireIssued(t *testing.T, c *clientContainer, ts *testServer, dir, file string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	data := c.get(t, dir, file)
	require.NotNil(t, data, "the client saved no certificate as %s", file)
	cert := parseCertificate(t, data)
	require.NoError(t, cert.CheckSignatureFrom(ts.ca.Cert()), "certificate not issued by the test CA")
	require.True(t, samePublicKey(t, cert, key), "certificate does not certify the requested key")
	status, ok := ts.ca.confirmation(cert)
	require.True(t, ok, "the server reported no confirmation for serial %s", cert.SerialNumber)
	require.Equal(t, server.ConfirmAccepted, status)
	return cert
}

// cmpclientEnroll enrolls key under commonName with a shared-secret ir and returns the certificate and its path in dir.
func cmpclientEnroll(t *testing.T, c *clientContainer, ts *testServer, dir, keyFile string, key crypto.Signer, commonName string) (*x509.Certificate, string) {
	t.Helper()
	args := append([]string{"--type", "ir", "--subject", "CN=" + commonName, "--private", keyFile}, macArgs...)
	cmpclient(t, c, ts, dir, "enroll", args...)
	return requireIssued(t, c, ts, dir, "enroll/cert-0.pem", key), "enroll/cert-0.pem"
}

// The Insta Certifier 10 cmpclient enrolls, updates and revokes once the
// server accepts its proof of possession and its revocation request.
func TestCmpclient(t *testing.T) {
	c := clients(t)
	ts := startServer(t, c, newCA(t), server.WithPoposkInputVariants(), server.WithOptionalRevocationReason())
	// setup gives each subtest its own directory and keys.
	setup := func(t *testing.T) (dir string, ecKey, newKey crypto.Signer) {
		dir = c.workdir(t)
		ecKey, ecPEM := newECKey(t)
		newKey, newPEM := newECKey(t)
		c.put(t, dir, "ec.key", ecPEM)
		c.put(t, dir, "new.key", newPEM)
		c.put(t, dir, "ec.csr", csrPEM(t, ecKey, "cmpclient-csr"))
		return dir, ecKey, newKey
	}

	t.Run("IRWithSharedSecret", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		cert, _ := cmpclientEnroll(t, c, ts, dir, "ec.key", ecKey, "cmpclient-ir")
		assert.Equal(t, "cmpclient-ir", cert.Subject.CommonName)
	})
	t.Run("IRWithRSAKey", func(t *testing.T) {
		dir, _, _ := setup(t)
		rsaKey, rsaPEM := newRSAKey(t)
		c.put(t, dir, "rsa.key", rsaPEM)
		cmpclientEnroll(t, c, ts, dir, "rsa.key", rsaKey, "cmpclient-rsa")
	})
	t.Run("IRFromCertificateRequest", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		cmpclient(t, c, ts, dir, "out", append([]string{"--type", "ir", "--template", "ec.csr", "--private", "ec.key"}, macArgs...)...)
		cert := requireIssued(t, c, ts, dir, "out/cert-0.pem", ecKey)
		assert.Equal(t, "cmpclient-csr", cert.Subject.CommonName)
	})
	t.Run("CRWithSharedSecret", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		cmpclient(t, c, ts, dir, "out", append([]string{"--type", "cr", "--subject", "CN=cmpclient-cr", "--private", "ec.key"}, macArgs...)...)
		requireIssued(t, c, ts, dir, "out/cert-0.pem", ecKey)
	})
	t.Run("P10CRWithSharedSecret", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		cmpclient(t, c, ts, dir, "out", append([]string{"--type", "p10cr", "--template", "ec.csr", "--private", "ec.key"}, macArgs...)...)
		requireIssued(t, c, ts, dir, "out/cert-0.pem", ecKey)
	})
	t.Run("CRSignedWithIssuedCertificate", func(t *testing.T) {
		dir, ecKey, newKey := setup(t)
		_, certFile := cmpclientEnroll(t, c, ts, dir, "ec.key", ecKey, "cmpclient-signer")
		cmpclient(t, c, ts, dir, "out", "--type", "cr", "--signercert", certFile, "--signerkey", "ec.key", "--subject", "CN=cmpclient-signed-cr", "--private", "new.key")
		requireIssued(t, c, ts, dir, "out/cert-0.pem", newKey)
	})
	t.Run("KURWithNewKey", func(t *testing.T) {
		dir, ecKey, newKey := setup(t)
		old, certFile := cmpclientEnroll(t, c, ts, dir, "ec.key", ecKey, "cmpclient-kur")
		cmpclient(t, c, ts, dir, "out", "--type", "kur", "--signercert", certFile, "--signerkey", "ec.key", "--template", certFile, "--private", "new.key")
		cert := requireIssued(t, c, ts, dir, "out/cert-0.pem", newKey)
		assert.Equal(t, old.Subject.String(), cert.Subject.String())
	})
	t.Run("KURWithSameKey", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		_, certFile := cmpclientEnroll(t, c, ts, dir, "ec.key", ecKey, "cmpclient-kur-same")
		cmpclient(t, c, ts, dir, "out", "--type", "kur", "--signercert", certFile, "--signerkey", "ec.key", "--template", certFile, "--private", "ec.key")
		requireIssued(t, c, ts, dir, "out/cert-0.pem", ecKey)
	})
	t.Run("RRSignedWithRevokedCertificate", func(t *testing.T) {
		dir, ecKey, _ := setup(t)
		cert, certFile := cmpclientEnroll(t, c, ts, dir, "ec.key", ecKey, "cmpclient-rr")
		rr := []string{"--type", "rr", "--signercert", certFile, "--signerkey", "ec.key", "--serial", cert.SerialNumber.String()}
		cmpclient(t, c, ts, dir, "rr", rr...)
		reason, ok := ts.ca.revocation(cert)
		require.True(t, ok, "the server did not revoke the certificate")
		// cmpclient has no reason option and omits crlEntryDetails.
		assert.Equal(t, pkicmp.CRLReasonUnspecified, reason)

		// The revoked certificate no longer authenticates a second request.
		out := cmpclient(t, c, ts, dir, "rr-again", rr...)
		assert.Contains(t, out, "unknown sender")
	})
	t.Run("WrongSharedSecretRefused", func(t *testing.T) {
		dir, _, _ := setup(t)
		out := cmpclient(t, c, ts, dir, "out", "--type", "ir", "--kid", pskReference, "--psk", "wrong-secret", "--subject", "CN=cmpclient-wrong", "--private", "ec.key")
		assert.Contains(t, out, "MAC verification failed")
		assert.Nil(t, c.get(t, dir, "out/cert-0.pem"))
	})
	t.Run("GeneralMessageRefused", func(t *testing.T) {
		dir, _, _ := setup(t)
		out := cmpclient(t, c, ts, dir, "out", append([]string{"--type", "info"}, macArgs...)...)
		assert.Contains(t, out, "message type not supported")
	})
}

// RFC 4211 §4.1 forbids poposkInput when the template carries the subject and
// public key. RFC 9483 §4.1.1 forbids it entirely. cmpclient sends it anyway,
// so the server refuses its requests unless WithPoposkInputVariants is set.
// The strict profile always refuses them.
func TestCmpclientPoposkInputRefused(t *testing.T) {
	c := clients(t)
	_, keyPEM := newECKey(t)
	tests := []struct {
		name   string
		opts   []server.Option
		status string
	}{
		{"Default", nil, "poposkInput not allowed when the template contains the subject and public key"},
		{"StrictProfile", []server.Option{server.WithPoposkInputVariants(), server.WithStrictProfileValidation()}, "poposkInput is not allowed in the proof of possession"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := startServer(t, c, newCA(t), tt.opts...)
			dir := c.workdir(t)
			c.put(t, dir, "ec.key", keyPEM)
			// Without --sender, cmpclient sends a MAC request from the NULL-DN,
			// which the strict profile refuses before it looks at the POP.
			args := slices.Concat([]string{"--type", "ir", "--sender", "CN=cmpclient-refused", "--subject", "CN=cmpclient-refused", "--private", "ec.key"}, macArgs)
			out := cmpclient(t, c, ts, dir, "out", args...)
			assert.Contains(t, out, tt.status)
			assert.Nil(t, c.get(t, dir, "out/cert-0.pem"))
			assert.Zero(t, ts.ca.issuedCount())
		})
	}
}

// RFC 9483 §4.2 requires a reasonCode in every rr. cmpclient has no reason
// option and omits crlEntryDetails, so the server refuses its rr unless
// WithOptionalRevocationReason is set.
func TestCmpclientRevocationReasonRequired(t *testing.T) {
	c := clients(t)
	ts := startServer(t, c, newCA(t), server.WithPoposkInputVariants())
	dir := c.workdir(t)
	key, keyPEM := newECKey(t)
	c.put(t, dir, "ec.key", keyPEM)
	cert, certFile := cmpclientEnroll(t, c, ts, dir, "ec.key", key, "cmpclient-rr-reason")
	out := cmpclient(t, c, ts, dir, "rr", "--type", "rr", "--signercert", certFile, "--signerkey", "ec.key", "--serial", cert.SerialNumber.String())
	assert.Contains(t, out, "reasonCode required")
	_, revoked := ts.ca.revocation(cert)
	assert.False(t, revoked)
}

// sshCmpclient runs ssh-cmpclient operation op against ts in dir.
func sshCmpclient(t *testing.T, c *clientContainer, ts *testServer, dir, op string, args ...string) string {
	t.Helper()
	full := append([]string{"ssh-cmpclient", op, "-y", "-f", "sha256:sha256"}, args...)
	return c.run(t, dir, append(full, ts.url, caName)...)
}

// sshKey returns the PKCS #8 DER private key ssh-cmpclient generated as dir/name.prv.
func sshKey(t *testing.T, c *clientContainer, dir, name string) crypto.Signer {
	t.Helper()
	data := c.get(t, dir, name+".prv")
	require.NotNil(t, data, "ssh-cmpclient generated no key %s.prv", name)
	key, err := x509.ParsePKCS8PrivateKey(data)
	require.NoError(t, err)
	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	return signer
}

// sshInitialize enrolls a key generated from keySpec under commonName with a
// shared-secret INITIALIZE. The key is dir/a.prv and the certificate dir/a-0.crt.
func sshInitialize(t *testing.T, c *clientContainer, ts *testServer, dir, keySpec, commonName string) *x509.Certificate {
	t.Helper()
	sshCmpclient(t, c, ts, dir, "INITIALIZE", "-P", "generate://pkcs8@"+keySpec+"/a", "-o", "a", "-p", pskReference+":"+pskSecret, "-s", "CN="+commonName)
	return requireIssued(t, c, ts, dir, "a-0.crt", sshKey(t, c, dir, "a"))
}

// skipWithoutSSHClient skips the test when the image has no ssh-cmpclient.
func skipWithoutSSHClient(t *testing.T, c *clientContainer) {
	t.Helper()
	if !c.hasSSHClient {
		t.Skip("the client image has no ssh-cmpclient")
	}
}

// ssh-cmpclient, shipped with Certifier 7 and NCM, enrolls and updates with
// the server defaults.
func TestSSHCmpclient(t *testing.T) {
	c := clients(t)
	skipWithoutSSHClient(t, c)
	ts := startServer(t, c, newCA(t))

	t.Run("Initialize", func(t *testing.T) {
		cert := sshInitialize(t, c, ts, c.workdir(t), "ec:256", "ssh-init")
		assert.Equal(t, "ssh-init", cert.Subject.CommonName)
	})
	t.Run("InitializeWithRSAKey", func(t *testing.T) {
		sshInitialize(t, c, ts, c.workdir(t), "rsa:2048", "ssh-rsa")
	})
	t.Run("P10CR", func(t *testing.T) {
		dir := c.workdir(t)
		sshCmpclient(t, c, ts, dir, "P10CR", "-P", "generate://pkcs8@ec:256/p", "-o", "p", "-p", pskReference+":"+pskSecret, "-s", "CN=ssh-p10cr")
		requireIssued(t, c, ts, dir, "p-0.crt", sshKey(t, c, dir, "p"))
	})
	t.Run("EnrollSignedWithIssuedCertificate", func(t *testing.T) {
		dir := c.workdir(t)
		sshInitialize(t, c, ts, dir, "ec:256", "ssh-signer")
		sshCmpclient(t, c, ts, dir, "ENROLL", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-P", "generate://pkcs8@ec:256/e", "-o", "e", "-s", "CN=ssh-enroll")
		requireIssued(t, c, ts, dir, "e-0.crt", sshKey(t, c, dir, "e"))
	})
	t.Run("UpdateWithNewKey", func(t *testing.T) {
		dir := c.workdir(t)
		old := sshInitialize(t, c, ts, dir, "ec:256", "ssh-update")
		sshCmpclient(t, c, ts, dir, "UPDATE", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-P", "generate://pkcs8@ec:256/n", "-o", "n")
		cert := requireIssued(t, c, ts, dir, "n-0.crt", sshKey(t, c, dir, "n"))
		assert.Equal(t, old.Subject.String(), cert.Subject.String())
	})
	// Without -P, UPDATE keeps the key and sends no proof of possession.
	// RFC 4211 §4 lets the server choose how it enforces proof of possession,
	// but the default requires one in the request.
	t.Run("UpdateWithSameKeyRefused", func(t *testing.T) {
		dir := c.workdir(t)
		sshInitialize(t, c, ts, dir, "ec:256", "ssh-same-key")
		out := sshCmpclient(t, c, ts, dir, "UPDATE", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-o", "u")
		assert.Contains(t, out, "proof of possession by signature required")
		assert.Nil(t, c.get(t, dir, "u-0.crt"))
	})
	// ssh-cmpclient REVOKE sends pvno 0 even when asked for version 2, and
	// RFC 9810 §7 refuses an unsupported version.
	t.Run("RevokeRefused", func(t *testing.T) {
		dir := c.workdir(t)
		cert := sshInitialize(t, c, ts, dir, "ec:256", "ssh-revoke")
		out := sshCmpclient(t, c, ts, dir, "REVOKE", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-T", "a-0.crt", "-a", "1")
		assert.Contains(t, out, "unsupported pvno 0")
		_, revoked := ts.ca.revocation(cert)
		assert.False(t, revoked)
	})
}

// WithSignatureProtectionPOP accepts the UPDATE that keeps its key, because
// the request is signed with that key. The strict profile refuses it.
func TestSSHCmpclientSameKeyUpdate(t *testing.T) {
	c := clients(t)
	skipWithoutSSHClient(t, c)

	t.Run("Accepted", func(t *testing.T) {
		ts := startServer(t, c, newCA(t), server.WithSignatureProtectionPOP())
		dir := c.workdir(t)
		old := sshInitialize(t, c, ts, dir, "ec:256", "ssh-same-key")
		sshCmpclient(t, c, ts, dir, "UPDATE", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-o", "u")
		cert := requireIssued(t, c, ts, dir, "u-0.crt", sshKey(t, c, dir, "a"))
		assert.NotZero(t, old.SerialNumber.Cmp(cert.SerialNumber), "the update issued a new certificate")
	})
	t.Run("RefusedUnderStrictProfile", func(t *testing.T) {
		// ssh-cmpclient sends its shared-secret INITIALIZE from the NULL-DN,
		// which RFC 9483 §3.1 does not allow, so it enrolls at a second
		// server for the same CA.
		ca := newCA(t)
		enroll := startServer(t, c, ca)
		ts := startServer(t, c, ca, server.WithSignatureProtectionPOP(), server.WithStrictProfileValidation())
		dir := c.workdir(t)
		sshInitialize(t, c, enroll, dir, "ec:256", "ssh-same-key-strict")
		out := sshCmpclient(t, c, ts, dir, "UPDATE", "-k", "file://pkcs8@/a.prv", "-c", "a-0.crt", "-o", "u")
		// The request also lacks the protection certificate in extraCerts,
		// which RFC 9483 §3.3 requires. That check comes first.
		assert.Contains(t, out, "signature protection without extraCerts")
		assert.Nil(t, c.get(t, dir, "u-0.crt"))
	})
}
