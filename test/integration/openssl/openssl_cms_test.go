//go:build integration

package openssl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/cms"
)

var oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

// runOpenSSL runs openssl with args, logs its output and fails the test when it exits with an error.
func runOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command("openssl", args...).CombinedOutput()
	require.NoError(t, err, "openssl %s\n%s", strings.Join(args, " "), out)
	return out
}

// mlkemPKCS8 encodes an ML-KEM private key as PKCS #8 in the seed form of RFC 9935 §6.
func mlkemPKCS8(oid asn1.ObjectIdentifier, seed []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(seed)
			})
		})
	})
	return b.BytesOrPanic()
}

// wrapContentInfo wraps an EnvelopedData in the ContentInfo that "openssl cms" reads.
func wrapContentInfo(envelopedData []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidEnvelopedData)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddBytes(envelopedData)
		})
	})
	return b.BytesOrPanic()
}

// unwrapContentInfo returns the EnvelopedData inside the ContentInfo that "openssl cms" writes.
func unwrapContentInfo(t *testing.T, der []byte) []byte {
	t.Helper()
	s := cryptobyte.String(der)
	var seq, explicit, inner cryptobyte.String
	var oid asn1.ObjectIdentifier
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1ObjectIdentifier(&oid) && oid.Equal(oidEnvelopedData))
	require.True(t, seq.ReadASN1(&explicit, cbasn1.Tag(0).ContextSpecific().Constructed()) && explicit.ReadASN1Element(&inner, cbasn1.SEQUENCE))
	return inner
}

// TestOpenSSLCMSInterop checks that OpenSSL decrypts the EnvelopedData of the cms package and
// that the cms package decrypts what OpenSSL encrypts, for every supported recipient key type.
func TestOpenSSLCMSInterop(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	major := opensslMajorVersion(t)
	dir := t.TempDir()
	// The CA is created in Go because "openssl req" needs an openssl.cnf, which an
	// installation with make install_sw lacks.
	ca := &certyaml.Certificate{Subject: "cn=CMS Test CA"}
	require.NoError(t, ca.Generate())
	caKey, caCert := filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem")
	writeKeyPEM(t, ca, caKey)
	writeCertPEM(t, ca, caCert)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	kem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	kem1024, err := mlkem.GenerateKey1024()
	require.NoError(t, err)

	pkcs8 := func(key any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return der
	}
	cases := []struct {
		name string
		pub  crypto.PublicKey
		priv any
		der  []byte
		// keyopts are the "openssl cms -encrypt" options for the recipient.
		keyopts []string
		mlkem   bool
	}{
		{name: "RSA-OAEP", pub: &rsaKey.PublicKey, priv: rsaKey, der: pkcs8(rsaKey), keyopts: []string{"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256"}},
		{name: "ECDH P-256", pub: &p256.PublicKey, priv: p256, der: pkcs8(p256)},
		{name: "ECDH P-384 SHA-384 KDF", pub: &p384.PublicKey, priv: p384, der: pkcs8(p384), keyopts: []string{"-keyopt", "ecdh_kdf_md:sha384"}},
		{name: "ECDH P-521", pub: &p521.PublicKey, priv: p521, der: pkcs8(p521)},
		{name: "ML-KEM-768", pub: kem768.EncapsulationKey(), priv: kem768, der: mlkemPKCS8(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}, kem768.Bytes()), mlkem: true},
		{name: "ML-KEM-1024", pub: kem1024.EncapsulationKey(), priv: kem1024, der: mlkemPKCS8(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}, kem1024.Bytes()), mlkem: true},
	}
	content := bytes.Repeat([]byte("encrypted certificate "), 20)
	contentFile := filepath.Join(dir, "content.bin")
	require.NoError(t, os.WriteFile(contentFile, content, 0600))

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// OpenSSL 3.5 cannot use ML-KEM keys in CMS. OpenSSL 4.0 can.
			if tc.mlkem && major < 4 {
				t.Skip("ML-KEM in CMS needs OpenSSL 4.0 or newer")
			}
			base := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			keyFile, pubFile, certFile := base+".key", base+".pub", base+".pem"
			writePEM(t, keyFile, "PRIVATE KEY", tc.der)
			runOpenSSL(t, "pkey", "-in", keyFile, "-pubout", "-out", pubFile)
			runOpenSSL(t, "x509", "-new", "-force_pubkey", pubFile, "-CA", caCert, "-CAkey", caKey, "-subj", "/CN=recipient "+tc.name, "-set_serial", strconv.Itoa(i+1), "-days", "1", "-out", certFile)
			certPEM, err := os.ReadFile(certFile)
			require.NoError(t, err)
			block, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)

			// cms package to OpenSSL.
			envelope, err := cms.Encrypt(content, tc.pub, cms.IssuerAndSerial(cert))
			require.NoError(t, err)
			toOpenSSL := base + ".go.der"
			require.NoError(t, os.WriteFile(toOpenSSL, wrapContentInfo(envelope), 0600))
			decrypted := filepath.Join(dir, "decrypted.bin")
			runOpenSSL(t, "cms", "-decrypt", "-binary", "-inform", "DER", "-in", toOpenSSL, "-recip", certFile, "-inkey", keyFile, "-out", decrypted)
			got, err := os.ReadFile(decrypted)
			require.NoError(t, err)
			assert.Equal(t, content, got, "OpenSSL decrypts the cms package envelope")

			// OpenSSL to the cms package.
			fromOpenSSL := base + ".openssl.der"
			args := append([]string{"cms", "-encrypt", "-binary", "-aes-256-cbc", "-in", contentFile, "-outform", "DER", "-out", fromOpenSSL, "-recip", certFile}, tc.keyopts...)
			runOpenSSL(t, args...)
			der, err := os.ReadFile(fromOpenSSL)
			require.NoError(t, err)
			plain, err := cms.Decrypt(unwrapContentInfo(t, der), tc.priv)
			require.NoError(t, err)
			assert.Equal(t, content, plain, "the cms package decrypts the OpenSSL envelope")
		})
	}

	// OpenSSL defaults to RSA PKCS #1 v1.5 key transport, which the cms package refuses.
	t.Run("RSA PKCS1 v1.5 refused", func(t *testing.T) {
		keyFile, pubFile, certFile := filepath.Join(dir, "v15.key"), filepath.Join(dir, "v15.pub"), filepath.Join(dir, "v15.pem")
		writePEM(t, keyFile, "PRIVATE KEY", pkcs8(rsaKey))
		runOpenSSL(t, "pkey", "-in", keyFile, "-pubout", "-out", pubFile)
		runOpenSSL(t, "x509", "-new", "-force_pubkey", pubFile, "-CA", caCert, "-CAkey", caKey, "-subj", "/CN=recipient v15", "-days", "1", "-out", certFile)
		out := filepath.Join(dir, "v15.der")
		runOpenSSL(t, "cms", "-encrypt", "-binary", "-aes-256-cbc", "-in", contentFile, "-outform", "DER", "-out", out, "-recip", certFile)
		der, err := os.ReadFile(out)
		require.NoError(t, err)
		_, err = cms.Decrypt(unwrapContentInfo(t, der), rsaKey)
		assert.ErrorContains(t, err, "only RSAES-OAEP is accepted")
	})
}
