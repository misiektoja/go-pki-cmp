package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/stretchr/testify/require"
)

// compositeTestAlgorithms covers both pre-hashes and every traditional component family.
var compositeTestAlgorithms = []compositemldsa.Algorithm{
	compositemldsa.MLDSA44RSA2048PSSSHA256,
	compositemldsa.MLDSA44ECDSAP256SHA256,
	compositemldsa.MLDSA65Ed25519SHA512,
	compositemldsa.MLDSA87ECDSAP384SHA512,
}

// newCompositeTestCert certifies key with a certificate that issuerKey signs under issuer or that key self-signs when issuer is nil.
func newCompositeTestCert(t *testing.T, name string, isCA bool, key crypto.Signer, issuer *x509.Certificate, issuerKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte(name),
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
	}
	if issuer == nil {
		issuer, issuerKey = tmpl, key
	}
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// roundTrip protects a PKIConf message with creds and parses it back.
func roundTrip(t *testing.T, creds Credentials, subject pkix.Name) *PKIMessage {
	t.Helper()
	msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryName(subject), Recipient: NewDirectoryName(subject)})
	require.NoError(t, creds.Protect(msg))
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	return parsed
}

// TestCompositeMessageSignatures protects and verifies messages with composite ML-DSA keys.
func TestCompositeMessageSignatures(t *testing.T) {
	for _, alg := range compositeTestAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			key, err := compositemldsa.GenerateKey(alg)
			require.NoError(t, err)
			cert := newCompositeTestCert(t, "Composite signer", true, key, nil, nil)
			require.Nil(t, cert.PublicKey)

			creds, err := NewSignatureCredentials(key, cert)
			require.NoError(t, err)
			parsed := roundTrip(t, creds, cert.Subject)
			require.Equal(t, alg.OID(), parsed.Header.ProtectionAlg.Algorithm)
			require.Empty(t, parsed.Header.ProtectionAlg.Parameters)

			result, err := parsed.Verify(VerifyOptions{TrustedCert: cert})
			require.NoError(t, err)
			require.Equal(t, cert, result.ProtectionCertificate)
			_, err = parsed.Verify(VerifyOptions{TrustPool: x509pool(cert), ExtraCerts: parsed.ExtraCerts})
			require.NoError(t, err)

			parsed.Protection[len(parsed.Protection)-1] ^= 1
			_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
			require.Error(t, err)
		})
	}
}

// TestCompositeProtectionRejections refuses mismatched keys, algorithms and parameters.
func TestCompositeProtectionRejections(t *testing.T) {
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	cert := newCompositeTestCert(t, "Composite signer", true, key, nil, nil)
	other, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	require.NoError(t, err)
	otherCert := newCompositeTestCert(t, "Composite signer", true, other, nil, nil)

	t.Run("credentials key mismatch", func(t *testing.T) {
		_, err := NewSignatureCredentials(other, cert)
		var protErr *ProtectionError
		require.ErrorAs(t, err, &protErr)
		require.Equal(t, ReasonMissingSigner, protErr.Reason)
	})
	t.Run("parameters present", func(t *testing.T) {
		creds, err := NewSignatureCredentials(key, cert)
		require.NoError(t, err)
		parsed := roundTrip(t, creds, cert.Subject)
		parsed.Header.ProtectionAlg.Parameters = asn1.NullBytes
		_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
		var parseErr *ParseError
		require.ErrorAs(t, err, &parseErr)
	})
	t.Run("certificate of another composite algorithm", func(t *testing.T) {
		creds, err := NewSignatureCredentials(key, cert)
		require.NoError(t, err)
		parsed := roundTrip(t, creds, cert.Subject)
		_, err = parsed.Verify(VerifyOptions{TrustedCert: otherCert})
		var verErr *VerificationError
		require.ErrorAs(t, err, &verErr)
		require.Equal(t, ReasonSignatureFailed, verErr.Reason)
	})
	t.Run("classical certificate", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecCert := newCompositeTestCert(t, "Composite signer", true, ecKey, nil, nil)
		creds, err := NewSignatureCredentials(key, cert)
		require.NoError(t, err)
		parsed := roundTrip(t, creds, cert.Subject)
		_, err = parsed.Verify(VerifyOptions{TrustedCert: ecCert})
		require.Error(t, err)
	})
	t.Run("classical algorithm with composite certificate", func(t *testing.T) {
		creds, err := NewSignatureCredentials(key, cert)
		require.NoError(t, err)
		parsed := roundTrip(t, creds, cert.Subject)
		parsed.Header.ProtectionAlg = &AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
		_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
		require.Error(t, err)
	})
}

// TestCompositeSignerChain verifies a classical CMP signer certified by a composite CA.
func TestCompositeSignerChain(t *testing.T) {
	caKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	require.NoError(t, err)
	caCert := newCompositeTestCert(t, "Composite CA", true, caKey, nil, nil)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerCert := newCompositeTestCert(t, "CMP signer", false, signerKey, caCert, caKey)

	withChain, err := NewSignatureCredentials(signerKey, signerCert, caCert)
	require.NoError(t, err)
	parsed := roundTrip(t, withChain, signerCert.Subject)
	result, err := parsed.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: parsed.ExtraCerts})
	require.NoError(t, err)
	require.True(t, result.ProtectionCertificate.Equal(signerCert))

	// A composite issuer is found only among the candidates, so a chain
	// without the CA certificate cannot be verified.
	withoutChain, err := NewSignatureCredentials(signerKey, signerCert)
	require.NoError(t, err)
	parsed = roundTrip(t, withoutChain, signerCert.Subject)
	_, err = parsed.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: parsed.ExtraCerts})
	require.Error(t, err)
}

// TestCompositeSignerChainCurrentTime checks the certificates of a path through a composite CA at VerifyOptions.CurrentTime.
func TestCompositeSignerChainCurrentTime(t *testing.T) {
	caKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	require.NoError(t, err)
	caCert := newCompositeTestCert(t, "Composite CA", true, caKey, nil, nil)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerCert := newCompositeTestCert(t, "CMP signer", false, signerKey, caCert, caKey)
	creds, err := NewSignatureCredentials(signerKey, signerCert, caCert)
	require.NoError(t, err)
	parsed := roundTrip(t, creds, signerCert.Subject)

	// The CA was certified first, so it is valid from the signer's first second.
	result, err := parsed.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: parsed.ExtraCerts, CurrentTime: signerCert.NotBefore})
	require.NoError(t, err)
	require.True(t, result.ProtectionCertificate.Equal(signerCert))

	// Both times lie outside the signer's validity, the first one also while it is valid at the time of the call.
	for _, at := range []time.Time{signerCert.NotBefore.Add(-time.Second), signerCert.NotAfter.Add(time.Second)} {
		_, err = parsed.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: parsed.ExtraCerts, CurrentTime: at})
		var ve *VerificationError
		require.ErrorAs(t, err, &ve)
		require.Equal(t, ReasonUntrustedSigner, ve.Reason)
	}
}

// TestCompositeCertHash hashes certificates signed by a composite CA with the pre-hash of its algorithm.
func TestCompositeCertHash(t *testing.T) {
	cases := []struct {
		alg  compositemldsa.Algorithm
		oid  asn1.ObjectIdentifier
		hash func([]byte) []byte
	}{
		{compositemldsa.MLDSA44ECDSAP256SHA256, oidSHA256, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
		{compositemldsa.MLDSA65Ed25519SHA512, oidSHA512, func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }},
	}
	for _, tc := range cases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			caKey, err := compositemldsa.GenerateKey(tc.alg)
			require.NoError(t, err)
			caCert := newCompositeTestCert(t, "Composite CA", true, caKey, nil, nil)
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			leaf := newCompositeTestCert(t, "Device", false, leafKey, caCert, caKey)
			require.Equal(t, x509.UnknownSignatureAlgorithm, leaf.SignatureAlgorithm)

			status, err := NewCertStatus(leaf, 3)
			require.NoError(t, err)
			require.Equal(t, tc.hash(leaf.Raw), status.CertHash)
			require.Equal(t, tc.oid, status.HashAlg.Algorithm)
			require.Equal(t, int64(3), status.CertReqID)

			hash, err := CertHash(leaf)
			require.NoError(t, err)
			require.Equal(t, status.CertHash, hash)
			expected, err := status.CertificateHash(leaf)
			require.NoError(t, err)
			require.Equal(t, status.CertHash, expected)

			// A peer that omits hashAlg is checked with the pre-hash too.
			status.HashAlg = nil
			expected, err = status.CertificateHash(leaf)
			require.NoError(t, err)
			require.Equal(t, status.CertHash, expected)
		})
	}
}

// x509pool returns a certificate pool holding certs.
func x509pool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// compositeCertReqMsg builds a CertReqMsg requesting a certificate for pub.
func compositeCertReqMsg(t *testing.T, pub crypto.PublicKey) *CertReqMsg {
	t.Helper()
	pubDER, err := compositex509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return &CertReqMsg{CertReq: CertRequest{CertTemplate: CertTemplate{
		Subject:   NewDirectoryName(pkix.Name{CommonName: "composite-device"}),
		PublicKey: pubDER,
	}}}
}

// signedCompositePOP returns a parsed CertReqMsg for pub whose POP signer made.
func signedCompositePOP(t *testing.T, pub crypto.PublicKey, signer crypto.Signer) *CertReqMsg {
	t.Helper()
	reqMsg := compositeCertReqMsg(t, pub)
	require.NoError(t, reqMsg.GeneratePOP(signer))
	return roundTripCertReqMsg(t, reqMsg)
}

// TestCompositePOP verifies signature proof of possession for composite
// ML-DSA request keys, which sign the DER CertRequest with an empty context.
func TestCompositePOP(t *testing.T) {
	for _, alg := range compositeTestAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			key, err := compositemldsa.GenerateKey(alg)
			require.NoError(t, err)
			reqMsg := signedCompositePOP(t, key.Public(), key)
			require.True(t, reqMsg.Popo.Signature.Algorithm.Algorithm.Equal(alg.OID()))
			require.Empty(t, reqMsg.Popo.Signature.Algorithm.Parameters)
			require.NoError(t, VerifyPOP(reqMsg))
			require.NoError(t, compositemldsa.Verify(key.PublicKey(), reqMsg.CertReq.Raw, reqMsg.Popo.Signature.Signature, nil))

			pub, err := reqMsg.PublicKey()
			require.NoError(t, err)
			require.True(t, key.PublicKey().Equal(pub))
		})
	}
}

// TestCompositePOPRejections refuses composite POPs that do not prove the requested key.
func TestCompositePOPRejections(t *testing.T) {
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	sameAlgorithm, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	otherAlgorithm, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	require.NoError(t, err)
	classical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("tampered signature", func(t *testing.T) {
		reqMsg := signedCompositePOP(t, key.Public(), key)
		reqMsg.Popo.Signature.Signature[len(reqMsg.Popo.Signature.Signature)-1] ^= 1
		require.Error(t, VerifyPOP(reqMsg))
	})
	t.Run("ML-DSA component alone", func(t *testing.T) {
		reqMsg := signedCompositePOP(t, key.Public(), key)
		n := key.Algorithm().MLDSAParameters().SignatureSize()
		reqMsg.Popo.Signature.Signature = reqMsg.Popo.Signature.Signature[:n]
		require.Error(t, VerifyPOP(reqMsg))
	})
	t.Run("signed by another key of the same algorithm", func(t *testing.T) {
		require.Error(t, VerifyPOP(signedCompositePOP(t, key.Public(), sameAlgorithm)))
	})
	t.Run("signed with another composite algorithm", func(t *testing.T) {
		err := VerifyPOP(signedCompositePOP(t, key.Public(), otherAlgorithm))
		require.ErrorContains(t, err, "does not match the requested public key")
	})
	t.Run("classical signature for a composite key", func(t *testing.T) {
		err := VerifyPOP(signedCompositePOP(t, key.Public(), classical))
		require.ErrorContains(t, err, "does not match the requested public key")
	})
	t.Run("composite signature for a classical key", func(t *testing.T) {
		err := VerifyPOP(signedCompositePOP(t, classical.Public(), key))
		require.ErrorContains(t, err, "does not match the requested public key")
	})
	t.Run("parameters present", func(t *testing.T) {
		reqMsg := signedCompositePOP(t, key.Public(), key)
		reqMsg.Popo.Signature.Algorithm.Parameters = []byte{5, 0}
		var perr *ParseError
		require.ErrorAs(t, VerifyPOP(reqMsg), &perr)
	})
}
