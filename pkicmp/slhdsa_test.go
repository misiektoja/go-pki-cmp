package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
)

// slhdsaFastSets are the parameter sets used where a test signs, because the
// small sets take up to seconds per signature.
var slhdsaFastSets = []slhdsa.ID{slhdsa.SHA2_128f, slhdsa.SHAKE_128f, slhdsa.SHA2_192f, slhdsa.SHAKE_256f}

// newSLHDSAKey generates an SLH-DSA key of parameter set id.
func newSLHDSAKey(t *testing.T, id slhdsa.ID) slhdsa.PrivateKey {
	t.Helper()
	_, key, err := slhdsa.GenerateKey(rand.Reader, id)
	require.NoError(t, err)
	return key
}

// newSLHDSATestCert certifies key under a self-signed ECDSA CA and returns both certificates.
func newSLHDSATestCert(t *testing.T, name string, key crypto.Signer) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caCert := newCompositeTestCert(t, "SLH-DSA test CA", true, caKey, nil, nil)
	spki, err := MarshalPublicKey(key.Public())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte(name),
	}
	der, err := kemcert.CreateCertificate(tmpl, caCert, spki, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, caCert
}

// newSLHDSACSR returns a PKCS #10 request for subject that key signs.
func newSLHDSACSR(t *testing.T, key slhdsa.PrivateKey, subject string) *x509.CertificateRequest {
	t.Helper()
	spki, err := MarshalPublicKey(key.Public())
	require.NoError(t, err)
	oid, ok := SLHDSAAlgorithmOID(key.ID)
	require.True(t, ok)
	der, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, spki, oid, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestSLHDSAAlgorithmIdentifiers checks the identifier table against the RFC 9909 §3 assignments.
func TestSLHDSAAlgorithmIdentifiers(t *testing.T) {
	// RFC 9909 §3 lists the sets in this order under id-sigAlgs (2.16.840.1.101.3.4.3).
	names := []string{
		"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
		"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
		"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
	}
	for i, name := range names {
		id, err := slhdsa.IDByName(name)
		require.NoError(t, err)
		oid, ok := SLHDSAAlgorithmOID(id)
		require.True(t, ok, name)
		require.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20 + i}, oid, name)
		back, ok := SLHDSAAlgorithmFromOID(oid)
		require.True(t, ok)
		require.Equal(t, id, back)
	}
	_, ok := SLHDSAAlgorithmFromOID(oidMLDSA44)
	require.False(t, ok)
	_, ok = SLHDSAAlgorithmOID(0)
	require.False(t, ok)
}

// TestSLHDSAPublicKeyEncoding round-trips every parameter set through a SubjectPublicKeyInfo.
func TestSLHDSAPublicKeyEncoding(t *testing.T) {
	for i := range 12 {
		oid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20 + i}
		id, ok := SLHDSAAlgorithmFromOID(oid)
		require.True(t, ok)
		alg := struct {
			id  slhdsa.ID
			oid asn1.ObjectIdentifier
		}{id, oid}
		t.Run(alg.id.String(), func(t *testing.T) {
			key := newSLHDSAKey(t, alg.id)
			pub := key.PublicKey()
			der, err := MarshalPublicKey(pub)
			require.NoError(t, err)
			fromPointer, err := MarshalPublicKey(&pub)
			require.NoError(t, err)
			require.Equal(t, der, fromPointer)

			oid, bits, ok := parseSPKI(der)
			require.True(t, ok, "parameters are absent")
			require.Equal(t, alg.oid, oid)
			raw, err := pub.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, raw, bits)

			parsed, err := ParsePublicKey(der)
			require.NoError(t, err)
			require.IsType(t, slhdsa.PublicKey{}, parsed)
			require.True(t, PublicKeysEqual(parsed, key.Public()))
			require.True(t, PublicKeysEqual(&pub, parsed))
			require.False(t, PublicKeysEqual(parsed, newSLHDSAKey(t, alg.id).Public()))
		})
	}
}

// TestSLHDSAPublicKeyRejections refuses keys of the wrong length and keys with algorithm parameters.
func TestSLHDSAPublicKeyRejections(t *testing.T) {
	oid, _ := SLHDSAAlgorithmOID(slhdsa.SHA2_192f)
	encode := func(params []byte, key slhdsa.PublicKey) []byte {
		raw, err := key.MarshalBinary()
		require.NoError(t, err)
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oid)
				b.AddBytes(params)
			})
			b.AddASN1BitString(raw)
		})
		return b.BytesOrPanic()
	}
	_, err := ParsePublicKey(encode(nil, newSLHDSAKey(t, slhdsa.SHA2_192f).PublicKey()))
	require.NoError(t, err)
	_, err = ParsePublicKey(encode(nil, newSLHDSAKey(t, slhdsa.SHA2_128f).PublicKey()))
	require.Error(t, err, "a 128-bit key under a 192-bit identifier")
	_, err = ParsePublicKey(encode(asn1.NullBytes, newSLHDSAKey(t, slhdsa.SHA2_192f).PublicKey()))
	require.Error(t, err, "NULL parameters")
}

// TestSLHDSAMessageSignatures protects and verifies messages with SLH-DSA keys.
func TestSLHDSAMessageSignatures(t *testing.T) {
	for _, id := range slhdsaFastSets {
		t.Run(id.String(), func(t *testing.T) {
			key := newSLHDSAKey(t, id)
			cert, caCert := newSLHDSATestCert(t, "SLH-DSA signer", key)
			require.Nil(t, cert.PublicKey)

			creds, err := NewSignatureCredentials(key, cert, caCert)
			require.NoError(t, err)
			parsed := roundTrip(t, creds, cert.Subject)
			oid, _ := SLHDSAAlgorithmOID(id)
			require.Equal(t, oid, parsed.Header.ProtectionAlg.Algorithm)
			require.Empty(t, parsed.Header.ProtectionAlg.Parameters)

			result, err := parsed.Verify(VerifyOptions{TrustedCert: cert})
			require.NoError(t, err)
			require.Equal(t, cert, result.ProtectionCertificate)
			_, err = parsed.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: parsed.ExtraCerts, RequiredProtection: ProtectionSignature})
			require.NoError(t, err)

			parsed.Protection[len(parsed.Protection)-1] ^= 1
			_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
			var verErr *VerificationError
			require.ErrorAs(t, err, &verErr)
			require.Equal(t, ReasonSignatureFailed, verErr.Reason)
		})
	}
}

// TestSLHDSAProtectionRejections refuses mismatched keys, parameter sets and parameters.
func TestSLHDSAProtectionRejections(t *testing.T) {
	key := newSLHDSAKey(t, slhdsa.SHA2_128f)
	cert, _ := newSLHDSATestCert(t, "SLH-DSA signer", key)
	creds, err := NewSignatureCredentials(key, cert)
	require.NoError(t, err)

	t.Run("credentials key mismatch", func(t *testing.T) {
		_, err := NewSignatureCredentials(newSLHDSAKey(t, slhdsa.SHA2_128f), cert)
		var protErr *ProtectionError
		require.ErrorAs(t, err, &protErr)
		require.Equal(t, ReasonMissingSigner, protErr.Reason)
	})
	t.Run("parameters present", func(t *testing.T) {
		parsed := roundTrip(t, creds, cert.Subject)
		parsed.Header.ProtectionAlg.Parameters = asn1.NullBytes
		_, err := parsed.Verify(VerifyOptions{TrustedCert: cert})
		var parseErr *ParseError
		require.ErrorAs(t, err, &parseErr)
	})
	t.Run("identifier of another parameter set", func(t *testing.T) {
		parsed := roundTrip(t, creds, cert.Subject)
		parsed.Header.ProtectionAlg.Algorithm, _ = SLHDSAAlgorithmOID(slhdsa.SHAKE_128f)
		_, err := parsed.Verify(VerifyOptions{TrustedCert: cert})
		require.Error(t, err)
	})
	t.Run("certificate of another key", func(t *testing.T) {
		otherCert, _ := newSLHDSATestCert(t, "SLH-DSA signer", newSLHDSAKey(t, slhdsa.SHA2_128f))
		parsed := roundTrip(t, creds, cert.Subject)
		_, err := parsed.Verify(VerifyOptions{TrustedCert: otherCert})
		require.Error(t, err)
	})
	t.Run("ML-DSA identifier with an SLH-DSA certificate", func(t *testing.T) {
		parsed := roundTrip(t, creds, cert.Subject)
		parsed.Header.ProtectionAlg.Algorithm = oidMLDSA44
		_, err := parsed.Verify(VerifyOptions{TrustedCert: cert})
		require.Error(t, err)
	})
	t.Run("MAC protection required", func(t *testing.T) {
		parsed := roundTrip(t, creds, cert.Subject)
		_, err := parsed.Verify(VerifyOptions{TrustedCert: cert, RequiredProtection: ProtectionMAC})
		var verErr *VerificationError
		require.ErrorAs(t, err, &verErr)
		require.Equal(t, ReasonUnexpectedProtection, verErr.Reason)
	})
}

// TestSLHDSAPOP proves possession of SLH-DSA keys and refuses forged or mismatched proofs.
func TestSLHDSAPOP(t *testing.T) {
	ids := append([]slhdsa.ID{slhdsa.SHA2_128s}, slhdsaFastSets...)
	for _, id := range ids {
		t.Run(id.String(), func(t *testing.T) {
			key := newSLHDSAKey(t, id)
			pub, err := MarshalPublicKey(key.Public())
			require.NoError(t, err)
			req := CertReqMsg{CertReq: CertRequest{CertReqID: 3, CertTemplate: CertTemplate{PublicKey: pub, Subject: NewDirectoryName(pkix.Name{CommonName: "device"})}}}
			require.NoError(t, req.GeneratePOP(key))
			oid, _ := SLHDSAAlgorithmOID(id)
			require.Equal(t, oid, req.Popo.Signature.Algorithm.Algorithm)

			msg := NewPKIMessage(NewIRBody(&CertReqMessages{req}), MessageOptions{})
			der, err := msg.MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			requests, err := parsed.Body.IR()
			require.NoError(t, err)
			proof := &(*requests)[0]
			require.NoError(t, VerifyPOP(proof))
			got, err := proof.PublicKey()
			require.NoError(t, err)
			require.True(t, PublicKeysEqual(got, key.Public()))

			proof.Popo.Signature.Algorithm.Parameters = asn1.NullBytes
			require.Error(t, VerifyPOP(proof))
			proof.Popo.Signature.Algorithm.Parameters = nil
			proof.Popo.Signature.Signature[0] ^= 1
			require.Error(t, VerifyPOP(proof))
		})
	}
}

// TestSLHDSAPOPRejections refuses proofs whose algorithm does not match the requested key.
func TestSLHDSAPOPRejections(t *testing.T) {
	key := newSLHDSAKey(t, slhdsa.SHA2_128f)
	pub, err := MarshalPublicKey(key.Public())
	require.NoError(t, err)
	request := func(signer crypto.Signer) *CertReqMsg {
		req := &CertReqMsg{CertReq: CertRequest{CertTemplate: CertTemplate{PublicKey: pub, Subject: NewDirectoryName(pkix.Name{CommonName: "device"})}}}
		require.NoError(t, req.GeneratePOP(signer))
		der, err := NewPKIMessage(NewIRBody(&CertReqMessages{*req}), MessageOptions{}).MarshalBinary()
		require.NoError(t, err)
		parsed, err := ParsePKIMessage(der)
		require.NoError(t, err)
		requests, err := parsed.Body.IR()
		require.NoError(t, err)
		return &(*requests)[0]
	}

	t.Run("proof by another SLH-DSA key", func(t *testing.T) {
		require.Error(t, VerifyPOP(request(newSLHDSAKey(t, slhdsa.SHA2_128f))))
	})
	t.Run("proof under another parameter set", func(t *testing.T) {
		require.Error(t, VerifyPOP(request(newSLHDSAKey(t, slhdsa.SHAKE_128f))))
	})
	t.Run("ML-DSA proof for an SLH-DSA key", func(t *testing.T) {
		other, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)
		require.Error(t, VerifyPOP(request(other)))
	})
	t.Run("SLH-DSA proof for an ECDSA key", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecPub, err := MarshalPublicKey(ecKey.Public())
		require.NoError(t, err)
		req := &CertReqMsg{CertReq: CertRequest{CertTemplate: CertTemplate{PublicKey: ecPub, Subject: NewDirectoryName(pkix.Name{CommonName: "device"})}}}
		require.NoError(t, req.GeneratePOP(key))
		der, err := NewPKIMessage(NewIRBody(&CertReqMessages{*req}), MessageOptions{}).MarshalBinary()
		require.NoError(t, err)
		parsed, err := ParsePKIMessage(der)
		require.NoError(t, err)
		requests, err := parsed.Body.IR()
		require.NoError(t, err)
		require.Error(t, VerifyPOP(&(*requests)[0]))
	})
}

// TestSLHDSACertificateRequestSignature checks SLH-DSA PKCS #10 self-signatures and leaves other requests to compositex509.
func TestSLHDSACertificateRequestSignature(t *testing.T) {
	for _, id := range slhdsaFastSets {
		t.Run(id.String(), func(t *testing.T) {
			key := newSLHDSAKey(t, id)
			csr := newSLHDSACSR(t, key, "slh-dsa-device")
			require.NoError(t, CheckCertificateRequestSignature(csr))

			tampered := *csr
			tampered.Signature = append([]byte(nil), csr.Signature...)
			tampered.Signature[0] ^= 1
			require.Error(t, CheckCertificateRequestSignature(&tampered))
		})
	}

	t.Run("parameters present", func(t *testing.T) {
		csr := newSLHDSACSR(t, newSLHDSAKey(t, slhdsa.SHA2_128f), "slh-dsa-device")
		oid, _ := SLHDSAAlgorithmOID(slhdsa.SHA2_128f)
		withNull := replaceOuterSignatureAlgorithm(t, csr.Raw, oid, asn1.NullBytes)
		parsed, err := x509.ParseCertificateRequest(withNull)
		require.NoError(t, err)
		var parseErr *ParseError
		require.ErrorAs(t, CheckCertificateRequestSignature(parsed), &parseErr)
	})
	t.Run("ECDSA request", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ec-device"}}, ecKey)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		require.NoError(t, CheckCertificateRequestSignature(csr))
	})
}

// replaceOuterSignatureAlgorithm re-encodes a signed structure with its signature algorithm set to oid and params.
func replaceOuterSignatureAlgorithm(t *testing.T, der []byte, oid asn1.ObjectIdentifier, params []byte) []byte {
	t.Helper()
	var signed struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	_, err := asn1.Unmarshal(der, &signed)
	require.NoError(t, err)
	alg, err := asn1.Marshal(struct {
		OID    asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: params}})
	require.NoError(t, err)
	signed.Algorithm = asn1.RawValue{FullBytes: alg}
	out, err := asn1.Marshal(signed)
	require.NoError(t, err)
	return out
}

// TestSLHDSAOpenSSLMessages verifies an ir proof and a p10cr request that OpenSSL 4.0.3 produced with SLH-DSA keys.
func TestSLHDSAOpenSSLMessages(t *testing.T) {
	t.Run("ir with SLH-DSA-SHA2-128s proof", func(t *testing.T) {
		der, err := os.ReadFile("testdata/ir_slhdsa_golden.der")
		require.NoError(t, err)
		msg, err := ParsePKIMessage(der)
		require.NoError(t, err)
		requests, err := msg.Body.IR()
		require.NoError(t, err)
		proof := &(*requests)[0]
		pub, err := proof.PublicKey()
		require.NoError(t, err)
		key, ok := pub.(slhdsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, slhdsa.SHA2_128s, key.ID)
		require.NoError(t, VerifyPOP(proof))
		proof.Popo.Signature.Signature[100] ^= 1
		require.Error(t, VerifyPOP(proof))
	})
	t.Run("p10cr with SLH-DSA-SHAKE-128s request", func(t *testing.T) {
		der, err := os.ReadFile("testdata/p10cr_slhdsa_golden.der")
		require.NoError(t, err)
		msg, err := ParsePKIMessage(der)
		require.NoError(t, err)
		csr, err := msg.Body.P10CR()
		require.NoError(t, err)
		pub, err := ParsePublicKey(csr.RawSubjectPublicKeyInfo)
		require.NoError(t, err)
		require.Equal(t, slhdsa.SHAKE_128s, pub.(slhdsa.PublicKey).ID)
		require.NoError(t, CheckCertificateRequestSignature(csr))
	})
}

// TestSLHDSACertStatus checks that the confirmation of a certificate signed by
// an SLH-DSA CA names SHA-512, because the signature algorithm names no hash.
func TestSLHDSACertStatus(t *testing.T) {
	key := newSLHDSAKey(t, slhdsa.SHA2_128f)
	spki, err := MarshalPublicKey(key.Public())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SLH-DSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte("SLH-DSA CA"),
	}
	oid, _ := SLHDSAAlgorithmOID(key.ID)
	der, err := kemcert.CreateSLHDSACertificate(tmpl, tmpl, spki, oid, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	status, err := NewCertStatus(cert, 7)
	require.NoError(t, err)
	expected := sha512.Sum512(cert.Raw)
	require.Equal(t, expected[:], status.CertHash)
	require.Equal(t, oidSHA512, status.HashAlg.Algorithm)
	actual, err := status.CertificateHash(cert)
	require.NoError(t, err)
	require.Equal(t, status.CertHash, actual)
	status.HashAlg = nil
	_, err = status.CertificateHash(cert)
	require.Error(t, err, "without hashAlg the receiver cannot choose a hash")
}
