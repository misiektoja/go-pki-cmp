package pkicmp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMessageSignatures verifies pure-message signatures independently of confirmation hashes.
func TestMessageSignatures(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsaParams := []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}
	keys := make([]crypto.Signer, 0, 1+len(mldsaParams))
	keys = append(keys, ed)
	for _, params := range mldsaParams {
		key, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		keys = append(keys, key)
	}
	for _, key := range keys {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Signature test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		t.Run(cert.SignatureAlgorithm.String(), func(t *testing.T) {
			msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryName(cert.Subject), Recipient: NewDirectoryName(cert.Subject)})
			require.NoError(t, msg.protectWithSignature(key, 0, cert))
			der, err := msg.MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			data, err := parsed.ProtectedData()
			require.NoError(t, err)
			require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, data, parsed.Protection))
			_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
			require.NoError(t, err)
			parsed.Protection[0] ^= 1
			_, err = parsed.Verify(VerifyOptions{TrustedCert: cert})
			require.Error(t, err)
		})
	}
}

// TestMLDSAProofAndConfirmation rejects forged proofs and ambiguous algorithm parameters.
func TestMLDSAProofAndConfirmation(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			pub, err := x509.MarshalPKIXPublicKey(key.Public())
			require.NoError(t, err)
			req := CertReqMsg{CertReq: CertRequest{CertReqID: 7, CertTemplate: CertTemplate{PublicKey: pub, Subject: NewDirectoryName(pkix.Name{CommonName: "device"})}}}
			require.NoError(t, req.GeneratePOP(key))
			msg := NewPKIMessage(NewIRBody(&CertReqMessages{req}), MessageOptions{})
			der, err := msg.MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			requests, err := parsed.Body.IR()
			require.NoError(t, err)
			proof := &(*requests)[0]
			require.NoError(t, VerifyPOP(proof))
			proof.Popo.Signature.Algorithm.Parameters = asn1.NullBytes
			require.Error(t, VerifyPOP(proof))
			proof.Popo.Signature.Algorithm.Parameters = nil
			proof.Popo.Signature.Signature[0] ^= 1
			require.Error(t, VerifyPOP(proof))
			oid, _, err := signatureAlgorithmFromKey(key)
			require.NoError(t, err)
			algorithm, err := sigAlgFromOID(oid)
			require.NoError(t, err)
			_, err = signatureAlgorithm(AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullBytes}, false)
			require.Error(t, err)
			cert := &x509.Certificate{Raw: []byte("certificate bytes"), SignatureAlgorithm: algorithm}
			status, err := NewCertStatus(cert, 7)
			require.NoError(t, err)
			expected := sha512.Sum512(cert.Raw)
			require.Equal(t, expected[:], status.CertHash)
			require.Equal(t, int64(7), status.CertReqID)
			require.Equal(t, oidSHA512, status.HashAlg.Algorithm)
			actual, err := status.CertificateHash(cert)
			require.NoError(t, err)
			require.Equal(t, status.CertHash, actual)
			status.HashAlg = nil
			_, err = status.CertificateHash(cert)
			require.Error(t, err)
		})
	}
}
