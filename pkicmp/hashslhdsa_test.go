package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/cloudflare/circl/xof"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
)

// hashSLHDSAAlgorithms maps each parameter set to its RFC 9909 §3 HashSLH-DSA
// identifier, id-hash-slh-dsa-<set>-with-<pre-hash>, under id-sigAlgs.
var hashSLHDSAAlgorithms = map[slhdsa.ID]asn1.ObjectIdentifier{
	slhdsa.SHA2_128s:  {2, 16, 840, 1, 101, 3, 4, 3, 35},
	slhdsa.SHA2_128f:  {2, 16, 840, 1, 101, 3, 4, 3, 36},
	slhdsa.SHA2_192s:  {2, 16, 840, 1, 101, 3, 4, 3, 37},
	slhdsa.SHA2_192f:  {2, 16, 840, 1, 101, 3, 4, 3, 38},
	slhdsa.SHA2_256s:  {2, 16, 840, 1, 101, 3, 4, 3, 39},
	slhdsa.SHA2_256f:  {2, 16, 840, 1, 101, 3, 4, 3, 40},
	slhdsa.SHAKE_128s: {2, 16, 840, 1, 101, 3, 4, 3, 41},
	slhdsa.SHAKE_128f: {2, 16, 840, 1, 101, 3, 4, 3, 42},
	slhdsa.SHAKE_192s: {2, 16, 840, 1, 101, 3, 4, 3, 43},
	slhdsa.SHAKE_192f: {2, 16, 840, 1, 101, 3, 4, 3, 44},
	slhdsa.SHAKE_256s: {2, 16, 840, 1, 101, 3, 4, 3, 45},
	slhdsa.SHAKE_256f: {2, 16, 840, 1, 101, 3, 4, 3, 46},
}

// hashSLHDSAPreHash returns the pre-hash that the HashSLH-DSA identifier of
// parameter set id names: SHA-256 for SHA2-128, SHA-512 for the larger SHA2
// sets, SHAKE128 for SHAKE-128 and SHAKE256 for the larger SHAKE sets.
func hashSLHDSAPreHash(id slhdsa.ID) (*slhdsa.PreHash, error) {
	switch id {
	case slhdsa.SHA2_128s, slhdsa.SHA2_128f:
		return slhdsa.NewPreHashWithHash(crypto.SHA256)
	case slhdsa.SHA2_192s, slhdsa.SHA2_192f, slhdsa.SHA2_256s, slhdsa.SHA2_256f:
		return slhdsa.NewPreHashWithHash(crypto.SHA512)
	case slhdsa.SHAKE_128s, slhdsa.SHAKE_128f:
		return slhdsa.NewPreHashWithXof(xof.SHAKE128)
	default:
		return slhdsa.NewPreHashWithXof(xof.SHAKE256)
	}
}

// hashSLHDSAMessage pre-hashes data into the message that HashSLH-DSA with parameter set id signs (FIPS 205 §10.2.2).
func hashSLHDSAMessage(t *testing.T, id slhdsa.ID, data []byte) *slhdsa.Message {
	t.Helper()
	ph, err := hashSLHDSAPreHash(id)
	require.NoError(t, err)
	_, err = ph.Write(data)
	require.NoError(t, err)
	msg, err := ph.BuildMessage()
	require.NoError(t, err)
	return msg
}

// hashSLHDSASigner signs with HashSLH-DSA, the pre-hash variant of SLH-DSA,
// using the pre-hash that RFC 9909 §3 pairs with the key's parameter set.
type hashSLHDSASigner struct {
	t   *testing.T
	key slhdsa.PrivateKey
}

// Public returns the SLH-DSA public key, which HashSLH-DSA shares with pure SLH-DSA.
func (s hashSLHDSASigner) Public() crypto.PublicKey { return s.key.Public() }

// Sign returns a HashSLH-DSA signature of message with an empty context and ignores opts.
func (s hashSLHDSASigner) Sign(random io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return slhdsa.SignRandomized(&s.key, random, hashSLHDSAMessage(s.t, s.key.ID, message), nil)
}

// requireHashSLHDSASignature checks that signature is a valid HashSLH-DSA signature of data by pub,
// so that a refusal of it cannot come from a broken signature.
func requireHashSLHDSASignature(t *testing.T, pub crypto.PublicKey, data, signature []byte) {
	t.Helper()
	key, ok := slhdsaPublicKey(pub)
	require.True(t, ok)
	require.True(t, slhdsa.Verify(&key, hashSLHDSAMessage(t, key.ID, data), signature, nil), "valid HashSLH-DSA signature")
	require.False(t, slhdsa.Verify(&key, slhdsa.NewMessage(data), signature, nil), "not a pure signature")
}

// encodeSLHDSASPKI encodes raw SLH-DSA public key bytes under oid with absent parameters.
func encodeSLHDSASPKI(t *testing.T, oid asn1.ObjectIdentifier, raw []byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid) })
		b.AddASN1BitString(raw)
	})
	der, err := b.Bytes()
	require.NoError(t, err)
	return der
}

// protectWithAlgorithm protects a PKIConf message from cert with signer under
// the protection algorithm oid, which signer need not match, and parses it back.
func protectWithAlgorithm(t *testing.T, signer crypto.Signer, cert *x509.Certificate, oid asn1.ObjectIdentifier) *PKIMessage {
	t.Helper()
	msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryNameFromRawDER(cert.RawSubject)})
	msg.Header.ProtectionAlg = &AlgorithmIdentifier{Algorithm: oid}
	msg.Header.SenderKID = cert.SubjectKeyId
	msg.ExtraCerts = []CMPCertificate{{Raw: cert.Raw}}
	require.NoError(t, msg.marshalForProtection())
	data, err := msg.protectedPart()
	require.NoError(t, err)
	msg.Protection, err = signer.Sign(rand.Reader, data, crypto.Hash(0))
	require.NoError(t, err)
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	return parsed
}

// TestHashSLHDSARefused checks that keys, message protection, proofs of
// possession, PKCS #10 requests and certificates under the HashSLH-DSA
// identifiers of RFC 9909 §3 are refused. Each signature case carries a valid
// HashSLH-DSA signature, which an implementation of the pre-hash variant would
// accept, and a pure signature under the HashSLH-DSA identifier, which treating
// the identifiers as aliases of the pure ones would accept. RFC 9909 §8 forbids
// verifying a HashSLH-DSA signature with a key identified as pure SLH-DSA.
func TestHashSLHDSARefused(t *testing.T) {
	t.Run("identifiers", func(t *testing.T) {
		require.Len(t, hashSLHDSAAlgorithms, 12)
		for id, oid := range hashSLHDSAAlgorithms {
			_, ok := SLHDSAAlgorithmFromOID(oid)
			require.False(t, ok, "%s HashSLH-DSA identifier %v", id, oid)
		}
	})

	t.Run("public keys", func(t *testing.T) {
		for id, oid := range hashSLHDSAAlgorithms {
			raw := make([]byte, id.Scheme().PublicKeySize())
			_, err := rand.Read(raw)
			require.NoError(t, err)
			pure, _ := SLHDSAAlgorithmOID(id)
			_, err = ParsePublicKey(encodeSLHDSASPKI(t, pure, raw))
			require.NoError(t, err, "%s key under its pure identifier", id)
			_, err = ParsePublicKey(encodeSLHDSASPKI(t, oid, raw))
			require.Error(t, err, "%s key under its HashSLH-DSA identifier", id)
		}
	})

	t.Run("message protection", func(t *testing.T) {
		for _, id := range []slhdsa.ID{slhdsa.SHA2_128f, slhdsa.SHAKE_128f} {
			t.Run(id.String(), func(t *testing.T) {
				key := newSLHDSAKey(t, id)
				cert, _ := newSLHDSATestCert(t, "HashSLH-DSA signer", key)
				pure, _ := SLHDSAAlgorithmOID(id)
				_, err := protectWithAlgorithm(t, key, cert, pure).Verify(VerifyOptions{TrustedCert: cert})
				require.NoError(t, err, "pure signature under the pure identifier")

				prehashed := protectWithAlgorithm(t, hashSLHDSASigner{t, key}, cert, hashSLHDSAAlgorithms[id])
				data, err := prehashed.protectedPart()
				require.NoError(t, err)
				requireHashSLHDSASignature(t, key.Public(), data, prehashed.Protection)
				relabelled := protectWithAlgorithm(t, key, cert, hashSLHDSAAlgorithms[id])
				for name, msg := range map[string]*PKIMessage{"HashSLH-DSA signature": prehashed, "pure signature": relabelled} {
					_, err := msg.Verify(VerifyOptions{TrustedCert: cert})
					var verErr *VerificationError
					require.ErrorAs(t, err, &verErr, name)
					require.Equal(t, ReasonUnsupportedAlgorithm, verErr.Reason, name)
				}
			})
		}
	})

	t.Run("proof of possession", func(t *testing.T) {
		key := newSLHDSAKey(t, slhdsa.SHA2_128f)
		pub, err := MarshalPublicKey(key.Public())
		require.NoError(t, err)
		// proof returns a parsed request for key with a proof that signer made under the HashSLH-DSA identifier.
		proof := func(signer crypto.Signer) *CertReqMsg {
			req := CertReqMsg{CertReq: CertRequest{CertTemplate: CertTemplate{PublicKey: pub, Subject: NewDirectoryName(pkix.Name{CommonName: "device"})}}}
			require.NoError(t, req.GeneratePOP(signer))
			req.Popo.Signature.Algorithm.Algorithm = hashSLHDSAAlgorithms[key.ID]
			der, err := NewPKIMessage(NewIRBody(&CertReqMessages{req}), MessageOptions{}).MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			requests, err := parsed.Body.IR()
			require.NoError(t, err)
			return &(*requests)[0]
		}

		prehashed := proof(hashSLHDSASigner{t, key})
		requireHashSLHDSASignature(t, key.Public(), prehashed.CertReq.Raw, prehashed.Popo.Signature.Signature)
		require.Error(t, VerifyPOP(prehashed), "HashSLH-DSA signature")

		relabelled := proof(key)
		require.Error(t, VerifyPOP(relabelled), "pure signature")
		relabelled.Popo.Signature.Algorithm.Algorithm, _ = SLHDSAAlgorithmOID(key.ID)
		require.NoError(t, VerifyPOP(relabelled), "pure signature under the pure identifier")
	})

	t.Run("PKCS #10 request", func(t *testing.T) {
		key := newSLHDSAKey(t, slhdsa.SHA2_128f)
		spki, err := MarshalPublicKey(key.Public())
		require.NoError(t, err)
		// request returns a parsed request for key that signer signs under the HashSLH-DSA identifier.
		request := func(signer crypto.Signer) *x509.CertificateRequest {
			der, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, spki, hashSLHDSAAlgorithms[key.ID], signer)
			require.NoError(t, err)
			csr, err := x509.ParseCertificateRequest(der)
			require.NoError(t, err)
			return csr
		}

		prehashed := request(hashSLHDSASigner{t, key})
		requireHashSLHDSASignature(t, key.Public(), prehashed.RawTBSCertificateRequest, prehashed.Signature)
		// The server answers x509.ErrUnsupportedAlgorithm with badAlg.
		require.ErrorIs(t, CheckCertificateRequestSignature(prehashed), x509.ErrUnsupportedAlgorithm, "HashSLH-DSA signature")
		require.ErrorIs(t, CheckCertificateRequestSignature(request(key)), x509.ErrUnsupportedAlgorithm, "pure signature")
	})

	t.Run("certificate signatures", func(t *testing.T) {
		caKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
		caSPKI, err := MarshalPublicKey(caKey.Public())
		require.NoError(t, err)
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "SLH-DSA CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			SubjectKeyId:          []byte("SLH-DSA CA"),
		}
		pure, _ := SLHDSAAlgorithmOID(caKey.ID)
		der, err := kemcert.CreateSLHDSACertificate(caTmpl, caTmpl, caSPKI, pure, caKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		signerSPKI, err := MarshalPublicKey(signerKey.Public())
		require.NoError(t, err)
		// issue certifies the signer key with a certificate the CA signs with signer under oid.
		issue := func(signer crypto.Signer, oid asn1.ObjectIdentifier) *x509.Certificate {
			der, err := kemcert.CreateSLHDSACertificate(&x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "CMP signer"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				SubjectKeyId: []byte("CMP signer"),
			}, caCert, signerSPKI, oid, signer)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			return cert
		}
		// verify checks a message signed with the signer key against the CA through the certificate cert.
		verify := func(cert *x509.Certificate) error {
			creds, err := NewSignatureCredentials(signerKey, cert, caCert)
			require.NoError(t, err)
			msg := roundTrip(t, creds, cert.Subject)
			_, err = msg.Verify(VerifyOptions{TrustPool: x509pool(caCert), ExtraCerts: msg.ExtraCerts, SenderKID: msg.Header.SenderKID})
			return err
		}
		require.NoError(t, verify(issue(caKey, pure)), "pure signature under the pure identifier")

		prehashed := issue(hashSLHDSASigner{t, caKey}, hashSLHDSAAlgorithms[caKey.ID])
		requireHashSLHDSASignature(t, caKey.Public(), prehashed.RawTBSCertificate, prehashed.Signature)
		relabelled := issue(caKey, hashSLHDSAAlgorithms[caKey.ID])
		for name, cert := range map[string]*x509.Certificate{"HashSLH-DSA signature": prehashed, "pure signature": relabelled} {
			var verErr *VerificationError
			require.ErrorAs(t, verify(cert), &verErr, name)
			require.Equal(t, ReasonUntrustedSigner, verErr.Reason, name)
			// No confirmation hash is defined for a signature algorithm the library refuses.
			_, err := NewCertStatus(cert, 0)
			require.Error(t, err, name)
		}
	})
}
