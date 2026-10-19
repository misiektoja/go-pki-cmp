package pkicmp

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
)

// SLHDSAAlgorithmOID returns the RFC 9909 identifier of an SLH-DSA parameter set.
func SLHDSAAlgorithmOID(id slhdsa.ID) (asn1.ObjectIdentifier, bool) { return slhdsasig.OID(id) }

// SLHDSAAlgorithmFromOID returns the SLH-DSA parameter set that an RFC 9909 identifier names.
func SLHDSAAlgorithmFromOID(oid asn1.ObjectIdentifier) (slhdsa.ID, bool) {
	return slhdsasig.FromOID(oid)
}

// slhdsaSignatureAlgorithm resolves an SLH-DSA signature identifier, whose parameters must be absent (RFC 9909 §3).
func slhdsaSignatureAlgorithm(alg AlgorithmIdentifier) (slhdsa.ID, bool, error) {
	id, ok := SLHDSAAlgorithmFromOID(alg.Algorithm)
	if !ok {
		return 0, false, nil
	}
	if len(alg.Parameters) != 0 {
		return 0, false, &ParseError{Detail: "SLH-DSA parameters must be absent"}
	}
	return id, true, nil
}

// slhdsaPublicKey returns pub as an SLH-DSA public key. It accepts the value
// that circl's PrivateKey.Public returns and a pointer to it.
func slhdsaPublicKey(pub crypto.PublicKey) (slhdsa.PublicKey, bool) { return slhdsasig.Key(pub) }

// verifySLHDSA checks a pure SLH-DSA signature with an empty context, made with
// pub under parameter set id, as RFC 9909 §3 specifies for X.509 and CMS.
func verifySLHDSA(id slhdsa.ID, pub crypto.PublicKey, data, signature []byte) error {
	return slhdsasig.Verify(id, pub, data, signature)
}

// CheckCertificateRequestSignature verifies the self-signature of a PKCS #10
// request. It checks SLH-DSA signatures (RFC 9909) itself and passes every
// other request to compositex509.CheckCertificateRequestSignature, which covers
// classical, ML-DSA and composite ML-DSA keys. crypto/x509 parses an SLH-DSA
// request with a nil PublicKey, so its own check always fails for one.
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error {
	alg, err := outerSignatureAlgorithm(csr.Raw)
	if err != nil {
		return err
	}
	id, ok, err := slhdsaSignatureAlgorithm(alg)
	if err != nil {
		return err
	}
	if !ok {
		return compositex509.CheckCertificateRequestSignature(csr)
	}
	pub, err := ParsePublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	return verifySLHDSA(id, pub, csr.RawTBSCertificateRequest, csr.Signature)
}

// outerSignatureAlgorithm reads the signature AlgorithmIdentifier of a signed
// structure laid out as SEQUENCE { tbs, signatureAlgorithm, signature }, which
// covers certificates, CRLs and PKCS #10 requests.
func outerSignatureAlgorithm(der []byte) (AlgorithmIdentifier, error) {
	s := cryptobyte.String(der)
	var signed, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&signed, cbasn1.SEQUENCE) || !signed.SkipASN1(cbasn1.SEQUENCE) ||
		!signed.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return AlgorithmIdentifier{}, &ParseError{Detail: "malformed signature algorithm"}
	}
	return AlgorithmIdentifier{Algorithm: oid, Parameters: []byte(alg)}, nil
}
