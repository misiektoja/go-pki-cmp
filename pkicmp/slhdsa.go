package pkicmp

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// slhdsaAlgorithms lists the SLH-DSA parameter sets with their identifiers (RFC 9909 §3).
// One identifier names both the key and its pure signature with an empty context.
// circl numbers the sets in a different order, so the mapping is spelled out.
var slhdsaAlgorithms = [...]struct {
	id  slhdsa.ID
	oid asn1.ObjectIdentifier
}{
	{slhdsa.SHA2_128s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}},
	{slhdsa.SHA2_128f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}},
	{slhdsa.SHA2_192s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}},
	{slhdsa.SHA2_192f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}},
	{slhdsa.SHA2_256s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}},
	{slhdsa.SHA2_256f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}},
	{slhdsa.SHAKE_128s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}},
	{slhdsa.SHAKE_128f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}},
	{slhdsa.SHAKE_192s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}},
	{slhdsa.SHAKE_192f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}},
	{slhdsa.SHAKE_256s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}},
	{slhdsa.SHAKE_256f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}},
}

// SLHDSAAlgorithmOID returns the RFC 9909 identifier of an SLH-DSA parameter set.
func SLHDSAAlgorithmOID(id slhdsa.ID) (asn1.ObjectIdentifier, bool) {
	for _, alg := range slhdsaAlgorithms {
		if alg.id == id {
			return alg.oid, true
		}
	}
	return nil, false
}

// SLHDSAAlgorithmFromOID returns the SLH-DSA parameter set that an RFC 9909 identifier names.
func SLHDSAAlgorithmFromOID(oid asn1.ObjectIdentifier) (slhdsa.ID, bool) {
	for _, alg := range slhdsaAlgorithms {
		if alg.oid.Equal(oid) {
			return alg.id, true
		}
	}
	return 0, false
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
func slhdsaPublicKey(pub crypto.PublicKey) (slhdsa.PublicKey, bool) {
	switch k := pub.(type) {
	case slhdsa.PublicKey:
		return k, true
	case *slhdsa.PublicKey:
		if k != nil {
			return *k, true
		}
	}
	return slhdsa.PublicKey{}, false
}

// verifySLHDSA checks a pure SLH-DSA signature with an empty context, made with
// pub under parameter set id, as RFC 9909 §3 specifies for X.509 and CMS.
func verifySLHDSA(id slhdsa.ID, pub crypto.PublicKey, data, signature []byte) error {
	key, ok := slhdsaPublicKey(pub)
	if !ok || key.ID != id {
		return errors.New("pkicmp: key does not match the SLH-DSA signature algorithm")
	}
	if !slhdsa.Verify(&key, slhdsa.NewMessage(data), signature, nil) {
		return errors.New("pkicmp: SLH-DSA signature verification failed")
	}
	return nil
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
