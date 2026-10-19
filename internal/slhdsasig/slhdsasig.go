// Package slhdsasig holds the SLH-DSA identifiers of RFC 9909 and verifies SLH-DSA signatures on
// certificates, which crypto/x509 and compositex509 cannot check.
package slhdsasig

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

// algorithms lists the SLH-DSA parameter sets with their identifiers (RFC 9909 §3).
// One identifier names both the key and its pure signature with an empty context.
// circl numbers the sets in a different order, so the mapping is spelled out.
var algorithms = [...]struct {
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

// OID returns the RFC 9909 identifier of an SLH-DSA parameter set.
func OID(id slhdsa.ID) (asn1.ObjectIdentifier, bool) {
	for _, alg := range algorithms {
		if alg.id == id {
			return alg.oid, true
		}
	}
	return nil, false
}

// FromOID returns the SLH-DSA parameter set that an RFC 9909 identifier names.
func FromOID(oid asn1.ObjectIdentifier) (slhdsa.ID, bool) {
	for _, alg := range algorithms {
		if alg.oid.Equal(oid) {
			return alg.id, true
		}
	}
	return 0, false
}

// Key returns pub as an SLH-DSA public key. It accepts the value that circl's
// PrivateKey.Public returns and a pointer to it.
func Key(pub crypto.PublicKey) (slhdsa.PublicKey, bool) {
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

// Verify checks a pure SLH-DSA signature with an empty context, made with pub
// under parameter set id, as RFC 9909 §3 specifies for X.509 and CMS.
func Verify(id slhdsa.ID, pub crypto.PublicKey, data, signature []byte) error {
	key, ok := Key(pub)
	if !ok || key.ID != id {
		return errors.New("pkicmp: key does not match the SLH-DSA signature algorithm")
	}
	if !slhdsa.Verify(&key, slhdsa.NewMessage(data), signature, nil) {
		return errors.New("pkicmp: SLH-DSA signature verification failed")
	}
	return nil
}

// PublicKey returns the SLH-DSA key of a DER SubjectPublicKeyInfo. It reports
// false for other keys and an error for a malformed SLH-DSA key.
func PublicKey(spki []byte) (slhdsa.PublicKey, bool, error) {
	s := cryptobyte.String(spki)
	var info, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&info, cbasn1.SEQUENCE) || !info.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&oid) {
		return slhdsa.PublicKey{}, false, nil
	}
	id, ok := FromOID(oid)
	if !ok {
		return slhdsa.PublicKey{}, false, nil
	}
	var bits asn1.BitString
	if !alg.Empty() || !info.ReadASN1BitString(&bits) || !info.Empty() || !s.Empty() || bits.BitLength%8 != 0 {
		return slhdsa.PublicKey{}, true, errors.New("pkicmp: malformed SLH-DSA public key")
	}
	pub := slhdsa.PublicKey{ID: id}
	if err := pub.UnmarshalBinary(bits.Bytes); err != nil {
		return slhdsa.PublicKey{}, true, errors.New("pkicmp: malformed SLH-DSA public key")
	}
	return pub, true, nil
}

// SignatureID returns the parameter set named by the outer signature algorithm
// of a certificate, CRL or PKCS #10 request. It reports false for other
// algorithms and an error when the SLH-DSA parameters are present.
func SignatureID(signed []byte) (slhdsa.ID, bool, error) {
	s := cryptobyte.String(signed)
	var outer, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.SkipASN1(cbasn1.SEQUENCE) ||
		!outer.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return 0, false, nil
	}
	id, ok := FromOID(oid)
	if !ok {
		return 0, false, nil
	}
	if !alg.Empty() {
		return 0, false, errors.New("pkicmp: SLH-DSA parameters must be absent")
	}
	return id, true, nil
}

// CheckSignatureFrom works like compositex509.CheckSignatureFrom and also
// verifies certificates signed by an SLH-DSA parent key. It applies the same
// basic constraints and key usage checks as crypto/x509.
func CheckSignatureFrom(cert, parent *x509.Certificate) error {
	pub, ok, err := PublicKey(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if !ok {
		return compositex509.CheckSignatureFrom(cert, parent)
	}
	// RFC 5280 §4.2.1.9, as enforced by crypto/x509.
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	id, ok, err := SignatureID(cert.Raw)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("pkicmp: certificate is not signed with the SLH-DSA key of its issuer")
	}
	return Verify(id, pub, cert.RawTBSCertificate, cert.Signature)
}
