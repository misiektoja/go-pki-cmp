package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

var (
	// Message Digest Algorithms (RFC 9481 §2.1).
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Deprecated SHA-1 signature algorithms, accepted only on request (RFC 9481 §7.1).
	oidSHA1WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidECDSAWithSHA1         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

	// Signature Algorithms (RFC 9481 §3).
	oidSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519                 = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// MAC Algorithms (RFC 9481 §6.1, RFC 9810 §5.1.3.4).
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	// Deprecated: SHOULD NOT be used (RFC 9481 §7.1).
	oidPBMMac_HMACSHA1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	// Unused but reserved for KEM-based MAC (RFC 9810 §5.1.3.4):
	// oidKemBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 16}
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// PBKDF2 (RFC 8018 §A.2).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// HMAC Algorithms (RFC 9481 §6.2.1).
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// X.509 extensions (RFC 5280 §4.2.1.3).
	oidExtensionKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

	// CMP InfoType OIDs (RFC 9810 §5.1.1).
	oidConfirmWaitTime = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14}
	oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}
	oidCertProfile     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 21}
)

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(oidSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported hash algorithm: %v", oid)}
}

func hmacHashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA1) || oid.Equal(oidPBMMac_HMACSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(oidHMACWithSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidHMACWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidHMACWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidHMACWithSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported HMAC algorithm: %v", oid)}
}

// sigAlgFromOID maps an OID to x509.SignatureAlgorithm.
func sigAlgFromOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(oidSHA256WithRSAEncryption):
		return x509.SHA256WithRSA, nil
	case oid.Equal(oidSHA384WithRSAEncryption):
		return x509.SHA384WithRSA, nil
	case oid.Equal(oidSHA512WithRSAEncryption):
		return x509.SHA512WithRSA, nil
	case oid.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(oidEd25519):
		return x509.PureEd25519, nil
	case oid.Equal(oidMLDSA44):
		return x509.MLDSA44, nil
	case oid.Equal(oidMLDSA65):
		return x509.MLDSA65, nil
	case oid.Equal(oidMLDSA87):
		return x509.MLDSA87, nil
	}
	return x509.UnknownSignatureAlgorithm, &ParseError{Detail: fmt.Sprintf("unsupported signature algorithm: %v", oid)}
}

// sha1SigAlgFromOID maps a deprecated SHA-1 signature OID to x509.SignatureAlgorithm.
func sha1SigAlgFromOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, bool) {
	switch {
	case oid.Equal(oidSHA1WithRSAEncryption):
		return x509.SHA1WithRSA, true
	case oid.Equal(oidECDSAWithSHA1):
		return x509.ECDSAWithSHA1, true
	}
	return x509.UnknownSignatureAlgorithm, false
}

// signatureAlgorithm validates parameters before resolving a signature
// identifier, including SHA-1 ones when allowSHA1 is set.
func signatureAlgorithm(alg AlgorithmIdentifier, allowSHA1 bool) (x509.SignatureAlgorithm, error) {
	isMLDSA := alg.Algorithm.Equal(oidMLDSA44) || alg.Algorithm.Equal(oidMLDSA65) || alg.Algorithm.Equal(oidMLDSA87)
	if isMLDSA && len(alg.Parameters) != 0 {
		return x509.UnknownSignatureAlgorithm, &ParseError{Detail: "ML-DSA parameters must be absent"}
	}
	if sigAlg, ok := sha1SigAlgFromOID(alg.Algorithm); ok {
		if !allowSHA1 {
			return x509.UnknownSignatureAlgorithm, &VerificationError{
				Reason: ReasonUnsupportedAlgorithm,
				Err:    fmt.Errorf("SHA-1 signature algorithm %v is deprecated and not enabled", alg.Algorithm),
			}
		}
		return sigAlg, nil
	}
	return sigAlgFromOID(alg.Algorithm)
}

// compositeSignatureAlgorithm resolves a composite ML-DSA signature identifier,
// whose parameters must be absent (draft-ietf-lamps-pq-composite-sigs-19 §7).
func compositeSignatureAlgorithm(alg AlgorithmIdentifier) (compositemldsa.Algorithm, bool, error) {
	composite, ok := compositemldsa.AlgorithmFromOID(alg.Algorithm)
	if !ok {
		return 0, false, nil
	}
	if len(alg.Parameters) != 0 {
		return 0, false, &ParseError{Detail: "composite ML-DSA parameters must be absent"}
	}
	return composite, true, nil
}

// NewCertStatus computes confirmation with an explicit hash identifier for
// ML-DSA and composite ML-DSA certificates.
func NewCertStatus(cert *x509.Certificate, certReqID int64) (CertStatus, error) {
	status := CertStatus{CertReqID: certReqID}
	switch cert.SignatureAlgorithm {
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		sum := sha512.Sum512(cert.Raw)
		status.CertHash = sum[:]
		status.HashAlg = &AlgorithmIdentifier{Algorithm: oidSHA512}
		return status, nil
	default:
		hash, err := CertHash(cert)
		if err != nil {
			return status, err
		}
		status.CertHash = hash
		// The pre-hash is named in the composite algorithm, but receivers
		// without composite support can only learn it from an explicit hashAlg.
		if composite, ok, err := compositex509.SignatureAlgorithm(cert.Raw); err == nil && ok {
			status.HashAlg = &AlgorithmIdentifier{Algorithm: hashOID(composite.PreHash())}
		}
		return status, nil
	}
}

// CertHash computes the certHash of a certificate with the hash matching its
// signature algorithm, as RFC 9810 §5.3.18 and RFC 9481 §3 require.
func CertHash(cert *x509.Certificate) ([]byte, error) {
	hash := certHashFunc(cert)
	if hash == 0 || !hash.Available() {
		return nil, &ParseError{
			Detail: fmt.Sprintf("no certHash algorithm for signature algorithm %v", cert.SignatureAlgorithm),
		}
	}
	h := hash.New()
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}

// CertificateHash computes the confirmation hash using an explicit algorithm when supplied.
func (s *CertStatus) CertificateHash(cert *x509.Certificate) ([]byte, error) {
	if s.HashAlg == nil {
		return CertHash(cert)
	}
	hash, err := hashFromOID(s.HashAlg.Algorithm)
	if err != nil {
		return nil, err
	}
	if hash < crypto.SHA256 || !hash.Available() {
		return nil, &ParseError{Detail: "unsupported confirmation hash"}
	}
	if len(s.HashAlg.Parameters) != 0 && !bytes.Equal(s.HashAlg.Parameters, []byte{5, 0}) {
		return nil, &ParseError{Detail: "invalid confirmation hash parameters"}
	}
	h := hash.New()
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}

// certHashFunc returns the hash that created and verifies the certificate
// signature. A composite ML-DSA signature is computed over its pre-hash, so
// the pre-hash is that hash (RFC 9810 §5.3.18).
func certHashFunc(cert *x509.Certificate) crypto.Hash {
	if hash := hashFromSigAlg(cert.SignatureAlgorithm); hash != 0 {
		return hash
	}
	if composite, ok, err := compositex509.SignatureAlgorithm(cert.Raw); err == nil && ok {
		return composite.PreHash()
	}
	return 0
}

// hashOID maps the SHA-2 hashes used by composite pre-hashing to their OIDs.
func hashOID(hash crypto.Hash) asn1.ObjectIdentifier {
	switch hash {
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidSHA384
	default:
		return oidSHA512
	}
}

// hashFromSigAlg maps x509.SignatureAlgorithm to crypto.Hash.
func hashFromSigAlg(sigAlg x509.SignatureAlgorithm) crypto.Hash {
	switch sigAlg {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1: // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	case x509.PureEd25519:
		// RFC 9481 §3.3: EdDSA uses SHA-512 for certHash.
		return crypto.SHA512
	default:
		// Zero tells callers that no certHash algorithm is defined for sigAlg.
		return 0
	}
}

func signatureAlgorithmFromKey(key crypto.Signer) (asn1.ObjectIdentifier, crypto.Hash, error) {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		// Select hash strength based on key size (NIST SP 800-57 Part 1).
		switch {
		case pub.N.BitLen() >= 4096:
			return oidSHA512WithRSAEncryption, crypto.SHA512, nil
		case pub.N.BitLen() >= 3072:
			return oidSHA384WithRSAEncryption, crypto.SHA384, nil
		default:
			return oidSHA256WithRSAEncryption, crypto.SHA256, nil
		}
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return oidECDSAWithSHA256, crypto.SHA256, nil
		case 384:
			return oidECDSAWithSHA384, crypto.SHA384, nil
		case 521:
			return oidECDSAWithSHA512, crypto.SHA512, nil
		default:
			return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported ECDSA curve size: %d", pub.Curve.Params().BitSize)}
		}
	case ed25519.PublicKey:
		return oidEd25519, crypto.Hash(0), nil
	case *mldsa.PublicKey:
		switch pub.Parameters() {
		case mldsa.MLDSA44():
			return oidMLDSA44, crypto.Hash(0), nil
		case mldsa.MLDSA65():
			return oidMLDSA65, crypto.Hash(0), nil
		case mldsa.MLDSA87():
			return oidMLDSA87, crypto.Hash(0), nil
		}
		return nil, 0, &ParseError{Detail: "unsupported ML-DSA parameters"}
	case *compositemldsa.PublicKey:
		// Composite signing covers the whole message with an empty context.
		return pub.Algorithm().OID(), crypto.Hash(0), nil
	case slhdsa.PublicKey, *slhdsa.PublicKey:
		// circl signs the whole message in pure mode with an empty context, as RFC 9909 §3 requires.
		slh, _ := slhdsaPublicKey(pub)
		if oid, ok := SLHDSAAlgorithmOID(slh.ID); ok {
			return oid, crypto.Hash(0), nil
		}
		return nil, 0, &ParseError{Detail: "unsupported SLH-DSA parameter set"}
	default:
		return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported public key type: %T", pub)}
	}
}

// ImplicitConfirmInfoValue returns an InfoTypeAndValue for the implicitConfirm
// info type (RFC 9810 §5.1.1).
func ImplicitConfirmInfoValue() InfoTypeAndValue {
	return InfoTypeAndValue{
		InfoType: oidImplicitConfirm,
	}
}

// ConfirmWaitTimeInfoValue returns an InfoTypeAndValue for the confirmWaitTime info type.
//
// RFC 9810 §5.1.1.2 defines ConfirmWaitTimeValue as a GeneralizedTime, so the
// value is the absolute instant by which the certConf is expected, not the
// duration itself.
func ConfirmWaitTimeInfoValue(d time.Duration) InfoTypeAndValue {
	if d < 0 {
		d = 0
	}
	deadline := time.Now().Add(d).UTC().Truncate(time.Second)
	val, _ := asn1.MarshalWithParams(deadline, "generalized")
	return InfoTypeAndValue{
		InfoType:  oidConfirmWaitTime,
		InfoValue: val,
	}
}

// ParseConfirmWaitTime returns the deadline carried by a confirmWaitTime info value.
func ParseConfirmWaitTime(itav InfoTypeAndValue) (time.Time, error) {
	if !itav.InfoType.Equal(oidConfirmWaitTime) {
		return time.Time{}, &ParseError{Detail: "not a confirmWaitTime info value"}
	}
	var deadline time.Time
	rest, err := asn1.UnmarshalWithParams(itav.InfoValue, &deadline, "generalized")
	if err != nil {
		return time.Time{}, &ParseError{Detail: "invalid confirmWaitTime: " + err.Error()}
	}
	if len(rest) != 0 {
		return time.Time{}, &ParseError{Detail: "trailing data after confirmWaitTime"}
	}
	return deadline, nil
}
