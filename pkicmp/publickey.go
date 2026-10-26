package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"encoding/asn1"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/internal/keylimit"
)

// ML-KEM algorithm identifiers (RFC 9935 §3).
var (
	oidMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	oidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// ErrMLKEM512 is returned for an ML-KEM-512 key, which the Go standard library does not implement.
var ErrMLKEM512 = errors.New("pkicmp: ML-KEM-512 keys are not supported")

// MaxRSAModulusBits is the largest RSA modulus accepted in a key or certificate
// taken from a peer. The cost of one RSA operation grows with the square of the
// modulus size and crypto/rsa does not bound it, so a larger key would let one
// message cost tens of seconds of verification. The limit matches OpenSSL's.
const MaxRSAModulusBits = keylimit.MaxRSAModulusBits

// ErrRSAKeyTooLarge is returned for an RSA key whose modulus exceeds [MaxRSAModulusBits].
var ErrRSAKeyTooLarge = keylimit.ErrRSAKeyTooLarge

// ParsePublicKey parses a DER SubjectPublicKeyInfo.
//
// ML-KEM-768 and ML-KEM-1024 keys (RFC 9935) are returned as *mlkem.EncapsulationKey768
// and *mlkem.EncapsulationKey1024, and ML-KEM-512 keys are refused with [ErrMLKEM512].
// An SLH-DSA key (RFC 9909) is returned as an slhdsa.PublicKey value from
// github.com/cloudflare/circl/sign/slhdsa, the type its PrivateKey.Public returns.
// A composite ML-DSA key is returned as *compositemldsa.PublicKey and every other key
// as crypto/x509 returns it. An RSA key whose modulus exceeds [MaxRSAModulusBits] is
// refused with [ErrRSAKeyTooLarge].
func ParsePublicKey(der []byte) (crypto.PublicKey, error) {
	oid, key, ok := parseSPKI(der)
	if id, isSLHDSA := SLHDSAAlgorithmFromOID(oid); ok && isSLHDSA {
		pub := slhdsa.PublicKey{ID: id}
		if err := pub.UnmarshalBinary(key); err != nil {
			return nil, errors.New("pkicmp: malformed SLH-DSA public key")
		}
		return pub, nil
	}
	switch {
	case !ok:
		// Leave the error report for a malformed encoding to crypto/x509.
	case oid.Equal(oidMLKEM768):
		return mlkem.NewEncapsulationKey768(key)
	case oid.Equal(oidMLKEM1024):
		return mlkem.NewEncapsulationKey1024(key)
	case oid.Equal(oidMLKEM512):
		return nil, ErrMLKEM512
	}
	pub, err := compositex509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	if err := keylimit.Check(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// MarshalPublicKey encodes a public key as a DER SubjectPublicKeyInfo. It accepts the
// key types [ParsePublicKey] returns.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var key []byte
	switch k := pub.(type) {
	case *mlkem.EncapsulationKey768:
		oid, key = oidMLKEM768, k.Bytes()
	case *mlkem.EncapsulationKey1024:
		oid, key = oidMLKEM1024, k.Bytes()
	case slhdsa.PublicKey, *slhdsa.PublicKey:
		slh, _ := slhdsaPublicKey(k)
		var known bool
		if oid, known = SLHDSAAlgorithmOID(slh.ID); !known {
			return nil, errors.New("pkicmp: unknown SLH-DSA parameter set")
		}
		var err error
		if key, err = slh.MarshalBinary(); err != nil {
			return nil, err
		}
	default:
		return compositex509.MarshalPKIXPublicKey(pub)
	}
	// RFC 9935 §4 and RFC 9909 §4: the parameters field is absent.
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1BitString(key)
	})
	return b.Bytes()
}

// parseSPKI returns the algorithm OID and key bits of a SubjectPublicKeyInfo with absent algorithm parameters.
func parseSPKI(der []byte) (asn1.ObjectIdentifier, []byte, bool) {
	s := cryptobyte.String(der)
	var spki, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	var bits asn1.BitString
	if !s.ReadASN1(&spki, cbasn1.SEQUENCE) || !s.Empty() || !spki.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&oid) || !alg.Empty() {
		return nil, nil, false
	}
	if !spki.ReadASN1BitString(&bits) || !spki.Empty() || bits.BitLength%8 != 0 {
		return nil, nil, false
	}
	return oid, bits.Bytes, true
}

// IsKEMKey reports whether pub is an ML-KEM key, which can only prove possession by decryption.
func IsKEMKey(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case *mlkem.EncapsulationKey768, *mlkem.EncapsulationKey1024:
		return true
	}
	return false
}

// PublicKeysEqual reports whether a and b are the same public key. It compares
// ML-KEM keys by their encoding, because the mlkem types have no Equal method,
// SLH-DSA keys as values whether either is passed by pointer, and other keys
// with their Equal method.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	if ka, ok := slhdsaPublicKey(a); ok {
		kb, ok := slhdsaPublicKey(b)
		return ok && ka.Equal(kb)
	}
	switch ka := a.(type) {
	case *mlkem.EncapsulationKey768:
		kb, ok := b.(*mlkem.EncapsulationKey768)
		return ok && bytes.Equal(ka.Bytes(), kb.Bytes())
	case *mlkem.EncapsulationKey1024:
		kb, ok := b.(*mlkem.EncapsulationKey1024)
		return ok && bytes.Equal(ka.Bytes(), kb.Bytes())
	}
	comparable, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && comparable.Equal(b)
}
