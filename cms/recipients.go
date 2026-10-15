package cms

import (
	"crypto"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidRSAESOAEP  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}

	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// The dhSinglePass-stdDH KDF schemes of RFC 5753 §7.1.4 and RFC 9481 §4.1.2.
	oidStdDHSHA1KDF   = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 63, 0, 2}
	oidStdDHSHA224KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 0}
	oidStdDHSHA256KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
	oidStdDHSHA384KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}
	oidStdDHSHA512KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 3}

	oidORIKEM     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 13, 3}
	oidMLKEM768   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
	oidHKDFSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 28}
	oidHKDFSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 29}
	oidHKDFSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 30}
	// The ANS X9.44 key derivation functions of RFC 9690 Appendix B.
	oidKDF2 = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 9, 44, 1, 1}
	oidKDF3 = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 9, 44, 1, 2}
)

// ML-KEM encapsulation key sizes from FIPS 203 Table 3.
const (
	mlkem768EncapsulationKeySize  = 1184
	mlkem1024EncapsulationKeySize = 1568
)

// keyTransRecipient encodes a KeyTransRecipientInfo (RFC 5652 §6.2.1) that
// carries cek encrypted with RSAES-OAEP and SHA-256.
func keyTransRecipient(pub *rsa.PublicKey, rid RecipientID, cek []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return nil, err
	}
	version := int64(0)
	if rid.SubjectKeyID != nil {
		version = 2
	}
	sha := algorithm(oidSHA256)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		rid.addRecipientIdentifier(b)
		// RSAES-OAEP-params (RFC 4055 §4.1) with SHA-256 for the hash and for MGF1, and an empty label.
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidRSAESOAEP)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(sha)
				})
				b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidMGF1)
						b.AddBytes(sha)
					})
				})
			})
		})
		b.AddASN1OctetString(encrypted)
	})
	return b.Bytes()
}

// openKeyTransRecipient decrypts the content-encryption key of a KeyTransRecipientInfo.
// The second result is false when ri is not a KeyTransRecipientInfo.
func openKeyTransRecipient(ri cryptobyte.String, key crypto.Decrypter) ([]byte, bool, error) {
	if !ri.PeekASN1Tag(cbasn1.SEQUENCE) {
		return nil, false, nil
	}
	var seq, encrypted cryptobyte.String
	var version int64
	if !ri.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&version) || (version != 0 && version != 2) {
		return nil, true, errors.New("cms: invalid KeyTransRecipientInfo")
	}
	if _, err := readRecipientIdentifier(&seq); err != nil {
		return nil, true, err
	}
	alg, err := readAlgorithmIdentifier(&seq)
	if err != nil {
		return nil, true, err
	}
	if !alg.oid.Equal(oidRSAESOAEP) {
		return nil, true, fmt.Errorf("cms: unsupported key transport algorithm %v, only RSAES-OAEP is accepted", alg.oid)
	}
	opts, err := parseOAEPParams(alg.params)
	if err != nil {
		return nil, true, err
	}
	if !seq.ReadASN1(&encrypted, cbasn1.OCTET_STRING) || !seq.Empty() {
		return nil, true, errors.New("cms: invalid KeyTransRecipientInfo")
	}
	cek, err := key.Decrypt(rand.Reader, encrypted, opts)
	if err != nil {
		return nil, true, errDecrypt
	}
	return cek, true, nil
}

// parseOAEPParams decodes RSAES-OAEP-params (RFC 4055 §4.1), applying the SHA-1 defaults for absent fields.
func parseOAEPParams(params cryptobyte.String) (*rsa.OAEPOptions, error) {
	opts := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	if len(params) == 0 {
		return opts, nil
	}
	invalid := errors.New("cms: invalid RSAES-OAEP parameters")
	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() {
		return nil, invalid
	}
	var field cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&field, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, invalid
	}
	if present {
		alg, err := readAlgorithmIdentifier(&field)
		h, ok := hashByOID(alg.oid)
		if err != nil || !ok || !field.Empty() || !alg.paramsAbsentOrNull() {
			return nil, invalid
		}
		opts.Hash = h
	}
	if !seq.ReadOptionalASN1(&field, &present, cbasn1.Tag(1).ContextSpecific().Constructed()) {
		return nil, invalid
	}
	if present {
		alg, err := readAlgorithmIdentifier(&field)
		if err != nil || !alg.oid.Equal(oidMGF1) || !field.Empty() {
			return nil, invalid
		}
		inner, err := readAlgorithmIdentifier(&alg.params)
		h, ok := hashByOID(inner.oid)
		if err != nil || !ok || !inner.paramsAbsentOrNull() {
			return nil, invalid
		}
		opts.MGFHash = h
	}
	if !seq.ReadOptionalASN1(&field, &present, cbasn1.Tag(2).ContextSpecific().Constructed()) {
		return nil, invalid
	}
	if present {
		alg, err := readAlgorithmIdentifier(&field)
		if err != nil || !alg.oid.Equal(oidPSpecified) || !field.Empty() {
			return nil, invalid
		}
		var label cryptobyte.String
		if !alg.params.ReadASN1(&label, cbasn1.OCTET_STRING) {
			return nil, invalid
		}
		opts.Label = label
	}
	if !seq.Empty() {
		return nil, invalid
	}
	return opts, nil
}

// ecdhScheme returns the dhSinglePass-stdDH scheme and its KDF hash that RFC 9481 Table 2 pairs with a curve.
func ecdhScheme(curve ecdh.Curve) (asn1.ObjectIdentifier, crypto.Hash, error) {
	switch curve {
	case ecdh.P256():
		return oidStdDHSHA256KDF, crypto.SHA256, nil
	case ecdh.P384():
		return oidStdDHSHA384KDF, crypto.SHA384, nil
	case ecdh.P521():
		return oidStdDHSHA512KDF, crypto.SHA512, nil
	}
	return nil, 0, fmt.Errorf("cms: unsupported ECDH curve %v", curve)
}

// ecdhKDFHash maps a dhSinglePass-stdDH scheme to its KDF hash.
func ecdhKDFHash(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidStdDHSHA1KDF):
		return crypto.SHA1, true
	case oid.Equal(oidStdDHSHA224KDF):
		return crypto.SHA224, true
	case oid.Equal(oidStdDHSHA256KDF):
		return crypto.SHA256, true
	case oid.Equal(oidStdDHSHA384KDF):
		return crypto.SHA384, true
	case oid.Equal(oidStdDHSHA512KDF):
		return crypto.SHA512, true
	}
	return 0, false
}

// keyAgreeRecipient encodes an ephemeral-static ECDH KeyAgreeRecipientInfo (RFC 5753 §3.1) that wraps cek with AES-256.
func keyAgreeRecipient(pub *ecdh.PublicKey, rid RecipientID, cek []byte) ([]byte, error) {
	scheme, h, err := ecdhScheme(pub.Curve())
	if err != nil {
		return nil, err
	}
	ephemeral, err := pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	z, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, err
	}
	wrapAlg := algorithm(oidAES256Wrap)
	sharedInfo, err := eccSharedInfo(wrapAlg, nil, 32)
	if err != nil {
		return nil, err
	}
	kek, err := x963KDF(h, z, sharedInfo, 32)
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapKey(kek, cek)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		// originator [0] EXPLICIT OriginatorIdentifierOrKey, originatorKey [1] OriginatorPublicKey.
		// RFC 5753 §3.1.1 says the id-ecPublicKey parameters SHOULD be absent.
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(algorithm(oidECPublicKey))
				b.AddASN1BitString(ephemeral.PublicKey().Bytes())
			})
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(scheme)
			b.AddBytes(wrapAlg)
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				rid.addKeyAgreeRecipientIdentifier(b)
				b.AddASN1OctetString(wrapped)
			})
		})
	})
	return b.Bytes()
}

// openKeyAgreeRecipient recovers the content-encryption key of an ephemeral-static ECDH KeyAgreeRecipientInfo.
// The second result is false when ri is not a KeyAgreeRecipientInfo.
func openKeyAgreeRecipient(ri cryptobyte.String, key ecdh.KeyExchanger) ([]byte, bool, error) {
	tag := cbasn1.Tag(1).ContextSpecific().Constructed()
	if !ri.PeekASN1Tag(tag) {
		return nil, false, nil
	}
	invalid := errors.New("cms: invalid KeyAgreeRecipientInfo")
	var seq cryptobyte.String
	var version int64
	if !ri.ReadASN1(&seq, tag) || !seq.ReadASN1Integer(&version) || version != 3 {
		return nil, true, invalid
	}
	point, err := readOriginatorKey(&seq)
	if err != nil {
		return nil, true, err
	}
	ukm, err := readOptionalExplicitOctetString(&seq, 1)
	if err != nil {
		return nil, true, invalid
	}
	alg, err := readAlgorithmIdentifier(&seq)
	if err != nil {
		return nil, true, err
	}
	h, ok := ecdhKDFHash(alg.oid)
	if !ok {
		return nil, true, fmt.Errorf("cms: unsupported key agreement algorithm %v", alg.oid)
	}
	wrapAlg, kekLength, err := readWrapAlgorithm(&alg.params)
	if err != nil {
		return nil, true, err
	}
	encrypted, err := readRecipientEncryptedKey(&seq)
	if err != nil {
		return nil, true, err
	}
	ephemeral, err := key.Curve().NewPublicKey(point)
	if err != nil {
		return nil, true, errors.New("cms: originator key is not on the recipient's curve")
	}
	z, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, true, errDecrypt
	}
	sharedInfo, err := eccSharedInfo(wrapAlg.raw, ukm, kekLength)
	if err != nil {
		return nil, true, err
	}
	kek, err := x963KDF(h, z, sharedInfo, kekLength)
	if err != nil {
		return nil, true, err
	}
	cek, err := unwrapKey(kek, encrypted)
	if err != nil {
		return nil, true, errDecrypt
	}
	return cek, true, nil
}

// readOriginatorKey reads the originator field of a KeyAgreeRecipientInfo and
// returns the ephemeral public point. Other originator forms are refused.
func readOriginatorKey(seq *cryptobyte.String) ([]byte, error) {
	var originator, originatorKey cryptobyte.String
	if !seq.ReadASN1(&originator, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("cms: invalid KeyAgreeRecipientInfo")
	}
	if !originator.ReadASN1(&originatorKey, cbasn1.Tag(1).ContextSpecific().Constructed()) || !originator.Empty() {
		return nil, errors.New("cms: only an ephemeral originator key is supported")
	}
	keyAlg, err := readAlgorithmIdentifier(&originatorKey)
	if err != nil || !keyAlg.oid.Equal(oidECPublicKey) {
		return nil, errors.New("cms: originator key is not an EC public key")
	}
	var point asn1.BitString
	if !originatorKey.ReadASN1BitString(&point) || !originatorKey.Empty() || point.BitLength%8 != 0 {
		return nil, errors.New("cms: invalid originator key")
	}
	return point.Bytes, nil
}

// readRecipientEncryptedKey reads the recipientEncryptedKeys of a
// KeyAgreeRecipientInfo and returns the first encrypted key, because CMP
// envelopes have one recipient.
func readRecipientEncryptedKey(seq *cryptobyte.String) ([]byte, error) {
	var keys, rek, encrypted cryptobyte.String
	if !seq.ReadASN1(&keys, cbasn1.SEQUENCE) || !seq.Empty() || !keys.ReadASN1(&rek, cbasn1.SEQUENCE) {
		return nil, errors.New("cms: invalid recipientEncryptedKeys")
	}
	if _, err := readRecipientIdentifier(&rek); err != nil {
		return nil, err
	}
	if !rek.ReadASN1(&encrypted, cbasn1.OCTET_STRING) || !rek.Empty() {
		return nil, errors.New("cms: invalid RecipientEncryptedKey")
	}
	return encrypted, nil
}

// readOptionalExplicitOctetString reads an optional [tag] EXPLICIT OCTET STRING, such as a ukm.
func readOptionalExplicitOctetString(seq *cryptobyte.String, tag uint8) ([]byte, error) {
	explicitTag := cbasn1.Tag(tag).ContextSpecific().Constructed()
	if !seq.PeekASN1Tag(explicitTag) {
		return nil, nil
	}
	var explicit, value cryptobyte.String
	if !seq.ReadASN1(&explicit, explicitTag) || !explicit.ReadASN1(&value, cbasn1.OCTET_STRING) || !explicit.Empty() {
		return nil, errors.New("cms: invalid explicit OCTET STRING")
	}
	return value, nil
}

// readWrapAlgorithm reads a key wrap AlgorithmIdentifier and returns it with its key size.
func readWrapAlgorithm(s *cryptobyte.String) (algorithmIdentifier, int, error) {
	wrapAlg, err := readAlgorithmIdentifier(s)
	if err != nil {
		return algorithmIdentifier{}, 0, err
	}
	size, ok := wrapKeySize(wrapAlg.oid)
	if !ok || !wrapAlg.paramsAbsentOrNull() {
		return algorithmIdentifier{}, 0, fmt.Errorf("cms: unsupported key wrap algorithm %v", wrapAlg.oid)
	}
	return wrapAlg, size, nil
}

// mlkemAlgorithm returns the ML-KEM OID for an encapsulation key encoding.
// Parameter sets other than ML-KEM-768 and ML-KEM-1024 are refused.
func mlkemAlgorithm(encapsulationKey []byte) (asn1.ObjectIdentifier, error) {
	switch len(encapsulationKey) {
	case mlkem768EncapsulationKeySize:
		return oidMLKEM768, nil
	case mlkem1024EncapsulationKeySize:
		return oidMLKEM1024, nil
	}
	return nil, fmt.Errorf("cms: unsupported KEM public key of %d bytes, only ML-KEM-768 and ML-KEM-1024 are supported",
		len(encapsulationKey))
}

// hkdfHash maps an HKDF algorithm OID (RFC 8619) to its hash constructor.
func hkdfHash(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidHKDFSHA256):
		return sha256.New, true
	case oid.Equal(oidHKDFSHA384):
		return sha512.New384, true
	case oid.Equal(oidHKDFSHA512):
		return sha512.New, true
	}
	return nil, false
}

// kemKDF derives a key-encryption key of size bytes from a KEM shared secret
// and the encoded CMSORIforKEMOtherInfo.
type kemKDF func(sharedSecret, otherInfo []byte, size int) ([]byte, error)

// kemKeyDerivation returns the key derivation function named by the kdf field
// of a KEMRecipientInfo.
//
// RFC 9936 §3 requires HKDF with SHA-256 for ML-KEM and lets implementations
// support other KDFs. Decryption also accepts HKDF with SHA-384 or SHA-512 and
// the ANS X9.44 KDF2 and KDF3 of RFC 9690 Appendix B, because Bouncy Castle
// uses KDF3 with SHA-256 by default. SHA-1 is refused, as RFC 9690 requires.
func kemKeyDerivation(alg algorithmIdentifier) (kemKDF, error) {
	unsupported := fmt.Errorf("cms: unsupported KEM key derivation algorithm %v", alg.oid)
	if newHash, ok := hkdfHash(alg.oid); ok {
		// RFC 8619 §3: the parameters are absent.
		if len(alg.params) != 0 {
			return nil, unsupported
		}
		return func(z, info []byte, size int) ([]byte, error) {
			return hkdf.Key(newHash, z, nil, string(info), size)
		}, nil
	}
	isKDF3 := alg.oid.Equal(oidKDF3)
	if !isKDF3 && !alg.oid.Equal(oidKDF2) {
		return nil, unsupported
	}
	// The parameters are the required hash AlgorithmIdentifier.
	params := alg.params
	hashAlg, err := readAlgorithmIdentifier(&params)
	if err != nil || !params.Empty() || !hashAlg.paramsAbsentOrNull() {
		return nil, fmt.Errorf("cms: invalid %v key derivation parameters", alg.oid)
	}
	h, ok := hashByOID(hashAlg.oid)
	if !ok || h == crypto.SHA1 {
		return nil, fmt.Errorf("cms: unsupported %v key derivation hash %v", alg.oid, hashAlg.oid)
	}
	if isKDF3 {
		return func(z, info []byte, size int) ([]byte, error) { return kdf3(h, z, info, size) }, nil
	}
	return func(z, info []byte, size int) ([]byte, error) { return x963KDF(h, z, info, size) }, nil
}

// kemRecipient encodes an OtherRecipientInfo carrying a KEMRecipientInfo (RFC 9629 §3)
// with HKDF-SHA256 and AES-256 key wrap, as RFC 9936 §3 requires for ML-KEM.
func kemRecipient(pub crypto.Encapsulator, rid RecipientID, cek []byte) ([]byte, error) {
	kemAlg, err := mlkemAlgorithm(pub.Bytes())
	if err != nil {
		return nil, err
	}
	sharedSecret, ciphertext := pub.Encapsulate()
	wrapAlg := algorithm(oidAES256Wrap)
	info, err := kemOtherInfo(wrapAlg, nil, 32)
	if err != nil {
		return nil, err
	}
	kek, err := hkdf.Key(sha256.New, sharedSecret, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapKey(kek, cek)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidORIKEM)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(0)
			rid.addRecipientIdentifier(b)
			b.AddBytes(algorithm(kemAlg))
			b.AddASN1OctetString(ciphertext)
			b.AddBytes(algorithm(oidHKDFSHA256))
			b.AddASN1Int64(32)
			b.AddBytes(wrapAlg)
			b.AddASN1OctetString(wrapped)
		})
	})
	return b.Bytes()
}

// openKEMRecipient recovers the content-encryption key of a KEMRecipientInfo.
// The second result is false when ri is not an OtherRecipientInfo of type id-ori-kem.
func openKEMRecipient(ri cryptobyte.String, key crypto.Decapsulator) ([]byte, bool, error) {
	tag := cbasn1.Tag(4).ContextSpecific().Constructed()
	if !ri.PeekASN1Tag(tag) {
		return nil, false, nil
	}
	var ori, seq, ciphertext, encrypted cryptobyte.String
	var oriType asn1.ObjectIdentifier
	if !ri.ReadASN1(&ori, tag) || !ori.ReadASN1ObjectIdentifier(&oriType) {
		return nil, true, errors.New("cms: invalid OtherRecipientInfo")
	}
	if !oriType.Equal(oidORIKEM) {
		return nil, false, nil
	}
	invalid := errors.New("cms: invalid KEMRecipientInfo")
	var version, kekLength int64
	if !ori.ReadASN1(&seq, cbasn1.SEQUENCE) || !ori.Empty() || !seq.ReadASN1Integer(&version) || version != 0 {
		return nil, true, invalid
	}
	if _, err := readRecipientIdentifier(&seq); err != nil {
		return nil, true, err
	}
	if err := checkKEMAlgorithm(&seq, key); err != nil {
		return nil, true, err
	}
	if !seq.ReadASN1(&ciphertext, cbasn1.OCTET_STRING) {
		return nil, true, invalid
	}
	kdfAlg, err := readAlgorithmIdentifier(&seq)
	if err != nil {
		return nil, true, err
	}
	deriveKEK, err := kemKeyDerivation(kdfAlg)
	if err != nil {
		return nil, true, err
	}
	if !seq.ReadASN1Integer(&kekLength) {
		return nil, true, invalid
	}
	ukm, err := readOptionalExplicitOctetString(&seq, 0)
	if err != nil {
		return nil, true, invalid
	}
	wrapAlg, size, err := readWrapAlgorithm(&seq)
	if err != nil {
		return nil, true, err
	}
	// RFC 9629 §3: kekLength is the size of the key-encryption key the wrap algorithm needs.
	if kekLength != int64(size) {
		return nil, true, errors.New("cms: kekLength does not match the key wrap algorithm")
	}
	if !seq.ReadASN1(&encrypted, cbasn1.OCTET_STRING) || !seq.Empty() {
		return nil, true, invalid
	}
	sharedSecret, err := key.Decapsulate(ciphertext)
	if err != nil {
		return nil, true, errDecrypt
	}
	info, err := kemOtherInfo(wrapAlg.raw, ukm, size)
	if err != nil {
		return nil, true, err
	}
	kek, err := deriveKEK(sharedSecret, info, size)
	if err != nil {
		return nil, true, err
	}
	cek, err := unwrapKey(kek, encrypted)
	if err != nil {
		return nil, true, errDecrypt
	}
	return cek, true, nil
}

// checkKEMAlgorithm reads the kem AlgorithmIdentifier of a KEMRecipientInfo and
// checks that it names the parameter set of key, with absent parameters.
func checkKEMAlgorithm(seq *cryptobyte.String, key crypto.Decapsulator) error {
	kemAlg, err := readAlgorithmIdentifier(seq)
	if err != nil {
		return err
	}
	want, err := mlkemAlgorithm(key.Encapsulator().Bytes())
	if err != nil {
		return err
	}
	if !kemAlg.oid.Equal(want) || len(kemAlg.params) != 0 {
		return fmt.Errorf("cms: KEM algorithm %v does not match the decryption key", kemAlg.oid)
	}
	return nil
}
