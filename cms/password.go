package cms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Password is a shared secret that protects the content-encryption key in a
// PasswordRecipientInfo (RFC 5652 §6.2.4), as a MAC-protected CMP exchange
// does for a centrally generated private key (RFC 9483 §4.1.6.3). Pass it to
// [Encrypt] or [EncryptSignedData] as the recipient with a zero
// [RecipientID]. Pass it to [Decrypt] as the key.
//
// [Encrypt] wraps the key with the AES key wrap, as RFC 9483 §4.1.6.3 and
// RFC 9481 §4.3 require. [Decrypt] also reads the RFC 3211 key wrap of
// [PWRIKEKPassword].
type Password []byte

// PWRIKEKPassword is a [Password] that [Encrypt] wraps with the id-alg-PWRI-KEK
// key wrap of RFC 3211 §2.3 over AES-256-CBC. OpenSSL reads no other form.
type PWRIKEKPassword []byte

var (
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	// oidPWRIKEK is the key wrap of RFC 3211 §2.3, which OpenSSL and Bouncy Castle use.
	oidPWRIKEK = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 9}
)

const (
	// passwordIterations is the PBKDF2 iteration count of an encrypted key.
	passwordIterations = 100000
	// maxPasswordIterations bounds the PBKDF2 work a peer can demand from [Decrypt].
	maxPasswordIterations = 10000000
	passwordSaltSize      = 16
)

// prfHashes maps the PBKDF2 pseudorandom functions of RFC 8018 Appendix B.1 to their hashes.
var prfHashes = map[string]crypto.Hash{
	oidHMACWithSHA1.String():   crypto.SHA1,
	oidHMACWithSHA224.String(): crypto.SHA224,
	oidHMACWithSHA256.String(): crypto.SHA256,
	oidHMACWithSHA384.String(): crypto.SHA384,
	oidHMACWithSHA512.String(): crypto.SHA512,
}

// passwordRecipient encodes a PasswordRecipientInfo (RFC 5652 §6.2.4) that
// wraps cek with a key derived from password with PBKDF2 and HMAC-SHA256
// (RFC 9481 §4.4), under a salt independent of any MAC salt. With pwriKEK the
// key wrap is the RFC 3211 one over AES-256-CBC, otherwise the AES-256 key wrap
// of RFC 9481 §4.3.
func passwordRecipient(password []byte, pwriKEK bool, cek []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("cms: empty password")
	}
	salt := make([]byte, passwordSaltSize)
	rand.Read(salt)
	kek, err := pbkdf2.Key(crypto.SHA256.New, string(password), salt, passwordIterations, len(cek))
	if err != nil {
		return nil, err
	}
	var wrapped, kekAlgorithm []byte
	if pwriKEK {
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		wrapped, err = wrapPWRIKEK(kek, iv, cek)
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPWRIKEK)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAES256CBC)
				b.AddASN1OctetString(iv)
			})
		})
		kekAlgorithm = b.BytesOrPanic()
	} else {
		wrapped, err = wrapKey(kek, cek)
		kekAlgorithm = algorithm(oidAES256Wrap)
	}
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	// pwri [3] IMPLICIT PasswordRecipientInfo
	b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		// keyDerivationAlgorithm [0] IMPLICIT KeyDerivationAlgorithmIdentifier
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPBKDF2)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(salt)
				b.AddASN1Int64(passwordIterations)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidHMACWithSHA256)
					b.AddASN1NULL()
				})
			})
		})
		b.AddBytes(kekAlgorithm)
		b.AddASN1OctetString(wrapped)
	})
	return b.Bytes()
}

// wrapPWRIKEK applies the RFC 3211 §2.3 key wrap: the key length, three check
// bytes, the key and random padding to at least two blocks, encrypted twice
// with AES-CBC, the second pass chained from the last block of the first.
func wrapPWRIKEK(kek, iv, key []byte) ([]byte, error) {
	if len(key) < 3 || len(key) > 255 {
		return nil, errors.New("cms: key to wrap must be 3 to 255 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := max(2*aes.BlockSize, (4+len(key)+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	buf := make([]byte, n)
	rand.Read(buf[4+len(key):])
	buf[0] = byte(len(key)) // #nosec G115 -- the key length is checked to fit a byte
	for i := range 3 {
		buf[1+i] = ^key[i]
	}
	copy(buf[4:], key)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	cipher.NewCBCEncrypter(block, buf[n-aes.BlockSize:]).CryptBlocks(buf, buf)
	return buf, nil
}

// openPasswordRecipient returns the content-encryption key of a PasswordRecipientInfo.
// The second result is false when ri is not a PasswordRecipientInfo.
//
// The key may be wrapped with the AES key wrap of RFC 3394 that RFC 9481 §4.3
// requires. It may also be wrapped with the RFC 3211 key wrap over AES-CBC that
// OpenSSL and Bouncy Castle write.
func openPasswordRecipient(ri cryptobyte.String, password []byte) ([]byte, bool, error) {
	var seq cryptobyte.String
	if !ri.ReadASN1(&seq, cbasn1.Tag(3).ContextSpecific().Constructed()) {
		return nil, false, nil
	}
	var version int64
	var kdf cryptobyte.String
	if !seq.ReadASN1Integer(&version) || version != 0 {
		return nil, true, errors.New("cms: invalid PasswordRecipientInfo version")
	}
	if !seq.ReadASN1(&kdf, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, true, errors.New("cms: PasswordRecipientInfo without keyDerivationAlgorithm is not supported")
	}
	derive, err := pbkdf2Deriver(kdf)
	if err != nil {
		return nil, true, err
	}
	kekAlg, err := readAlgorithmIdentifier(&seq)
	if err != nil {
		return nil, true, err
	}
	var encryptedKey cryptobyte.String
	if !seq.ReadASN1(&encryptedKey, cbasn1.OCTET_STRING) || !seq.Empty() {
		return nil, true, errors.New("cms: invalid PasswordRecipientInfo")
	}
	if size, ok := wrapKeySize(kekAlg.oid); ok {
		if !kekAlg.paramsAbsentOrNull() {
			return nil, true, errors.New("cms: invalid key wrap parameters")
		}
		kek, err := derive(password, size)
		if err != nil {
			return nil, true, err
		}
		cek, err := unwrapKey(kek, encryptedKey)
		if err != nil {
			return nil, true, errDecrypt
		}
		return cek, true, nil
	}
	if !kekAlg.oid.Equal(oidPWRIKEK) {
		return nil, true, fmt.Errorf("cms: unsupported password key encryption algorithm %v", kekAlg.oid)
	}
	inner, err := readAlgorithmIdentifier(&kekAlg.params)
	if err != nil || !kekAlg.params.Empty() {
		return nil, true, errors.New("cms: invalid PWRI-KEK parameters")
	}
	size, ok := contentKeySize(inner.oid)
	var iv cryptobyte.String
	if !ok {
		return nil, true, fmt.Errorf("cms: unsupported PWRI-KEK cipher %v", inner.oid)
	}
	if !inner.params.ReadASN1(&iv, cbasn1.OCTET_STRING) || !inner.params.Empty() || len(iv) != aes.BlockSize {
		return nil, true, errors.New("cms: invalid PWRI-KEK cipher parameters")
	}
	kek, err := derive(password, size)
	if err != nil {
		return nil, true, err
	}
	cek, err := unwrapPWRIKEK(kek, iv, encryptedKey)
	if err != nil {
		return nil, true, err
	}
	return cek, true, nil
}

// pbkdf2Deriver parses the content of a keyDerivationAlgorithm that names
// PBKDF2 (RFC 8018 Appendix A.2) and returns the derivation of a key of a
// given size from a password. A keyLength in the parameters must match that size.
func pbkdf2Deriver(kdf cryptobyte.String) (func(password []byte, size int) ([]byte, error), error) {
	var oid asn1.ObjectIdentifier
	var params, salt cryptobyte.String
	var iterations int64
	if !kdf.ReadASN1ObjectIdentifier(&oid) || !oid.Equal(oidPBKDF2) {
		return nil, errors.New("cms: unsupported key derivation algorithm")
	}
	if !kdf.ReadASN1(&params, cbasn1.SEQUENCE) || !kdf.Empty() {
		return nil, errors.New("cms: invalid PBKDF2 parameters")
	}
	// The otherSource alternative of the salt is not supported.
	if !params.ReadASN1(&salt, cbasn1.OCTET_STRING) || !params.ReadASN1Integer(&iterations) {
		return nil, errors.New("cms: invalid PBKDF2 parameters")
	}
	if iterations < 1 || iterations > maxPasswordIterations {
		return nil, fmt.Errorf("cms: PBKDF2 iteration count %d is outside 1 to %d", iterations, maxPasswordIterations)
	}
	keyLength := int64(-1)
	if params.PeekASN1Tag(cbasn1.INTEGER) && !params.ReadASN1Integer(&keyLength) {
		return nil, errors.New("cms: invalid PBKDF2 key length")
	}
	// The prf defaults to HMAC-SHA1 (RFC 8018 Appendix A.2).
	prf := crypto.SHA1
	if !params.Empty() {
		alg, err := readAlgorithmIdentifier(&params)
		if err != nil || !params.Empty() || !alg.paramsAbsentOrNull() {
			return nil, errors.New("cms: invalid PBKDF2 pseudorandom function")
		}
		var ok bool
		if prf, ok = prfHashes[alg.oid.String()]; !ok {
			return nil, fmt.Errorf("cms: unsupported PBKDF2 pseudorandom function %v", alg.oid)
		}
	}
	return func(password []byte, size int) ([]byte, error) {
		if keyLength != -1 && keyLength != int64(size) {
			return nil, errors.New("cms: PBKDF2 key length does not match the key encryption algorithm")
		}
		return pbkdf2.Key(prf.New, string(password), salt, int(iterations), size)
	}, nil
}

// unwrapPWRIKEK reverses the RFC 3211 §2.3 key wrap: two passes of AES-CBC
// over a block holding the key length, three check bytes and the key.
func unwrapPWRIKEK(kek, iv, wrapped []byte) ([]byte, error) {
	n := len(wrapped)
	if n < 2*aes.BlockSize || n%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errDecrypt
	}
	tmp := make([]byte, n)
	// The outer pass was chained from the last block of the inner one, which
	// decrypting the last block with its predecessor as IV recovers.
	last := tmp[n-aes.BlockSize:]
	cipher.NewCBCDecrypter(block, wrapped[n-2*aes.BlockSize:n-aes.BlockSize]).CryptBlocks(last, wrapped[n-aes.BlockSize:])
	cipher.NewCBCDecrypter(block, last).CryptBlocks(tmp[:n-aes.BlockSize], wrapped[:n-aes.BlockSize])
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(tmp, tmp)
	keyLen := int(tmp[0])
	check := subtle.ConstantTimeByteEq((tmp[1]^tmp[4])&(tmp[2]^tmp[5])&(tmp[3]^tmp[6]), 0xff)
	if keyLen < 3 || 4+keyLen > n || check != 1 {
		return nil, errDecrypt
	}
	return tmp[4 : 4+keyLen], nil
}

// passwordBytes returns the secret of a [Password] or [PWRIKEKPassword].
func passwordBytes(p any) []byte {
	if k, ok := p.(PWRIKEKPassword); ok {
		return k
	}
	return p.(Password)
}
