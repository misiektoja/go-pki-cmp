package cms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- CMP version 2 peers encrypt with Triple DES, which is accepted for decryption only
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidDESEDE3CBC    = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// valueCipher is a CBC content cipher that an EncryptedValue symmAlg names.
type valueCipher struct {
	keySize   int
	blockSize int
	newBlock  func(key []byte) (cipher.Block, error)
}

// valueCipherByOID returns the content cipher of a symmAlg.
func valueCipherByOID(oid asn1.ObjectIdentifier) (valueCipher, bool) {
	if oid.Equal(oidDESEDE3CBC) {
		return valueCipher{keySize: 24, blockSize: des.BlockSize, newBlock: des.NewTripleDESCipher}, true
	}
	if size, ok := contentKeySize(oid); ok {
		return valueCipher{keySize: size, blockSize: aes.BlockSize, newBlock: aes.NewCipher}, true
	}
	return valueCipher{}, false
}

// NewEncryptedValue returns the DER encoding of an EncryptedValue (RFC 4211 §2.1)
// that encrypts content for an RSA key. It is the deprecated encryptedValue
// choice of EncryptedKey, which CMP version 2 peers use (RFC 9810 §5.2.2).
//
// The content is encrypted with AES-256-CBC and the key with RSAES-PKCS1-v1_5,
// because OpenSSL decrypts the key of an EncryptedValue with PKCS #1 v1.5
// whatever keyAlg names. Use [Encrypt] for a peer that accepts EnvelopedData.
func NewEncryptedValue(content []byte, recipient *rsa.PublicKey) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("cms: no recipient key")
	}
	cek := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	rand.Read(cek)
	rand.Read(iv)
	// PKCS #1 v1.5 is deprecated because its decryption can act as a padding
	// oracle. DecryptEncryptedValue guards that side.
	//nolint:staticcheck // SA1019: CMP version 2 peers decrypt only PKCS #1 v1.5.
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, recipient, cek)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(cek)
	padded := pad(content, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// The CRMF module uses implicit tags.
		b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidAES256CBC)
			b.AddASN1OctetString(iv)
		})
		b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddUint8(0) // no unused bits
			b.AddBytes(encKey)
		})
		b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidRSAEncryption)
			b.AddASN1NULL()
		})
		b.AddASN1BitString(encrypted)
	})
	return b.Bytes()
}

// encryptedValue holds the fields of an EncryptedValue that decryption reads.
type encryptedValue struct {
	symmAlg    algorithmIdentifier
	encSymmKey []byte
	// keyAlg is nil when the field is absent.
	keyAlg   *algorithmIdentifier
	encValue []byte
}

// readImplicitAlgorithm decodes an AlgorithmIdentifier carried as the implicitly tagged element [tag].
func readImplicitAlgorithm(elem cryptobyte.String, tag uint8) (algorithmIdentifier, error) {
	var a algorithmIdentifier
	var seq cryptobyte.String
	if !elem.ReadASN1(&seq, cbasn1.Tag(tag).ContextSpecific().Constructed()) || !elem.Empty() ||
		!seq.ReadASN1ObjectIdentifier(&a.oid) {
		return a, errors.New("cms: invalid AlgorithmIdentifier")
	}
	if !seq.Empty() {
		var t cbasn1.Tag
		if !seq.ReadAnyASN1Element(&a.params, &t) || !seq.Empty() {
			return a, errors.New("cms: invalid AlgorithmIdentifier parameters")
		}
	}
	return a, nil
}

// parseEncryptedValue decodes an EncryptedValue. It skips intendedAlg and
// valueHint and requires the fields that decryption needs.
func parseEncryptedValue(der []byte) (*encryptedValue, error) {
	invalid := errors.New("cms: invalid EncryptedValue")
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, invalid
	}
	var v encryptedValue
	var elem, bits cryptobyte.String
	var present bool
	if !seq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, invalid
	}
	symmTag := cbasn1.Tag(1).ContextSpecific().Constructed()
	if !seq.PeekASN1Tag(symmTag) {
		return nil, errors.New("cms: EncryptedValue has no symmAlg")
	}
	if !seq.ReadASN1Element(&elem, symmTag) {
		return nil, invalid
	}
	alg, err := readImplicitAlgorithm(elem, 1)
	if err != nil {
		return nil, err
	}
	v.symmAlg = alg
	if !seq.ReadOptionalASN1(&bits, &present, cbasn1.Tag(2).ContextSpecific()) {
		return nil, invalid
	}
	if !present {
		return nil, errors.New("cms: EncryptedValue has no encSymmKey")
	}
	// A BIT STRING of whole bytes starts with a zero unused-bits count.
	if len(bits) < 2 || bits[0] != 0 {
		return nil, invalid
	}
	v.encSymmKey = bits[1:]
	keyTag := cbasn1.Tag(3).ContextSpecific().Constructed()
	if seq.PeekASN1Tag(keyTag) {
		if !seq.ReadASN1Element(&elem, keyTag) {
			return nil, invalid
		}
		alg, err := readImplicitAlgorithm(elem, 3)
		if err != nil {
			return nil, err
		}
		v.keyAlg = &alg
	}
	var encValue asn1.BitString
	if !seq.SkipOptionalASN1(cbasn1.Tag(4).ContextSpecific()) || !seq.ReadASN1BitString(&encValue) ||
		encValue.BitLength%8 != 0 || !seq.Empty() {
		return nil, invalid
	}
	v.encValue = encValue.Bytes
	return &v, nil
}

// valueKey decrypts the symmetric key of v, which has size bytes.
//
// PKCS #1 v1.5 is decrypted in session key mode: invalid padding yields a random
// key of size bytes instead of an error. Content decrypted with it then fails
// like any other wrong key, so a caller cannot serve as a padding oracle
// (RFC 3218 §2.3.2).
func valueKey(key crypto.Decrypter, v *encryptedValue, size int) ([]byte, error) {
	var opts crypto.DecrypterOpts
	switch {
	case v.keyAlg == nil || (v.keyAlg.oid.Equal(oidRSAEncryption) && v.keyAlg.paramsAbsentOrNull()):
		//nolint:staticcheck // SA1019: CMP version 2 peers transport the key with PKCS #1 v1.5.
		opts = &rsa.PKCS1v15DecryptOptions{SessionKeyLen: size}
	case v.keyAlg.oid.Equal(oidRSAESOAEP):
		oaep, err := parseOAEPParams(v.keyAlg.params)
		if err != nil {
			return nil, err
		}
		opts = oaep
	default:
		return nil, fmt.Errorf("cms: unsupported EncryptedValue keyAlg %v", v.keyAlg.oid)
	}
	cek, err := key.Decrypt(rand.Reader, v.encSymmKey, opts)
	if err != nil || len(cek) != size {
		return nil, errDecrypt
	}
	return cek, nil
}

// DecryptEncryptedValue decrypts an EncryptedValue (RFC 4211 §2.1) with an RSA
// key, given as a [crypto.Decrypter] such as *rsa.PrivateKey.
//
// The content may be encrypted with AES-128, AES-192 or AES-256 in CBC mode or
// with Triple DES in CBC mode. The symmetric key may be transported with
// RSAES-PKCS1-v1_5 or RSAES-OAEP. An absent keyAlg means PKCS #1 v1.5. A PKCS #1
// v1.5 padding error is not reported apart from other decryption failures.
func DecryptEncryptedValue(der []byte, key any) ([]byte, error) {
	dec, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("cms: an EncryptedValue is decrypted with an RSA key, not %T", key)
	}
	if _, ok := dec.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("cms: an EncryptedValue is decrypted with an RSA key, not %T", dec.Public())
	}
	v, err := parseEncryptedValue(der)
	if err != nil {
		return nil, err
	}
	c, ok := valueCipherByOID(v.symmAlg.oid)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported EncryptedValue symmAlg %v", v.symmAlg.oid)
	}
	params := v.symmAlg.params
	var iv cryptobyte.String
	if !params.ReadASN1(&iv, cbasn1.OCTET_STRING) || !params.Empty() || len(iv) != c.blockSize {
		return nil, errors.New("cms: invalid symmAlg parameters")
	}
	cek, err := valueKey(dec, v, c.keySize)
	if err != nil {
		return nil, err
	}
	if len(v.encValue) == 0 || len(v.encValue)%c.blockSize != 0 {
		return nil, errDecrypt
	}
	block, err := c.newBlock(cek)
	if err != nil {
		return nil, errDecrypt
	}
	out := make([]byte, len(v.encValue))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, v.encValue)
	return unpad(out, c.blockSize)
}
