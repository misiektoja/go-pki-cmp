package cms

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}
	oidAES192Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 25}
	oidAES256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// errNoRecipient is returned when no RecipientInfo matches the type of the decryption key.
var errNoRecipient = errors.New("cms: no recipient matches the key type")

// errDecrypt is returned for every failure after the key management step so that the cause is not revealed.
var errDecrypt = errors.New("cms: decryption failed")

// RecipientID identifies the recipient key in a RecipientInfo (RFC 5652 §6.2.1).
// Set either Issuer and SerialNumber or SubjectKeyID.
type RecipientID struct {
	// Issuer is the DER encoded issuer Name of the recipient certificate.
	Issuer []byte
	// SerialNumber is the serial number of the recipient certificate.
	SerialNumber *big.Int
	// SubjectKeyID is the subject key identifier of the recipient key.
	SubjectKeyID []byte
}

// IssuerAndSerial returns the issuerAndSerialNumber identifier of a certificate.
func IssuerAndSerial(cert *x509.Certificate) RecipientID {
	return RecipientID{Issuer: cert.RawIssuer, SerialNumber: cert.SerialNumber}
}

// validate checks that exactly one form of identifier is set and that the issuer is a DER SEQUENCE.
func (r RecipientID) validate() error {
	if r.SubjectKeyID != nil {
		if len(r.SubjectKeyID) == 0 || r.Issuer != nil || r.SerialNumber != nil {
			return errors.New("cms: recipient identifier needs either a subject key identifier or an issuer and serial number")
		}
		return nil
	}
	if r.SerialNumber == nil {
		return errors.New("cms: recipient identifier has no serial number")
	}
	s := cryptobyte.String(r.Issuer)
	var name cryptobyte.String
	if !s.ReadASN1(&name, cbasn1.SEQUENCE) || !s.Empty() {
		return errors.New("cms: recipient issuer is not a DER encoded Name")
	}
	return nil
}

// addRecipientIdentifier encodes RecipientIdentifier (RFC 5652 §6.2.1) as used by
// KeyTransRecipientInfo and KEMRecipientInfo.
func (r RecipientID) addRecipientIdentifier(b *cryptobyte.Builder) {
	if r.SubjectKeyID != nil {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(r.SubjectKeyID)
		})
		return
	}
	r.addIssuerAndSerial(b)
}

// addKeyAgreeRecipientIdentifier encodes KeyAgreeRecipientIdentifier (RFC 5652 §6.2.2).
func (r RecipientID) addKeyAgreeRecipientIdentifier(b *cryptobyte.Builder) {
	if r.SubjectKeyID != nil {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(r.SubjectKeyID)
		})
		return
	}
	r.addIssuerAndSerial(b)
}

// addIssuerAndSerial encodes IssuerAndSerialNumber (RFC 5652 §10.2.4).
func (r RecipientID) addIssuerAndSerial(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(r.Issuer)
		b.AddASN1BigInt(r.SerialNumber)
	})
}

// readRecipientIdentifier decodes RecipientIdentifier or KeyAgreeRecipientIdentifier from s.
func readRecipientIdentifier(s *cryptobyte.String) (RecipientID, error) {
	var rid RecipientID
	switch {
	case s.PeekASN1Tag(cbasn1.SEQUENCE):
		var seq, issuer cryptobyte.String
		serial := new(big.Int)
		if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
			!seq.ReadASN1Integer(serial) || !seq.Empty() {
			return rid, errors.New("cms: invalid issuerAndSerialNumber")
		}
		rid.Issuer, rid.SerialNumber = issuer, serial
	case s.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		var ski cryptobyte.String
		if !s.ReadASN1(&ski, cbasn1.Tag(0).ContextSpecific()) {
			return rid, errors.New("cms: invalid subjectKeyIdentifier")
		}
		rid.SubjectKeyID = ski
	case s.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()):
		// rKeyId [0] RecipientKeyIdentifier of a KeyAgreeRecipientIdentifier. The date and other fields are ignored.
		var seq, ski cryptobyte.String
		if !s.ReadASN1(&seq, cbasn1.Tag(0).ContextSpecific().Constructed()) || !seq.ReadASN1(&ski, cbasn1.OCTET_STRING) {
			return rid, errors.New("cms: invalid rKeyId")
		}
		rid.SubjectKeyID = ski
	default:
		return rid, errors.New("cms: unsupported recipient identifier")
	}
	return rid, nil
}

// algorithmIdentifier is a decoded AlgorithmIdentifier that keeps its DER encoding.
type algorithmIdentifier struct {
	oid asn1.ObjectIdentifier
	// params is the parameters element including its tag, or empty when absent.
	params cryptobyte.String
	// raw is the whole AlgorithmIdentifier element.
	raw []byte
}

// paramsAbsentOrNull reports whether the parameters are absent or an ASN.1 NULL.
func (a algorithmIdentifier) paramsAbsentOrNull() bool {
	return len(a.params) == 0 || bytes.Equal(a.params, []byte{0x05, 0x00})
}

// readAlgorithmIdentifier decodes an AlgorithmIdentifier from s.
func readAlgorithmIdentifier(s *cryptobyte.String) (algorithmIdentifier, error) {
	var a algorithmIdentifier
	var raw, seq cryptobyte.String
	if !s.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
		return a, errors.New("cms: invalid AlgorithmIdentifier")
	}
	elem := raw
	if !elem.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&a.oid) {
		return a, errors.New("cms: invalid AlgorithmIdentifier")
	}
	if !seq.Empty() {
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&a.params, &tag) || !seq.Empty() {
			return a, errors.New("cms: invalid AlgorithmIdentifier parameters")
		}
	}
	a.raw = raw
	return a, nil
}

// algorithm encodes an AlgorithmIdentifier with absent parameters.
func algorithm(oid asn1.ObjectIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
	})
	return b.BytesOrPanic()
}

// hashByOID maps a hash algorithm OID to the Go hash.
func hashByOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidSHA224):
		return crypto.SHA224, true
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

// wrapKeySize returns the key size in bytes of an AES key wrap algorithm.
func wrapKeySize(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128Wrap):
		return 16, true
	case oid.Equal(oidAES192Wrap):
		return 24, true
	case oid.Equal(oidAES256Wrap):
		return 32, true
	}
	return 0, false
}

// contentKeySize returns the key size in bytes of an AES-CBC content-encryption algorithm.
func contentKeySize(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, true
	case oid.Equal(oidAES192CBC):
		return 24, true
	case oid.Equal(oidAES256CBC):
		return 32, true
	}
	return 0, false
}

// Encrypt returns the DER encoding of an EnvelopedData that encrypts content for one recipient.
//
// The recipient key is an *rsa.PublicKey, an *ecdsa.PublicKey or *ecdh.PublicKey on
// P-256, P-384 or P-521 or an ML-KEM-768 or ML-KEM-1024 [crypto.Encapsulator] such
// as *mlkem.EncapsulationKey768. rid names the recipient key in the RecipientInfo.
// A [Password] or [PWRIKEKPassword] encrypts for a shared secret with a zero rid.
func Encrypt(content []byte, recipient crypto.PublicKey, rid RecipientID) ([]byte, error) {
	return encrypt(content, oidData, recipient, rid)
}

// EncryptSignedData is [Encrypt] for the DER encoding of a SignedData (RFC 5652
// §5), which the EnvelopedData labels id-signedData. RFC 9483 §4.1.6 sends a
// centrally generated private key this way.
func EncryptSignedData(signedData []byte, recipient crypto.PublicKey, rid RecipientID) ([]byte, error) {
	return encrypt(signedData, oidSignedData, recipient, rid)
}

// encrypt returns an EnvelopedData that encrypts content of type contentType for one recipient.
func encrypt(content []byte, contentType asn1.ObjectIdentifier, recipient crypto.PublicKey, rid RecipientID) ([]byte, error) {
	switch recipient.(type) {
	case Password, PWRIKEKPassword:
		if rid.Issuer != nil || rid.SerialNumber != nil || rid.SubjectKeyID != nil {
			return nil, errors.New("cms: a password recipient takes no recipient identifier")
		}
	default:
		if err := rid.validate(); err != nil {
			return nil, err
		}
	}
	cek := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	rand.Read(cek)
	rand.Read(iv)

	var ri []byte
	var err error
	version := int64(2)
	switch key := recipient.(type) {
	case Password, PWRIKEKPassword:
		// RFC 5652 §6.1 and RFC 9483 erratum 7833 set version 3 for a pwri.
		_, pwriKEK := key.(PWRIKEKPassword)
		ri, err = passwordRecipient(passwordBytes(key), pwriKEK, cek)
		version = 3
	case *rsa.PublicKey:
		ri, err = keyTransRecipient(key, rid, cek)
		if rid.SubjectKeyID == nil {
			version = 0
		}
	case *ecdsa.PublicKey:
		var pub *ecdh.PublicKey
		if pub, err = key.ECDH(); err == nil {
			ri, err = keyAgreeRecipient(pub, rid, cek)
		}
	case *ecdh.PublicKey:
		ri, err = keyAgreeRecipient(key, rid, cek)
	case crypto.Encapsulator:
		ri, err = kemRecipient(key, rid, cek)
		version = 3
	default:
		return nil, fmt.Errorf("cms: unsupported recipient key type %T", recipient)
	}
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(cek)
	padded := pad(content, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddBytes(ri)
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(contentType)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAES256CBC)
				b.AddASN1OctetString(iv)
			})
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(encrypted)
			})
		})
	})
	return b.Bytes()
}

// envelope is a decoded EnvelopedData with the parts Decrypt needs.
type envelope struct {
	recipients []cryptobyte.String
	contentAlg algorithmIdentifier
	encrypted  []byte
}

// parseEnvelope decodes a DER EnvelopedData (RFC 5652 §6.1).
func parseEnvelope(der []byte) (*envelope, error) {
	input := cryptobyte.String(der)
	var seq, set, eci cryptobyte.String
	var version int64
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !input.Empty() || !seq.ReadASN1Integer(&version) {
		return nil, errors.New("cms: invalid EnvelopedData")
	}
	if version < 0 || version > 4 {
		return nil, fmt.Errorf("cms: unsupported EnvelopedData version %d", version)
	}
	// originatorInfo [0] only carries certificates and CRLs, which decryption does not use.
	seq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed())
	if !seq.ReadASN1(&set, cbasn1.SET) || set.Empty() {
		return nil, errors.New("cms: invalid recipientInfos")
	}
	env := &envelope{}
	for !set.Empty() {
		var ri cryptobyte.String
		var tag cbasn1.Tag
		if !set.ReadAnyASN1Element(&ri, &tag) {
			return nil, errors.New("cms: invalid RecipientInfo")
		}
		env.recipients = append(env.recipients, ri)
	}
	var contentType asn1.ObjectIdentifier
	if !seq.ReadASN1(&eci, cbasn1.SEQUENCE) || !eci.ReadASN1ObjectIdentifier(&contentType) {
		return nil, errors.New("cms: invalid EncryptedContentInfo")
	}
	var err error
	if env.contentAlg, err = readAlgorithmIdentifier(&eci); err != nil {
		return nil, err
	}
	switch {
	case eci.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		var content cryptobyte.String
		eci.ReadASN1(&content, cbasn1.Tag(0).ContextSpecific())
		env.encrypted = content
	case eci.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()):
		// The constructed form splits the content into OCTET STRING segments.
		var segments cryptobyte.String
		eci.ReadASN1(&segments, cbasn1.Tag(0).ContextSpecific().Constructed())
		for !segments.Empty() {
			var segment cryptobyte.String
			if !segments.ReadASN1(&segment, cbasn1.OCTET_STRING) {
				return nil, errors.New("cms: invalid encryptedContent segment")
			}
			env.encrypted = append(env.encrypted, segment...)
		}
	default:
		return nil, errors.New("cms: EnvelopedData without encryptedContent is not supported")
	}
	if !eci.Empty() {
		return nil, errors.New("cms: invalid EncryptedContentInfo")
	}
	// unprotectedAttrs [1] carry nothing decryption needs.
	seq.SkipOptionalASN1(cbasn1.Tag(1).ContextSpecific().Constructed())
	if !seq.Empty() {
		return nil, errors.New("cms: trailing data in EnvelopedData")
	}
	return env, nil
}

// Decrypt returns the content of a DER EnvelopedData decrypted with the recipient's private key.
//
// The key is a [crypto.Decrypter] with an RSA public key, an *ecdsa.PrivateKey or
// [ecdh.KeyExchanger] on P-256, P-384 or P-521, or an ML-KEM-768 or ML-KEM-1024
// [crypto.Decapsulator] such as *mlkem.DecapsulationKey768. A [Password] or
// [PWRIKEKPassword] opens a PasswordRecipientInfo with either key wrap. Decrypt
// uses the first RecipientInfo whose type fits the key and does not compare its
// recipient identifier. It does not check the content type, because OpenSSL
// labels a SignedData id-data.
func Decrypt(der []byte, key any) ([]byte, error) {
	env, err := parseEnvelope(der)
	if err != nil {
		return nil, err
	}
	var open func(ri cryptobyte.String) ([]byte, bool, error)
	switch k := key.(type) {
	case Password, PWRIKEKPassword:
		password := passwordBytes(k)
		open = func(ri cryptobyte.String) ([]byte, bool, error) { return openPasswordRecipient(ri, password) }
	case crypto.Decapsulator:
		open = func(ri cryptobyte.String) ([]byte, bool, error) { return openKEMRecipient(ri, k) }
	case *ecdsa.PrivateKey:
		priv, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		open = func(ri cryptobyte.String) ([]byte, bool, error) { return openKeyAgreeRecipient(ri, priv) }
	case ecdh.KeyExchanger:
		open = func(ri cryptobyte.String) ([]byte, bool, error) { return openKeyAgreeRecipient(ri, k) }
	case crypto.Decrypter:
		if _, ok := k.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("cms: unsupported decryption key type %T", key)
		}
		open = func(ri cryptobyte.String) ([]byte, bool, error) { return openKeyTransRecipient(ri, k) }
	default:
		return nil, fmt.Errorf("cms: unsupported decryption key type %T", key)
	}
	for _, ri := range env.recipients {
		cek, matched, err := open(ri)
		if !matched {
			continue
		}
		if err != nil {
			return nil, err
		}
		return decryptContent(env, cek)
	}
	return nil, errNoRecipient
}

// decryptContent decrypts the AES-CBC encrypted content with the content-encryption key and removes the padding.
func decryptContent(env *envelope, cek []byte) ([]byte, error) {
	size, ok := contentKeySize(env.contentAlg.oid)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported content-encryption algorithm %v", env.contentAlg.oid)
	}
	params := env.contentAlg.params
	var iv cryptobyte.String
	if !params.ReadASN1(&iv, cbasn1.OCTET_STRING) || !params.Empty() || len(iv) != aes.BlockSize {
		return nil, errors.New("cms: invalid AES-CBC parameters")
	}
	if len(cek) != size || len(env.encrypted) == 0 || len(env.encrypted)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, errDecrypt
	}
	out := make([]byte, len(env.encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, env.encrypted)
	return unpad(out, aes.BlockSize)
}

// pad applies PKCS #7 padding (RFC 5652 §6.3).
func pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padding := byte(n) // #nosec G115 -- n is at most the 16-byte AES block size
	return append(bytes.Clone(data), bytes.Repeat([]byte{padding}, n)...)
}

// unpad checks and removes PKCS #7 padding.
func unpad(data []byte, blockSize int) ([]byte, error) {
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, errDecrypt
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errDecrypt
		}
	}
	return data[:len(data)-n], nil
}
