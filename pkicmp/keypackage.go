package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// OIDExtKeyUsageCMKGA is the id-kp-cmKGA extended key usage (RFC 9480 §2.2)
	// of a key generation authority that signs centrally generated keys.
	OIDExtKeyUsageCMKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}

	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAsymmetricKeyPackage = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 78, 5}
	oidAttributeContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidRSAEncryption        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// IsKeyGenerationAuthority reports whether cert may sign a centrally generated
// key: it asserts id-kp-cmKGA or it is a CA certificate (RFC 9480 §2.2).
// OpenSSL accepts only the extended key usage.
func IsKeyGenerationAuthority(cert *x509.Certificate) bool {
	if cert.BasicConstraintsValid && cert.IsCA {
		return true
	}
	return slices.ContainsFunc(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool {
		return oid.Equal(OIDExtKeyUsageCMKGA)
	})
}

// CentralKeyGenerationPublicKey returns the publicKey of a certificate template
// that asks the CA to generate a key pair of the given algorithm: the algorithm
// with a zero-length subjectPublicKey (RFC 9483 §4.1.6). A template without a
// publicKey leaves the algorithm to the CA.
func CentralKeyGenerationPublicKey(algorithm AlgorithmIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		algorithm.marshal(nil, b)
		b.AddASN1BitString(nil)
	})
	return b.BytesOrPanic()
}

// RequestsCentralKeyGeneration reports whether the template asks the CA to
// generate the key pair (RFC 9483 §4.1.6): it has no publicKey or one with a
// zero-length subjectPublicKey. algorithm is the key algorithm the latter
// prefers. It is nil for the former.
func (t *CertTemplate) RequestsCentralKeyGeneration() (algorithm *AlgorithmIdentifier, ok bool) {
	if len(t.PublicKey) == 0 {
		return nil, true
	}
	s := cryptobyte.String(t.PublicKey)
	var spki cryptobyte.String
	var bits asn1.BitString
	alg := &AlgorithmIdentifier{}
	if !s.ReadASN1(&spki, cbasn1.SEQUENCE) || !s.Empty() || alg.unmarshal(&spki) != nil ||
		!spki.ReadASN1BitString(&bits) || !spki.Empty() || bits.BitLength != 0 {
		return nil, false
	}
	return alg, true
}

// KeyPackage is the content of a signed key package: the SignedData around a
// centrally generated private key (RFC 9483 §4.1.6).
type KeyPackage struct {
	// PrivateKey is the DER OneAsymmetricKey (RFC 5958 §2) of an
	// AsymmetricKeyPackage. For id-data content it is the content as is, which
	// OpenSSL encodes as PKCS #1, SEC 1 or PKCS #8.
	PrivateKey []byte
	// Content is the form of the package content.
	Content KeyPackageContent
	// Signer is the certificate whose key signed the package. [ParseKeyPackage]
	// checks the signature, not whether the certificate is trusted or authorized.
	Signer *x509.Certificate
	// Certificates holds every certificate of the SignedData, in its order.
	Certificates []*x509.Certificate
}

// KeyPackageContent selects how [NewKeyPackage] encapsulates the private key.
type KeyPackageContent int

const (
	// KeyPackageData signs the OneAsymmetricKey itself as id-data content. This
	// is the form OpenSSL writes and the only one it reads.
	KeyPackageData KeyPackageContent = iota
	// KeyPackageAsymmetricKeyPackage signs an AsymmetricKeyPackage (RFC 5958)
	// that holds the OneAsymmetricKey, with the id-ct-KP-aKeyPackage content
	// type that RFC 9810 §5.2.2 and RFC 9483 §4.1.6 specify.
	KeyPackageAsymmetricKeyPackage
)

// KeyPackageOptions changes how [ParseKeyPackage] checks a key package.
type KeyPackageOptions struct {
	// AllowSHA1Signatures accepts a signature with SHA-1, which RFC 9481 §7.1 deprecates.
	AllowSHA1Signatures bool
}

// NewKeyPackage returns the DER SignedData (RFC 5652 §5) that carries the DER
// OneAsymmetricKey privateKey in the given content form, signed by key, the
// key of the key generation authority certificate cert, as RFC 9483 §4.1.6
// describes. The SignedData carries cert and chain and names the signer by
// its subjectKeyIdentifier. A cert without one is named by issuer and serial
// number.
// The signed attributes are the content type and the message digest.
//
// RSA and ECDSA signatures use the digest their key size selects. Other
// algorithms sign the attributes themselves and name SHA-512 as the digest,
// as RFC 8419 §3 requires for Ed25519.
func NewKeyPackage(privateKey []byte, form KeyPackageContent, key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) ([]byte, error) {
	if key == nil || cert == nil {
		return nil, errors.New("pkicmp: a key package needs a signing key and its certificate")
	}
	sigOID, hash, err := signatureAlgorithmFromKey(key)
	if err != nil {
		return nil, err
	}
	digestHash := hash
	if digestHash == 0 {
		digestHash = crypto.SHA512
	}
	var contentType asn1.ObjectIdentifier
	var content []byte
	switch form {
	case KeyPackageData:
		contentType, content = oidData, privateKey
	case KeyPackageAsymmetricKeyPackage:
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(privateKey)
		})
		if content, err = b.Bytes(); err != nil {
			return nil, err
		}
		contentType = oidAsymmetricKeyPackage
	default:
		return nil, fmt.Errorf("pkicmp: unknown key package content %d", form)
	}
	h := digestHash.New()
	h.Write(content)
	attrs := signedAttributes(contentType, h.Sum(nil))
	// The signature covers the attributes with their EXPLICIT SET tag (RFC 5652 §5.4).
	var set cryptobyte.Builder
	set.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
	signed := set.BytesOrPanic()
	var opts crypto.SignerOpts = crypto.Hash(0)
	if hash != 0 {
		h := hash.New()
		h.Write(signed)
		signed, opts = h.Sum(nil), hash
	}
	signature, err := key.Sign(rand.Reader, signed, opts)
	if err != nil {
		return nil, err
	}

	digestAlg := AlgorithmIdentifier{Algorithm: hashOID(digestHash)}
	// SignerInfo version 3 names the signer by subjectKeyIdentifier, version 1
	// by issuer and serial number (RFC 5652 §5.3).
	version := int64(3)
	if len(cert.SubjectKeyId) == 0 {
		version = 1
	}
	// SignedData is version 3 when its content is not id-data or its SignerInfo
	// is version 3. It is version 1 otherwise (RFC 5652 §5.1).
	sdVersion := int64(1)
	if version == 3 || form != KeyPackageData {
		sdVersion = 3
	}
	var sd cryptobyte.Builder
	sd.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(sdVersion)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { digestAlg.marshal(nil, b) })
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(contentType)
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(content)
			})
		})
		// RFC 9483 §4.1.6 puts the KGA certificate first, so the SET keeps this order.
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddBytes(cert.Raw)
			for _, c := range chain {
				b.AddBytes(c.Raw)
			}
		})
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(version)
				if version == 3 {
					b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(cert.SubjectKeyId) })
				} else {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(cert.RawIssuer)
						b.AddASN1BigInt(cert.SerialNumber)
					})
				}
				digestAlg.marshal(nil, b)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(sigOID) })
				b.AddASN1OctetString(signature)
			})
		})
	})
	return sd.Bytes()
}

// signedAttributes returns the DER content-type and message-digest attributes
// in the order DER sets for a SET OF, without the SET header.
func signedAttributes(contentType asn1.ObjectIdentifier, digest []byte) []byte {
	attribute := func(oid asn1.ObjectIdentifier, value func(*cryptobyte.Builder)) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			b.AddASN1(cbasn1.SET, value)
		})
		return b.BytesOrPanic()
	}
	elements := [][]byte{
		attribute(oidAttributeContentType, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(contentType) }),
		attribute(oidAttributeDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(digest) }),
	}
	slices.SortFunc(elements, bytes.Compare)
	return bytes.Join(elements, nil)
}

// signerInfo is the part of a SignerInfo (RFC 5652 §5.3) that verification needs.
type signerInfo struct {
	issuer       []byte
	serial       *big.Int
	subjectKeyID []byte
	digest       AlgorithmIdentifier
	// attrs is the signedAttrs content, nil when the SignerInfo has none.
	attrs     cryptobyte.String
	hasAttrs  bool
	signature AlgorithmIdentifier
	value     []byte
}

// ParseKeyPackage parses the DER SignedData of a centrally generated private
// key and checks its signature with the signer certificate it carries.
//
// It accepts the AsymmetricKeyPackage content RFC 9483 §4.1.6 requires with
// exactly one key. It also accepts the id-data content of [KeyPackageData]. The
// signer is named
// by subjectKeyIdentifier or by issuer and serial number. Signed attributes,
// when present, must carry the content type and the digest of the content.
func ParseKeyPackage(der []byte, opts KeyPackageOptions) (*KeyPackage, error) {
	s := cryptobyte.String(der)
	var sd, digestAlgs, eci, certs, infos cryptobyte.String
	var version int64
	var contentType asn1.ObjectIdentifier
	if !s.ReadASN1(&sd, cbasn1.SEQUENCE) || !s.Empty() || !sd.ReadASN1Integer(&version) ||
		!sd.ReadASN1(&digestAlgs, cbasn1.SET) || !sd.ReadASN1(&eci, cbasn1.SEQUENCE) ||
		!eci.ReadASN1ObjectIdentifier(&contentType) {
		return nil, &ParseError{Detail: "invalid SignedData"}
	}
	if version < 1 || version > 5 {
		return nil, &ParseError{Detail: fmt.Sprintf("unsupported SignedData version %d", version)}
	}
	content, err := readEncapsulatedContent(&eci)
	if err != nil {
		return nil, err
	}

	pkg := &KeyPackage{}
	if sd.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		sd.ReadASN1(&certs, cbasn1.Tag(0).ContextSpecific().Constructed())
		for !certs.Empty() {
			var raw cryptobyte.String
			if !certs.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
				return nil, &ParseError{Detail: "unsupported certificate choice in SignedData"}
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, &ParseError{Detail: "invalid certificate in SignedData: " + err.Error()}
			}
			pkg.Certificates = append(pkg.Certificates, cert)
		}
	}
	// crls [1] are not needed to check the signature.
	sd.SkipOptionalASN1(cbasn1.Tag(1).ContextSpecific().Constructed())
	if !sd.ReadASN1(&infos, cbasn1.SET) || !sd.Empty() {
		return nil, &ParseError{Detail: "invalid SignedData signerInfos"}
	}
	var info cryptobyte.String
	if !infos.ReadASN1(&info, cbasn1.SEQUENCE) || !infos.Empty() {
		return nil, &ParseError{Detail: "a key package must have exactly one SignerInfo"}
	}
	si, err := parseSignerInfo(info)
	if err != nil {
		return nil, err
	}
	if pkg.Signer = findSigner(pkg.Certificates, si); pkg.Signer == nil {
		return nil, &ParseError{Detail: "the SignedData does not carry the signer certificate"}
	}
	if err := si.verify(pkg.Signer, contentType, content, opts); err != nil {
		return nil, err
	}

	switch {
	case contentType.Equal(oidAsymmetricKeyPackage):
		keys := cryptobyte.String(content)
		var seq, key cryptobyte.String
		if !keys.ReadASN1(&seq, cbasn1.SEQUENCE) || !keys.Empty() || !seq.ReadASN1Element(&key, cbasn1.SEQUENCE) {
			return nil, &ParseError{Detail: "invalid AsymmetricKeyPackage"}
		}
		if !seq.Empty() {
			return nil, &ParseError{Detail: "a key package must carry exactly one key"}
		}
		pkg.PrivateKey, pkg.Content = key, KeyPackageAsymmetricKeyPackage
	case contentType.Equal(oidData):
		pkg.PrivateKey, pkg.Content = content, KeyPackageData
	default:
		return nil, &ParseError{Detail: fmt.Sprintf("unsupported key package content type %v", contentType)}
	}
	return pkg, nil
}

// readEncapsulatedContent returns the eContent [0] EXPLICIT OCTET STRING of an
// EncapsulatedContentInfo, joining the segments of a constructed OCTET STRING.
func readEncapsulatedContent(eci *cryptobyte.String) ([]byte, error) {
	var explicit cryptobyte.String
	if !eci.ReadASN1(&explicit, cbasn1.Tag(0).ContextSpecific().Constructed()) || !eci.Empty() {
		return nil, &ParseError{Detail: "a key package must carry its content"}
	}
	var content cryptobyte.String
	if explicit.ReadASN1(&content, cbasn1.OCTET_STRING) && explicit.Empty() {
		return content, nil
	}
	var segments cryptobyte.String
	if !explicit.ReadASN1(&segments, cbasn1.OCTET_STRING.Constructed()) || !explicit.Empty() {
		return nil, &ParseError{Detail: "invalid SignedData eContent"}
	}
	var joined []byte
	for !segments.Empty() {
		var segment cryptobyte.String
		if !segments.ReadASN1(&segment, cbasn1.OCTET_STRING) {
			return nil, &ParseError{Detail: "invalid SignedData eContent segment"}
		}
		joined = append(joined, segment...)
	}
	return joined, nil
}

// parseSignerInfo decodes a SignerInfo (RFC 5652 §5.3).
func parseSignerInfo(info cryptobyte.String) (*signerInfo, error) {
	si := &signerInfo{}
	var version int64
	if !info.ReadASN1Integer(&version) {
		return nil, &ParseError{Detail: "invalid SignerInfo"}
	}
	switch {
	case info.PeekASN1Tag(cbasn1.SEQUENCE):
		var seq, issuer cryptobyte.String
		si.serial = new(big.Int)
		if !info.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
			!seq.ReadASN1Integer(si.serial) || !seq.Empty() {
			return nil, &ParseError{Detail: "invalid SignerInfo issuerAndSerialNumber"}
		}
		si.issuer = issuer
	case info.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		var ski cryptobyte.String
		info.ReadASN1(&ski, cbasn1.Tag(0).ContextSpecific())
		si.subjectKeyID = ski
	default:
		return nil, &ParseError{Detail: "invalid SignerInfo sid"}
	}
	if err := si.digest.unmarshal(&info); err != nil {
		return nil, err
	}
	if info.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		info.ReadASN1(&si.attrs, cbasn1.Tag(0).ContextSpecific().Constructed())
		si.hasAttrs = true
	}
	var value cryptobyte.String
	if err := si.signature.unmarshal(&info); err != nil {
		return nil, err
	}
	if !info.ReadASN1(&value, cbasn1.OCTET_STRING) {
		return nil, &ParseError{Detail: "invalid SignerInfo signature"}
	}
	// unsignedAttrs [1] carry nothing the check needs.
	info.SkipOptionalASN1(cbasn1.Tag(1).ContextSpecific().Constructed())
	if !info.Empty() {
		return nil, &ParseError{Detail: "trailing data in SignerInfo"}
	}
	si.value = value
	return si, nil
}

// findSigner returns the certificate among certs that the SignerInfo names.
func findSigner(certs []*x509.Certificate, si *signerInfo) *x509.Certificate {
	for _, cert := range certs {
		if si.subjectKeyID != nil {
			if len(cert.SubjectKeyId) > 0 && subtle.ConstantTimeCompare(cert.SubjectKeyId, si.subjectKeyID) == 1 {
				return cert
			}
			continue
		}
		if bytes.Equal(cert.RawIssuer, si.issuer) && cert.SerialNumber.Cmp(si.serial) == 0 {
			return cert
		}
	}
	return nil
}

// verify checks the signed attributes against content and the signature with the key of signer.
func (si *signerInfo) verify(signer *x509.Certificate, contentType asn1.ObjectIdentifier, content []byte, opts KeyPackageOptions) error {
	digestHash, err := hashFromOID(si.digest.Algorithm)
	if err != nil {
		return err
	}
	if digestHash == crypto.SHA1 && !opts.AllowSHA1Signatures {
		return &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    errors.New("SHA-1 key package digest is not enabled"),
		}
	}
	signed := content
	if si.hasAttrs {
		if err := checkSignedAttributes(si.attrs, contentType, digestHash, content); err != nil {
			return err
		}
		// The signature covers the attributes with their EXPLICIT SET tag (RFC 5652 §5.4).
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(si.attrs) })
		signed = b.BytesOrPanic()
	}
	alg := si.signature
	// RFC 3370 §3.2 lets a SignerInfo name rsaEncryption and take the hash from digestAlgorithm.
	if alg.Algorithm.Equal(oidRSAEncryption) {
		rsaAlgs := map[crypto.Hash]asn1.ObjectIdentifier{
			crypto.SHA1:   oidSHA1WithRSAEncryption,
			crypto.SHA256: oidSHA256WithRSAEncryption,
			crypto.SHA384: oidSHA384WithRSAEncryption,
			crypto.SHA512: oidSHA512WithRSAEncryption,
		}
		oid, ok := rsaAlgs[digestHash]
		if !ok {
			return &VerificationError{
				Reason: ReasonUnsupportedAlgorithm,
				Err:    fmt.Errorf("unsupported RSA digest %v", digestHash),
			}
		}
		alg = AlgorithmIdentifier{Algorithm: oid}
	}
	check, err := signatureChecker(alg, opts.AllowSHA1Signatures)
	if err != nil {
		return err
	}
	if err := check(signer, signed, si.value); err != nil {
		return &VerificationError{Reason: ReasonSignatureFailed, Err: fmt.Errorf("key package signature: %w", err)}
	}
	return nil
}

// checkSignedAttributes checks that attrs carry the content type and the digest of content (RFC 5652 §5.3, §11).
func checkSignedAttributes(attrs cryptobyte.String, contentType asn1.ObjectIdentifier, hash crypto.Hash, content []byte) error {
	var gotType asn1.ObjectIdentifier
	var gotDigest []byte
	for !attrs.Empty() {
		var attr, values cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) ||
			!attr.ReadASN1(&values, cbasn1.SET) || !attr.Empty() {
			return &ParseError{Detail: "invalid signed attribute"}
		}
		switch {
		case oid.Equal(oidAttributeContentType):
			if gotType != nil || !values.ReadASN1ObjectIdentifier(&gotType) || !values.Empty() {
				return &ParseError{Detail: "invalid content-type attribute"}
			}
		case oid.Equal(oidAttributeDigest):
			var digest cryptobyte.String
			if gotDigest != nil || !values.ReadASN1(&digest, cbasn1.OCTET_STRING) || !values.Empty() {
				return &ParseError{Detail: "invalid message-digest attribute"}
			}
			gotDigest = digest
		}
	}
	if !gotType.Equal(contentType) {
		return &VerificationError{
			Reason: ReasonSignatureFailed,
			Err:    errors.New("content-type attribute does not match the content"),
		}
	}
	h := hash.New()
	h.Write(content)
	if gotDigest == nil || subtle.ConstantTimeCompare(gotDigest, h.Sum(nil)) != 1 {
		return &VerificationError{
			Reason: ReasonSignatureFailed,
			Err:    errors.New("message-digest attribute does not match the content"),
		}
	}
	return nil
}

// SetEncryptedPrivateKey sets the privateKey of the key pair to the DER
// EnvelopedData of a centrally generated key (RFC 9483 §4.1.6). The message
// then needs CMP version 3, which marshaling selects.
func (ckp *CertifiedKeyPair) SetEncryptedPrivateKey(envelope []byte) {
	ckp.PrivateKey = &encryptedKey{envelopedData: &envelopedData{Raw: envelope}}
}

// EncryptedPrivateKey returns the DER EnvelopedData of the privateKey. It
// returns nil when the key pair has none or carries it as the deprecated
// EncryptedValue.
func (ckp *CertifiedKeyPair) EncryptedPrivateKey() []byte {
	if ckp.PrivateKey == nil || ckp.PrivateKey.envelopedData == nil {
		return nil
	}
	return ckp.PrivateKey.envelopedData.Raw
}
