package pkicmp

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Credentials is the interface representing material used to protect a CMP message.
// The library provides [MACCredentials] and [SignatureCredentials], but custom
// implementations are possible for hardware tokens, testing, or non-standard schemes.
type Credentials interface {
	// Protect applies protection to the message.
	Protect(msg *PKIMessage) error
}

// MACCredentialOption is a functional option for [NewMACCredentials].
type MACCredentialOption func(*macCredentialConfig)

type macCredentialConfig struct {
	algorithm         asn1.ObjectIdentifier
	iterationCount    int
	minIterationCount int // zero selects DefaultMinMACIterationCount
	maxIterationCount int // zero selects DefaultMaxMACIterationCount
	keyLength         int
	owf               asn1.ObjectIdentifier // PBM OWF or PBMAC1 PRF
	mac               asn1.ObjectIdentifier
	owfParameters     []byte               // raw ASN.1 params for PBM OWF echo-back
	macParameters     []byte               // raw ASN.1 params for PBM MAC echo-back
	protectionAlg     *AlgorithmIdentifier // raw AlgID from WithProtectionAlgorithm
	err               error                // invalid option, reported by NewMACCredentials
}

// WithPBM configures PasswordBasedMac protection (RFC 4210 §5.1.3.1).
// By default, [MACCredentials] uses PBMAC1 (RFC 8018), which is the
// RECOMMENDED algorithm per RFC 9481 §7.
func WithPBM() MACCredentialOption {
	return func(c *macCredentialConfig) { c.algorithm = oidPasswordBasedMac }
}

// WithPBMAlgorithms configures PasswordBasedMac protection (RFC 4210 §5.1.3.1)
// with the given one-way function and HMAC hash.
//
// The default is SHA-256 with HMAC-SHA256. RFC 4210 Appendix D.2 makes SHA-1
// with HMAC-SHA1 the mandatory combination, so WithPBMAlgorithms(crypto.SHA1,
// crypto.SHA1) suits a peer that implements only RFC 4210. RFC 9481 §7.1
// deprecates SHA-1. The supported hashes are SHA-1, SHA-224, SHA-256, SHA-384
// and SHA-512. The MAC digest must not be longer than the OWF output.
// [NewMACCredentials] reports any other choice.
func WithPBMAlgorithms(owf, mac crypto.Hash) MACCredentialOption {
	return func(c *macCredentialConfig) {
		c.algorithm = oidPasswordBasedMac
		owfOID, macOID, err := pbmAlgorithmOIDs(owf, mac)
		if err != nil {
			c.err = err
			return
		}
		c.owf = owfOID
		c.mac = macOID
	}
}

// pbmAlgorithmOIDs maps a PasswordBasedMac OWF and HMAC hash to their algorithm identifiers.
func pbmAlgorithmOIDs(owf, mac crypto.Hash) (asn1.ObjectIdentifier, asn1.ObjectIdentifier, error) {
	owfOIDs := map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA1:   oidSHA1,
		crypto.SHA224: oidSHA224,
		crypto.SHA256: oidSHA256,
		crypto.SHA384: oidSHA384,
		crypto.SHA512: oidSHA512,
	}
	// HMAC-SHA1 uses the identifier RFC 4210 Appendix D.2 names, which is the
	// one an RFC 4210 peer recognizes.
	macOIDs := map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA1:   oidPBMMac_HMACSHA1,
		crypto.SHA224: oidHMACWithSHA224,
		crypto.SHA256: oidHMACWithSHA256,
		crypto.SHA384: oidHMACWithSHA384,
		crypto.SHA512: oidHMACWithSHA512,
	}
	owfOID, ok := owfOIDs[owf]
	if !ok {
		return nil, nil, &ProtectionError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("unsupported PasswordBasedMac OWF %v", owf),
		}
	}
	macOID, ok := macOIDs[mac]
	if !ok {
		return nil, nil, &ProtectionError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("unsupported PasswordBasedMac HMAC hash %v", mac),
		}
	}
	// The key is the OWF output. Deriving a longer one (RFC 4210 §5.1.3.1 key
	// expansion) is not implemented.
	if mac.Size() > owf.Size() {
		return nil, nil, &ProtectionError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("HMAC hash %v is longer than PasswordBasedMac OWF %v", mac, owf),
		}
	}
	return owfOID, macOID, nil
}

// WithMACIterationCount sets the PBKDF iteration count. The default is 10000.
// A count outside [DefaultMinMACIterationCount] and
// [DefaultMaxMACIterationCount] also needs [WithMACIterationLimits].
func WithMACIterationCount(n int) MACCredentialOption {
	return func(c *macCredentialConfig) { c.iterationCount = n }
}

// WithMACIterationLimits bounds the iteration count that Protect uses, whether
// it comes from [WithMACIterationCount] or is echoed through
// [WithProtectionAlgorithm]. The defaults are [DefaultMinMACIterationCount] and
// [DefaultMaxMACIterationCount]. Zero selects a default and a maximum below the
// minimum is raised to it.
//
// The bound matters most when echoing: the count then comes from a peer, so
// pass the limits the received message was verified against.
func WithMACIterationLimits(minimum, maximum int) MACCredentialOption {
	return func(c *macCredentialConfig) {
		c.minIterationCount = minimum
		c.maxIterationCount = maximum
	}
}

// WithProtectionAlgorithm echoes the protection parameters from a received
// message's [AlgorithmIdentifier]. The server uses this to protect responses
// with the same algorithm suite as the request (fresh salt is generated).
// RFC 9810 §5.1.3.
func WithProtectionAlgorithm(alg *AlgorithmIdentifier) MACCredentialOption {
	return func(c *macCredentialConfig) {
		if alg != nil {
			c.protectionAlg = alg
		}
	}
}

// MACCredentials holds a shared secret for Password-Based MAC protection.
// Create with [NewMACCredentials].
//
// Callers should set Header.SenderKID before calling Protect to identify the
// shared secret to the recipient (RFC 9810 §5.1.1).
type MACCredentials struct {
	secret []byte
	cfg    macCredentialConfig
}

// NewMACCredentials creates credentials for shared-secret MAC protection.
// Returns an error if the secret is empty.
// The secret is copied — the caller may safely mutate the original slice after this call.
// By default, PBMAC1 (RFC 8018) with HMAC-SHA-256 is used, which is the
// RECOMMENDED algorithm per RFC 9481 §7. Use [WithPBM] or [WithPBMAlgorithms]
// for PasswordBasedMac.
// Use [WithMACIterationCount] to override the iteration count.
// Use [WithProtectionAlgorithm] to echo protection parameters from a received message.
func NewMACCredentials(secret []byte, opts ...MACCredentialOption) (*MACCredentials, error) {
	if len(secret) == 0 {
		return nil, &ProtectionError{Reason: ReasonMissingSharedSecret}
	}
	s := make([]byte, len(secret))
	copy(s, secret)
	c := &MACCredentials{secret: s}
	for _, opt := range opts {
		opt(&c.cfg)
	}
	if c.cfg.err != nil {
		return nil, c.cfg.err
	}
	return c, nil
}

func (c *MACCredentials) Protect(msg *PKIMessage) error {
	if c.cfg.protectionAlg != nil {
		return msg.protectWithMACAlgorithm(c.secret, c.cfg.protectionAlg, c.cfg.minIterationCount, c.cfg.maxIterationCount)
	}
	alg := c.cfg.algorithm
	if alg == nil {
		alg = oidPBMAC1 // RFC 9481 §7: PBMAC1 is RECOMMENDED over PasswordBasedMac.
	}
	if alg.Equal(oidPBMAC1) {
		return msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:            c.secret,
			IterationCount:    c.cfg.iterationCount,
			KeyLength:         c.cfg.keyLength,
			PRF:               c.cfg.owf,
			MAC:               c.cfg.mac,
			MinIterationCount: c.cfg.minIterationCount,
			MaxIterationCount: c.cfg.maxIterationCount,
		})
	}
	return msg.protectWithMACOptions(macOptions{
		Secret:            c.secret,
		Algorithm:         alg,
		IterationCount:    c.cfg.iterationCount,
		OWF:               c.cfg.owf,
		MAC:               c.cfg.mac,
		OWFParameters:     c.cfg.owfParameters,
		MACParameters:     c.cfg.macParameters,
		MinIterationCount: c.cfg.minIterationCount,
		MaxIterationCount: c.cfg.maxIterationCount,
	})
}

// SharedSecret returns the shared secret held by this credentials object.
// This is used internally by the server to protect responses with the same secret.
func (c *MACCredentials) SharedSecret() []byte {
	return c.secret
}

// SignatureCredentials holds a signing key and certificate for signature-based
// protection. Create with [NewSignatureCredentials].
type SignatureCredentials struct {
	key   crypto.Signer
	cert  *x509.Certificate
	chain []*x509.Certificate // optional intermediate certificates
	// hash replaces the digest the key type selects. Zero keeps the default.
	hash crypto.Hash
}

// NewSignatureCredentials creates credentials for certificate-based signature
// protection. Returns an error if key is nil, cert is nil, or the key does not
// match the certificate's public key.
func NewSignatureCredentials(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) (*SignatureCredentials, error) {
	if key == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner}
	}
	if cert == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner, Err: fmt.Errorf("certificate is nil")}
	}
	// crypto/x509 leaves PublicKey nil for composite ML-DSA and SLH-DSA
	// certificates, so the key is read from the certificate's
	// SubjectPublicKeyInfo. Both keys are re-encoded before comparing.
	certPub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	pubDER, err1 := MarshalPublicKey(key.Public())
	certPubDER, err2 := MarshalPublicKey(certPub)
	if err != nil || err1 != nil || err2 != nil || subtle.ConstantTimeCompare(pubDER, certPubDER) != 1 {
		return nil, &ProtectionError{
			Reason: ReasonMissingSigner,
			Err:    fmt.Errorf("private key does not match certificate public key"),
		}
	}
	return &SignatureCredentials{key: key, cert: cert, chain: chain}, nil
}

// Certificate returns the signing certificate.
func (c *SignatureCredentials) Certificate() *x509.Certificate {
	return c.cert
}

// Key returns the signing key. A client uses it to decrypt a private key the
// CA generated for it and encrypted to the protection certificate.
func (c *SignatureCredentials) Key() crypto.Signer {
	return c.key
}

// WithHash returns credentials that sign with the digest hash instead of the
// one the key type selects. An RSA or ECDSA key takes SHA-1, SHA-256, SHA-384
// or SHA-512. Other key types take no digest and are refused with a
// [*ProtectionError]. RFC 9481 §7.1 deprecates SHA-1, so a peer accepts it
// only when configured to, as [VerifyOptions.AllowSHA1Signatures] does here.
func (c *SignatureCredentials) WithHash(hash crypto.Hash) (*SignatureCredentials, error) {
	if _, _, err := signatureAlgorithmForHash(c.key, hash); err != nil {
		return nil, &ProtectionError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	withHash := *c
	withHash.hash = hash
	return &withHash, nil
}

func (c *SignatureCredentials) Protect(msg *PKIMessage) error {
	return msg.protectWithSignature(c.key, c.hash, c.cert, c.chain...)
}
