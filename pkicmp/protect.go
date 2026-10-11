package pkicmp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pbkdf2"
)

// macOptions configures Password-Based MAC protection when defaults are not suitable.
type macOptions struct {
	Secret         []byte
	Algorithm      asn1.ObjectIdentifier // default: oidPasswordBasedMac
	IterationCount int                   // default: 10000
	KeyLength      int                   // PBMAC1: derived key length (default: MAC hash size)
	OWF            asn1.ObjectIdentifier // default: SHA-256
	MAC            asn1.ObjectIdentifier // default: HMAC-SHA-256
	// OWFParameters and MACParameters hold the raw ASN.1 parameter bytes
	// from the AlgorithmIdentifier (e.g., NULL 05 00). When set, these are
	// echoed back verbatim to preserve the original encoding.
	OWFParameters []byte
	MACParameters []byte
	// MinIterationCount and MaxIterationCount bound IterationCount. Zero
	// selects the package default, as in [VerifyOptions].
	MinIterationCount int
	MaxIterationCount int
}

// protectWithMAC protects the message using Password-Based MAC with default
// parameters (SHA-256 OWF, HMAC-SHA-256, 10000 iterations, random 16-byte salt).
// RFC 9810 §5.1.3.1, RFC 9481 §7.1 (mandatory algorithm profile).
//
// Note: The caller is responsible for setting Header.SenderKID when the sender
// field is a NULL-DN (RFC 9810 §5.1.1 MUST requirement for MAC-protected messages
// with unknown sender identity).
func (m *PKIMessage) protectWithMAC(secret []byte) error {
	return m.protectWithMACOptions(macOptions{Secret: secret, Algorithm: oidPasswordBasedMac})
}

// protectWithMACOptions protects the message using Password-Based MAC with
// explicit parameters. Use protectWithMAC for the common case.
// RFC 9810 §5.1.3.1.
func (m *PKIMessage) protectWithMACOptions(opts macOptions) error {
	if m.Body == nil {
		return &ParseError{Detail: detailMissingMessageBody}
	}
	if len(opts.Secret) == 0 {
		return &ProtectionError{Reason: ReasonMissingSharedSecret}
	}
	if opts.Algorithm == nil {
		return &ParseError{Detail: "macOptions.Algorithm is required"}
	}

	// Apply defaults.
	alg := opts.Algorithm
	iterCount := opts.IterationCount
	if iterCount == 0 {
		iterCount = defaultPBMIterationCount
	}
	owf := opts.OWF
	if owf == nil {
		owf = defaultPBMOWF
	}
	mac := opts.MAC
	if mac == nil {
		mac = defaultPBMMAC
	}

	if err := validatePBMIterationCount(iterCount, opts.MinIterationCount, opts.MaxIterationCount); err != nil {
		return err
	}
	if _, err := hashFromOID(owf); err != nil {
		return err
	}
	if _, err := hmacHashFromOID(mac); err != nil {
		return err
	}

	// Generate random salt.
	salt := make([]byte, defaultPBMSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Build pbmParameter and serialize.
	p := pbmParameter{
		Salt:           salt,
		IterationCount: iterCount,
		OWF:            AlgorithmIdentifier{Algorithm: owf, Parameters: opts.OWFParameters},
		MAC:            AlgorithmIdentifier{Algorithm: mac, Parameters: opts.MACParameters},
	}
	var pb cryptobyte.Builder
	p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &pb)
	params, err := pb.Bytes()
	if err != nil {
		return err
	}

	m.Header.ProtectionAlg = &AlgorithmIdentifier{
		Algorithm:  alg,
		Parameters: params,
	}

	// Marshal header+body and compute MAC.
	if err := m.marshalForProtection(); err != nil {
		return err
	}
	data, err := m.protectedPart()
	if err != nil {
		return err
	}

	hash, _ := hashFromOID(owf)
	macHash, _ := hmacHashFromOID(mac)
	k, err := derivePBMKey(opts.Secret, salt, iterCount, hash, macHash)
	if err != nil {
		return err
	}
	h := hmac.New(macHash.New, k)
	h.Write(data)
	m.Protection = h.Sum(nil)
	return nil
}

// protectWithMACAlgorithm protects the message by echoing the algorithm
// parameters from a received message (with a fresh salt). Used by servers
// to match the request's protection suite. The echoed iteration count must lie
// within minIterations and maxIterations, where zero selects the default.
// RFC 9810 §5.1.3.
func (m *PKIMessage) protectWithMACAlgorithm(secret []byte, alg *AlgorithmIdentifier, minIterations, maxIterations int) error {
	if alg.Algorithm.Equal(oidPBMAC1) {
		var params struct {
			KeyDerivationFunc algorithmIdentifierASN1
			MessageAuthScheme algorithmIdentifierASN1
		}
		if _, err := asn1.Unmarshal(alg.Parameters, &params); err != nil {
			return &ParseError{Detail: "invalid PBMAC1-params: " + err.Error()}
		}
		if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
			return &ParseError{Detail: fmt.Sprintf("unsupported KDF: %v", params.KeyDerivationFunc.Algorithm)}
		}
		kdfParams, err := parsePBKDF2Params(params.KeyDerivationFunc.Parameters.FullBytes)
		if err != nil {
			return err
		}
		return m.protectWithPBMAC1Options(pbmac1Options{
			Secret:            secret,
			IterationCount:    kdfParams.IterationCount,
			KeyLength:         kdfParams.KeyLength,
			PRF:               kdfParams.PRF.Algorithm,
			MAC:               params.MessageAuthScheme.Algorithm,
			MinIterationCount: minIterations,
			MaxIterationCount: maxIterations,
		})
	}
	if alg.Algorithm.Equal(oidPasswordBasedMac) {
		var p pbmParameter
		params := cryptobyte.String(alg.Parameters)
		if err := p.unmarshal(&params); err != nil {
			return err
		}
		return m.protectWithMACOptions(macOptions{
			Secret:            secret,
			Algorithm:         alg.Algorithm,
			IterationCount:    p.IterationCount,
			OWF:               p.OWF.Algorithm,
			MAC:               p.MAC.Algorithm,
			OWFParameters:     p.OWF.Parameters,
			MACParameters:     p.MAC.Parameters,
			MinIterationCount: minIterations,
			MaxIterationCount: maxIterations,
		})
	}
	return &ParseError{Detail: fmt.Sprintf("unsupported MAC algorithm: %v", alg.Algorithm)}
}

// pbmac1Options configures PBMAC1 protection (RFC 8018 §7.1, RFC 9481 §6.1.2).
type pbmac1Options struct {
	Secret         []byte
	IterationCount int                   // default: 10000
	KeyLength      int                   // default: MAC hash size
	PRF            asn1.ObjectIdentifier // default: oidHMACWithSHA256 (for PBKDF2)
	MAC            asn1.ObjectIdentifier // default: oidHMACWithSHA256 (messageAuthScheme)
	// MinIterationCount and MaxIterationCount bound IterationCount. Zero
	// selects the package default, as in [VerifyOptions].
	MinIterationCount int
	MaxIterationCount int
}

// protectWithPBMAC1Options protects the message using PBMAC1 with explicit parameters.
// RFC 8018 §7.1, RFC 9481 §6.1.2.
func (m *PKIMessage) protectWithPBMAC1Options(opts pbmac1Options) error {
	if m.Body == nil {
		return &ParseError{Detail: detailMissingMessageBody}
	}
	if len(opts.Secret) == 0 {
		return &ProtectionError{Reason: ReasonMissingSharedSecret}
	}

	iterCount := opts.IterationCount
	if iterCount == 0 {
		iterCount = defaultPBMIterationCount
	}
	prf := opts.PRF
	if prf == nil {
		prf = oidHMACWithSHA256
	}
	mac := opts.MAC
	if mac == nil {
		mac = oidHMACWithSHA256
	}

	if err := validatePBMIterationCount(iterCount, opts.MinIterationCount, opts.MaxIterationCount); err != nil {
		return err
	}
	macHash, err := hmacHashFromOID(mac)
	if err != nil {
		return err
	}
	prfHash, err := hmacHashFromOID(prf)
	if err != nil {
		return err
	}

	// RFC 8018 §A.5: keyLength is OPTIONAL, and §7.1 ties it to the MAC scheme.
	// An echoed value reaches this point straight from a peer's message, so it is
	// bounded here as well as on the verification path.
	keyLen := opts.KeyLength
	if keyLen == 0 {
		keyLen = macHash.Size()
	}
	if err := validatePBKDF2KeyLength(keyLen, macHash); err != nil {
		return err
	}

	// Generate random salt (RFC 8018 §7.1).
	salt := make([]byte, defaultPBMSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Build PBMAC1-params ASN.1 structure (RFC 8018 §A.5).
	params, err := marshalPBMAC1Params(salt, iterCount, keyLen, prf, mac)
	if err != nil {
		return err
	}

	m.Header.ProtectionAlg = &AlgorithmIdentifier{
		Algorithm:  oidPBMAC1,
		Parameters: params,
	}

	if err := m.marshalForProtection(); err != nil {
		return err
	}
	data, err := m.protectedPart()
	if err != nil {
		return err
	}

	// Derive key using PBKDF2 (RFC 8018 §5.2).
	k := pbkdf2.Key(opts.Secret, salt, iterCount, keyLen, prfHash.New)
	h := hmac.New(macHash.New, k)
	h.Write(data)
	m.Protection = h.Sum(nil)
	return nil
}

// marshalPBMAC1Params builds the PBMAC1-params ASN.1 structure.
// RFC 8018 §A.5.
func marshalPBMAC1Params(salt []byte, iterCount, keyLen int, prf, mac asn1.ObjectIdentifier) ([]byte, error) {
	// PBKDF2-params: SEQUENCE { salt, iterationCount, keyLength, prf }.
	// Encoding through the same struct the parser uses keeps the two symmetric.
	params := pbkdf2ParamsASN1{
		Salt:           salt,
		IterationCount: iterCount,
		KeyLength:      keyLen,
	}
	// RFC 8018 §A.2 gives prf the default algid-hmacWithSHA1, and X.690 §11.5
	// forbids encoding a component that holds its default value. Leaving the
	// field zero makes encoding/asn1 omit it, which is what a peer that sent no
	// prf gets back when its parameters are echoed.
	if !prf.Equal(oidHMACWithSHA1) {
		params.PRF = algorithmIdentifierASN1{Algorithm: prf}
	}
	pbkdf2Params, err := asn1.Marshal(params)
	if err != nil {
		return nil, err
	}

	// PBMAC1-params: SEQUENCE { keyDerivationFunc, messageAuthScheme }
	return asn1.Marshal(struct {
		KeyDerivationFunc algorithmIdentifierASN1
		MessageAuthScheme algorithmIdentifierASN1
	}{
		KeyDerivationFunc: algorithmIdentifierASN1{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: pbkdf2Params}},
		MessageAuthScheme: algorithmIdentifierASN1{Algorithm: mac},
	})
}

// algorithmIdentifierASN1 is used for encoding/asn1 marshaling of AlgorithmIdentifier.
type algorithmIdentifierASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// pbkdf2ParamsASN1 mirrors PBKDF2-params (RFC 8018 §A.5). keyLength is OPTIONAL
// and prf carries a DEFAULT, so DER omits both when they are not needed.
type pbkdf2ParamsASN1 struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                     `asn1:"optional"`
	PRF            algorithmIdentifierASN1 `asn1:"optional"`
}

// parsePBKDF2Params decodes PBKDF2-params and applies the RFC 8018 §A.5 default for an absent prf.
func parsePBKDF2Params(der []byte) (*pbkdf2ParamsASN1, error) {
	var p pbkdf2ParamsASN1
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, &ParseError{Detail: "invalid PBKDF2-params: " + err.Error()}
	}
	// prf DEFAULT algid-hmacWithSHA1: DER requires the field to be omitted when it
	// holds the default, so an absent prf means HMAC-SHA-1 rather than "unspecified".
	if len(p.PRF.Algorithm) == 0 {
		p.PRF.Algorithm = oidHMACWithSHA1
	}
	return &p, nil
}

// protectWithSignature signs the message using the given key.
// The signature algorithm is inferred from the key type.
// cert is added to ExtraCerts and its SubjectKeyId is set as Header.SenderKID.
// chain provides optional intermediate certificates to include in ExtraCerts.
// RFC 9810 §5.1.3.3.
func (m *PKIMessage) protectWithSignature(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) error {
	if m.Body == nil {
		return &ParseError{Detail: detailMissingMessageBody}
	}

	sigAlgOID, hash, err := signatureAlgorithmFromKey(key)
	if err != nil {
		return &ProtectionError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}

	m.Header.ProtectionAlg = &AlgorithmIdentifier{Algorithm: sigAlgOID}

	// RFC 9810 §5.1.1: senderKID SHOULD be used.
	if len(cert.SubjectKeyId) > 0 {
		m.Header.SenderKID = cert.SubjectKeyId
	}

	// RFC 9483 §3.3 requires the CMP protection certificate to be the first
	// element of extraCerts, followed by its chain, so anything the caller
	// already placed there moves behind them.
	ordered := make([]CMPCertificate, 0, len(m.ExtraCerts)+len(chain)+1)
	ordered = append(ordered, CMPCertificate{Raw: cert.Raw})
	for _, c := range chain {
		ordered = append(ordered, CMPCertificate{Raw: c.Raw})
	}
	ordered = append(ordered, m.ExtraCerts...)
	m.ExtraCerts = dedupeCertificates(ordered)

	// Marshal header+body and compute signature.
	if err := m.marshalForProtection(); err != nil {
		return err
	}
	data, err := m.protectedPart()
	if err != nil {
		return err
	}

	var opts crypto.SignerOpts
	var digest []byte
	if hash != 0 {
		h := hash.New()
		h.Write(data)
		digest = h.Sum(nil)
		opts = hash
	} else {
		// e.g. Ed25519
		digest = data
		opts = crypto.Hash(0)
	}

	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return err
	}
	m.Protection = sig
	return nil
}

// dedupeCertificates keeps the first occurrence of each certificate and drops later repeats.
func dedupeCertificates(certs []CMPCertificate) []CMPCertificate {
	seen := make(map[string]struct{}, len(certs))
	out := make([]CMPCertificate, 0, len(certs))
	for _, c := range certs {
		if _, dup := seen[string(c.Raw)]; dup {
			continue
		}
		seen[string(c.Raw)] = struct{}{}
		out = append(out, c)
	}
	return out
}

// marshalForProtection encodes the body before the header so the body can
// raise the protocol version required by the header.
func (m *PKIMessage) marshalForProtection() error {
	mctx := &marshalContext{MinRequiredPVNO: PVNO2}
	if m.Header.PVNO > PVNO2 {
		mctx.MinRequiredPVNO = m.Header.PVNO
	}

	var bodyBuilder cryptobyte.Builder
	m.Body.marshal(mctx, &bodyBuilder)
	var err error
	m.rawBody, err = bodyBuilder.Bytes()
	if err != nil {
		return err
	}

	m.Header.PVNO = mctx.MinRequiredPVNO

	var headerBuilder cryptobyte.Builder
	m.Header.marshal(mctx, &headerBuilder)
	m.rawHeader, err = headerBuilder.Bytes()
	if err != nil {
		return err
	}
	return nil
}

// pbmParameter per RFC 9810 §5.1.3.1.
//
//	PBMParameter ::= SEQUENCE {
//	   salt                OCTET STRING,
//	   owf                 AlgorithmIdentifier,
//	   iterationCount      INTEGER,
//	   mac                 AlgorithmIdentifier
//	}
type pbmParameter struct {
	Salt           []byte
	OWF            AlgorithmIdentifier
	IterationCount int
	MAC            AlgorithmIdentifier
}

func (p *pbmParameter) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PBMParameter sequence"}
	}
	if !seq.ReadASN1Bytes(&p.Salt, cbasn1.OCTET_STRING) {
		return &ParseError{Detail: "invalid salt"}
	}
	if err := p.OWF.unmarshal(&seq); err != nil {
		return err
	}
	// Reading into int rejects a value that does not fit the platform int. The
	// range check belongs to the caller, which knows the configured limits.
	if !seq.ReadASN1Integer(&p.IterationCount) {
		return &ParseError{Detail: "invalid iterationCount"}
	}
	return p.MAC.unmarshal(&seq)
}

func (p *pbmParameter) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(p.Salt)
		p.OWF.marshal(mctx, b)
		b.AddASN1Int64(int64(p.IterationCount))
		p.MAC.marshal(mctx, b)
	})
}

var (
	// defaultPBMSaltLength is the default length of the salt for Password-Based MAC.
	// RFC 4211 §4.4 recommends at least 8 octets; 16 provides additional security margin.
	defaultPBMSaltLength = 16

	// defaultPBMIterationCount is the default number of iterations for Password-Based MAC.
	// RFC 4211 §4.4 requires a minimum of 100; 10000 is a local policy choice
	// balancing security against computation cost.
	defaultPBMIterationCount = 10000

	// defaultPBMOWF is the default one-way function (OWF) algorithm OID for Password-Based MAC.
	defaultPBMOWF = oidSHA256

	// defaultPBMMAC is the default MAC algorithm OID for Password-Based MAC.
	defaultPBMMAC = oidHMACWithSHA256

	// defaultPBKDF2MinKeyLength is the shortest PBMAC1 derived key accepted from a
	// peer, in bytes. 128 bits is the conventional floor for a symmetric key and
	// is well beyond exhaustive search.
	defaultPBKDF2MinKeyLength = 16
)

const (
	// DefaultMinMACIterationCount is the smallest PasswordBasedMac or PBMAC1
	// iteration count accepted by default. RFC 4211 §4.4 requires at least 100,
	// but the default stays at 1 so that a peer choosing fewer is not rejected.
	DefaultMinMACIterationCount = 1

	// DefaultMaxMACIterationCount is the largest PasswordBasedMac or PBMAC1
	// iteration count accepted by default. No RFC sets a maximum. RFC 4210 and
	// RFC 9810 let an implementation limit the count to reduce the risk of
	// denial of service, because the peer chooses it and the receiver must run
	// every iteration before it can check the MAC.
	DefaultMaxMACIterationCount = 500000
)

// macIterationLimits returns the effective iteration count bounds. A
// non-positive bound selects its default and a maximum below the minimum is
// raised to it.
func macIterationLimits(minimum, maximum int) (int, int) {
	if minimum <= 0 {
		minimum = DefaultMinMACIterationCount
	}
	if maximum <= 0 {
		maximum = DefaultMaxMACIterationCount
	}
	if maximum < minimum {
		maximum = minimum
	}
	return minimum, maximum
}

// validatePBMIterationCount checks a PasswordBasedMac or PBKDF2 iteration count
// against the bounds that macIterationLimits derives from minimum and maximum.
func validatePBMIterationCount(iterationCount, minimum, maximum int) error {
	minimum, maximum = macIterationLimits(minimum, maximum)
	if iterationCount < minimum {
		return &ParseError{Detail: fmt.Sprintf("PBM iterationCount too small: %d (minimum %d)", iterationCount, minimum)}
	}
	if iterationCount > maximum {
		return &ParseError{Detail: fmt.Sprintf("PBM iterationCount too large: %d (maximum %d)", iterationCount, maximum)}
	}
	return nil
}

// validatePBKDF2KeyLength bounds the PBMAC1 derived key length accepted from a peer.
func validatePBKDF2KeyLength(keyLength int, macHash crypto.Hash) error {
	// A very short derived key turns the key length into a forgery primitive: a
	// peer that asks for a few bytes shrinks the key space to something
	// searchable, so protection can be forged without ever learning the shared
	// secret. The floor is an absolute key strength requirement rather than the
	// MAC's digest size, because deriving 32 bytes for every MAC is common
	// practice, including for HMAC-SHA-384 and HMAC-SHA-512, and rejecting it
	// would break interoperability without buying any security.
	if keyLength < defaultPBKDF2MinKeyLength {
		return &ParseError{
			Detail: fmt.Sprintf("PBKDF2 keyLength too small: %d (minimum %d)", keyLength, defaultPBKDF2MinKeyLength),
		}
	}
	// An HMAC key longer than the hash block size is hashed down to the digest size,
	// so a longer derived key adds no strength while multiplying PBKDF2 work.
	maxKeyLength := macHash.New().BlockSize()
	if keyLength > maxKeyLength {
		return &ParseError{
			Detail: fmt.Sprintf("PBKDF2 keyLength too large: %d (maximum %d for this MAC)", keyLength, maxKeyLength),
		}
	}
	return nil
}

// derivePBMKey derives the MAC key from a shared secret using the Password-Based
// MAC key derivation algorithm per RFC 9810 §5.1.3.1.
// The OWF is applied iterationCount times: the salted secret is input to the
// first iteration, and each successive iteration uses the previous output.
//
// Returns an error if the MAC key size exceeds the OWF output size (key expansion
// K > H case per RFC 9810 §5.1.3.1 is not implemented).
func derivePBMKey(secret, salt []byte, iterationCount int, hash, macHash crypto.Hash) ([]byte, error) {
	if macHash.Size() > hash.Size() {
		return nil, fmt.Errorf(
			"MAC key size (%d) exceeds OWF output size (%d): key expansion not supported",
			macHash.Size(), hash.Size(),
		)
	}

	h := hash.New()
	h.Write(secret)
	h.Write(salt)
	k := h.Sum(nil)

	for i := 1; i < iterationCount; i++ {
		h.Reset()
		h.Write(k)
		k = h.Sum(nil)
	}
	return k, nil
}
