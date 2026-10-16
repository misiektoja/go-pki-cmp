package pkicmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"

	"github.com/misiektoja/go-pki-cmp/internal/certpath"
)

// ProtectionMechanism identifies a class of message protection.
type ProtectionMechanism int

const (
	// ProtectionAny accepts whichever mechanism the message carries. A server
	// needs this to serve both shared-secret and certificate-based clients,
	// because it cannot know which one a peer will use for the first message.
	ProtectionAny ProtectionMechanism = iota
	// ProtectionMAC accepts only shared-secret protection (PasswordBasedMac or PBMAC1).
	ProtectionMAC
	// ProtectionSignature accepts only signature-based protection.
	ProtectionSignature
)

// VerifyOptions provides trust material for message protection verification.
//
// Verification dispatches on the message's ProtectionAlg OID, so a caller that
// supplies both a shared secret and a trust pool accepts whichever mechanism
// the peer chose. Set RequiredProtection to pin the mechanism instead.
//
//   - MAC-protected message: uses the SharedSecret field.
//   - Signature-protected message: uses TrustPool for chain verification.
//
// RFC 9810 §5.1.3.
type VerifyOptions struct {
	// RequiredProtection restricts which protection mechanism is accepted. The
	// zero value, ProtectionAny, accepts either.
	//
	// The mechanism must not change within one PKI management operation
	// (RFC 9483 §3.1, failInfo wrongIntegrity in RFC 9810 §5.2.3). Pin it when
	// the caller knows how the operation started, otherwise a peer may
	// substitute whichever mechanism is easier for it to satisfy.
	RequiredProtection ProtectionMechanism

	// SharedSecret is the shared secret for MAC-protected messages.
	// For signature-protected messages this field is ignored (TrustPool is
	// used instead). May be nil if only signature verification is needed.
	SharedSecret []byte

	// TrustPool holds root CA certificates for verifying signature-protected
	// messages. For MAC-protected messages this field is ignored. May be nil
	// if only MAC verification is needed.
	//
	// A certificate signed with a composite ML-DSA key is accepted only when
	// its issuer is also in ExtraCerts, even if that issuer is a root in this
	// pool. No certificate in such a path may have name constraints.
	TrustPool *x509.CertPool

	// TrustedCert verifies the signature directly, without chain building, for a
	// verifier that already resolved the sender's certificate from its own store.
	// Takes precedence over TrustPool and ExtraCerts. The certificate must still
	// be within its validity period and match the sender named in the header.
	TrustedCert *x509.Certificate

	// CurrentTime is the time at which the protection certificate and its chain
	// must be valid. The zero value means the time of the call. Set it to check a
	// recorded message at the time it was received. Do not take it from the
	// message being verified when the result decides whether to act on that
	// message, because the sender chooses its messageTime.
	CurrentTime time.Time

	// ExtraCerts provides candidate signer certificates (typically from
	// msg.ExtraCerts) for signature chain building. Certificates the caller
	// knows out of band may be appended, and each must pass the same chain,
	// sender and signature checks. Without any candidate, verification fails
	// with [ReasonNoCandidateSigner].
	ExtraCerts []CMPCertificate

	// SenderKID filters candidate signer certificates by SubjectKeyId
	// (typically msg.Header.SenderKID). When it names none of them,
	// verification fails with [ReasonSenderKIDMismatch].
	SenderKID []byte

	// AllowSenderKIDMismatch tries every candidate when SenderKID names none
	// of them. A candidate that SenderKID names is still the only one tried.
	//
	// RFC 9483 §3.1 requires senderKID to hold the SubjectKeyIdentifier of the
	// CMP protection certificate, but some CAs copy the senderKID of the
	// request into the response. Each candidate still faces the chain, sender
	// and signature checks, so this only stops senderKID from excluding the
	// real signer. Enable it only for such a peer.
	AllowSenderKIDMismatch bool

	// RequireDigitalSignatureKeyUsage rejects a CMP protection certificate that
	// carries a keyUsage extension without the digitalSignature bit, as
	// RFC 9483 §3.5 requires.
	//
	// It is off by default because deployed CAs do not follow the rule. Nokia
	// NCM 26.7 protects its CMP responses with the issuing CA certificate, whose
	// keyUsage is keyCertSign and cRLSign only, so enabling this rejects every
	// response from that server. Turn it on when every peer is known to conform.
	RequireDigitalSignatureKeyUsage bool

	// AllowSHA1Signatures accepts message protection signed with
	// sha1WithRSAEncryption or ecdsa-with-SHA1, which RFC 4210 era peers may
	// still use. RFC 9481 §7.1 deprecates both, so enable this only for such
	// peers. crypto/x509 still rejects SHA-1 signatures on certificates during
	// chain building. DSA is not supported.
	AllowSHA1Signatures bool

	// MinMACIterationCount and MaxMACIterationCount bound the iteration count
	// that the sender chose for PasswordBasedMac or for PBKDF2 in PBMAC1. A
	// message outside the range fails before any key derivation. Zero selects
	// [DefaultMinMACIterationCount] or [DefaultMaxMACIterationCount]. A maximum
	// below the minimum is raised to it.
	//
	// The maximum limits the work an unauthenticated message can cost, because
	// every iteration runs before the MAC can be checked. Raise it for a peer
	// that sends more iterations. The minimum is the security setting: it
	// refuses protection too cheap to slow an offline guess of a weak secret.
	MinMACIterationCount int
	MaxMACIterationCount int
}

// VerifyResult is returned on successful verification.
type VerifyResult struct {
	// MACVerified is true when the message was verified using a shared secret
	// (PBM, PBMAC1, or KEM-MAC). This determines whether caPubs from the
	// message body may be trusted (RFC 9810 §5.3.2).
	MACVerified bool

	// ProtectionParams is a [MACCredentialOption] that captures the decoded
	// protection parameters from a verified MAC-protected message.
	// Pass it to [NewMACCredentials] to protect a response with the same
	// algorithm suite (fresh salt is generated). Nil for signature-verified messages.
	// RFC 9810 §5.1.3.
	ProtectionParams MACCredentialOption

	// ProtectionCertificate is the certificate whose signature was accepted, nil
	// for MAC-verified messages.
	//
	// extraCerts may appear only on the first message of an operation
	// (RFC 9810 §5.1), so later messages can arrive with no candidate signer.
	// Keep this and pass it back through [VerifyOptions.ExtraCerts] to verify
	// them; they still face the same chain, sender and signature checks.
	ProtectionCertificate *x509.Certificate
}

// Verify verifies the message protection and returns verification metadata.
// The algorithm is determined from Header.ProtectionAlg.
// Verify uses the algorithm OID from the header to select the correct
// verification path (MAC or signature) and ignores irrelevant fields.
// RFC 9810 §5.1.3.
func (m *PKIMessage) Verify(opts VerifyOptions) (*VerifyResult, error) {
	if m.Header.ProtectionAlg == nil {
		return nil, &ParseError{Detail: "message has no protection algorithm"}
	}
	if len(m.Protection) == 0 {
		return nil, &ParseError{Detail: "message is not protected"}
	}
	if m.Body == nil {
		return nil, &ParseError{Detail: detailMissingMessageBody}
	}

	alg := m.Header.ProtectionAlg.Algorithm

	// Dispatch based on algorithm OID, after checking it against the mechanism
	// the caller requires. Without this the peer picks the mechanism, which lets
	// it substitute one the caller never intended to accept.
	if alg.Equal(oidPasswordBasedMac) || alg.Equal(oidPBMAC1) {
		if opts.RequiredProtection == ProtectionSignature {
			return nil, &VerificationError{
				Reason: ReasonUnexpectedProtection,
				Err:    fmt.Errorf("message is MAC-protected but signature-based protection is required"),
			}
		}
		if alg.Equal(oidPasswordBasedMac) {
			return m.verifyPBM(opts)
		}
		return m.verifyPBMAC1(opts)
	}
	_, isSHA1 := sha1SigAlgFromOID(alg)
	_, isComposite := compositemldsa.AlgorithmFromOID(alg)
	if _, err := sigAlgFromOID(alg); err == nil || isSHA1 || isComposite {
		if opts.RequiredProtection == ProtectionMAC {
			return nil, &VerificationError{
				Reason: ReasonUnexpectedProtection,
				Err:    fmt.Errorf("message is signature-protected but MAC-based protection is required"),
			}
		}
		return m.verifySignature(opts)
	}

	return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("OID %v", alg)}
}

// verifyPBM verifies Password-Based MAC protection.
// RFC 9810 §5.1.3.1.
func (m *PKIMessage) verifyPBM(opts VerifyOptions) (*VerifyResult, error) {
	secret := opts.SharedSecret
	if len(secret) == 0 {
		return nil, &VerificationError{Reason: ReasonMissingSharedSecret}
	}

	var p pbmParameter
	params := cryptobyte.String(m.Header.ProtectionAlg.Parameters)
	if err := p.unmarshal(&params); err != nil {
		return nil, err
	}

	minIterations, maxIterations := macIterationLimits(opts.MinMACIterationCount, opts.MaxMACIterationCount)
	if err := validatePBMIterationCount(p.IterationCount, minIterations, maxIterations); err != nil {
		return nil, err
	}

	hash, err := hashFromOID(p.OWF.Algorithm)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	if !hash.Available() {
		return nil, &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("hash %v not available", p.OWF.Algorithm),
		}
	}

	macHash, err := hmacHashFromOID(p.MAC.Algorithm)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	if !macHash.Available() {
		return nil, &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("MAC hash %v not available", p.MAC.Algorithm),
		}
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	k, err := derivePBMKey(secret, p.Salt, p.IterationCount, hash, macHash)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	mac := hmac.New(macHash.New, k)
	mac.Write(data)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expected, m.Protection) != 1 {
		return nil, &VerificationError{Reason: ReasonBadMAC}
	}

	return &VerifyResult{
		MACVerified: true,
		ProtectionParams: func(c *macCredentialConfig) {
			c.algorithm = oidPasswordBasedMac
			c.iterationCount = p.IterationCount
			c.minIterationCount = minIterations
			c.maxIterationCount = maxIterations
			c.owf = p.OWF.Algorithm
			c.mac = p.MAC.Algorithm
			c.owfParameters = p.OWF.Parameters
			c.macParameters = p.MAC.Parameters
		},
	}, nil
}

// verifyPBMAC1 verifies PBMAC1 protection.
// RFC 8018 §7.1, RFC 9481 §6.1.2.
func (m *PKIMessage) verifyPBMAC1(opts VerifyOptions) (*VerifyResult, error) {
	secret := opts.SharedSecret
	if len(secret) == 0 {
		return nil, &VerificationError{Reason: ReasonMissingSharedSecret}
	}

	// Parse PBMAC1-params (RFC 8018 §A.5).
	var pbmac1Params struct {
		KeyDerivationFunc algorithmIdentifierASN1
		MessageAuthScheme algorithmIdentifierASN1
	}
	if _, err := asn1.Unmarshal(m.Header.ProtectionAlg.Parameters, &pbmac1Params); err != nil {
		return nil, &ParseError{Detail: "invalid PBMAC1-params: " + err.Error()}
	}

	if !pbmac1Params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("KDF OID %v", pbmac1Params.KeyDerivationFunc.Algorithm),
		}
	}

	// Parse PBKDF2-params from keyDerivationFunc.Parameters.
	pbkdf2Params, err := parsePBKDF2Params(pbmac1Params.KeyDerivationFunc.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}

	minIterations, maxIterations := macIterationLimits(opts.MinMACIterationCount, opts.MaxMACIterationCount)
	if err := validatePBMIterationCount(pbkdf2Params.IterationCount, minIterations, maxIterations); err != nil {
		return nil, err
	}

	prfHash, err := hmacHashFromOID(pbkdf2Params.PRF.Algorithm)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	if !prfHash.Available() {
		return nil, &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("PRF hash %v not available", pbkdf2Params.PRF.Algorithm),
		}
	}
	macHash, err := hmacHashFromOID(pbmac1Params.MessageAuthScheme.Algorithm)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	if !macHash.Available() {
		return nil, &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("MAC hash %v not available", pbmac1Params.MessageAuthScheme.Algorithm),
		}
	}

	// RFC 8018 §A.5: keyLength is OPTIONAL. When the peer omits it, §7.1 leaves the
	// length to the MAC scheme, which for HMAC is the digest size.
	if pbkdf2Params.KeyLength == 0 {
		pbkdf2Params.KeyLength = macHash.Size()
	}
	if err := validatePBKDF2KeyLength(pbkdf2Params.KeyLength, macHash); err != nil {
		return nil, err
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	// Derive key using PBKDF2 (RFC 8018 §5.2).
	k := pbkdf2.Key(secret, pbkdf2Params.Salt, pbkdf2Params.IterationCount, pbkdf2Params.KeyLength, prfHash.New)
	h := hmac.New(macHash.New, k)
	h.Write(data)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(expected, m.Protection) != 1 {
		return nil, &VerificationError{Reason: ReasonBadMAC}
	}

	return &VerifyResult{
		MACVerified: true,
		ProtectionParams: func(c *macCredentialConfig) {
			c.algorithm = oidPBMAC1
			c.iterationCount = pbkdf2Params.IterationCount
			c.minIterationCount = minIterations
			c.maxIterationCount = maxIterations
			c.keyLength = pbkdf2Params.KeyLength
			c.owf = pbkdf2Params.PRF.Algorithm
			c.mac = pbmac1Params.MessageAuthScheme.Algorithm
		},
	}, nil
}

// verifySignature verifies signature-based protection.
// RFC 9810 §5.1.3.3: Verify using certificates from extraCerts, validated
// against a trust pool.
// RFC 9810 §8.9: The message sender MUST be authenticated with existing
// trust anchors.
func (m *PKIMessage) verifySignature(opts VerifyOptions) (*VerifyResult, error) {
	checkSignature, err := signatureChecker(*m.Header.ProtectionAlg, opts.AllowSHA1Signatures)
	if err != nil {
		return nil, err
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	now := opts.verificationTime()

	// Direct verification against a pre-trusted certificate (server-side lookup).
	if opts.TrustedCert != nil {
		// The chain path gets expiry checking from x509.Verify. This path does
		// not, so without this an expired certificate left in the verifier's
		// database would keep authenticating forever.
		if now.Before(opts.TrustedCert.NotBefore) || now.After(opts.TrustedCert.NotAfter) {
			return nil, &VerificationError{Reason: ReasonCertificateExpired}
		}
		// RFC 9483 §3.5: the sender must be the subject of the protection
		// certificate. Resolving a certificate from a database proves only that
		// the verifier knows it, not that the message came from the identity the
		// header claims, so a lookup keyed on senderKID alone would otherwise
		// pair a genuine certificate with any sender name the peer chose.
		if !senderMatchesCertificate(m.Header.Sender, opts.TrustedCert) {
			return nil, &VerificationError{Reason: ReasonSenderMismatch}
		}
		if opts.RequireDigitalSignatureKeyUsage && !permittedToSign(opts.TrustedCert) {
			return nil, &VerificationError{Reason: ReasonKeyUsageNotPermitted}
		}
		if err := checkSignature(opts.TrustedCert, data, m.Protection); err != nil {
			return nil, &VerificationError{Reason: ReasonSignatureFailed}
		}
		return &VerifyResult{MACVerified: false, ProtectionCertificate: opts.TrustedCert}, nil
	}

	// Chain-based verification using TrustPool and ExtraCerts.
	if opts.TrustPool == nil {
		return nil, &VerificationError{Reason: ReasonMissingTrustAnchors}
	}

	// Candidate issuers from ExtraCerts for chain verification.
	var intermediates []*x509.Certificate
	for _, cert := range opts.ExtraCerts {
		x509Cert, err := cert.Parse()
		if err != nil {
			continue
		}
		intermediates = append(intermediates, x509Cert)
	}
	// A message without a certificate to try says nothing about its signature,
	// so it is reported apart from one whose signature did not verify. RFC 9483
	// §3.3 requires extraCerts on the first response of an operation, but
	// RFC 9810 §5.1 leaves them optional and some CAs omit them.
	if len(intermediates) == 0 {
		return nil, &VerificationError{Reason: ReasonNoCandidateSigner}
	}

	// RFC 9810 §5.1.1: senderKID identifies the key used for protection.
	signers := intermediates
	if len(opts.SenderKID) > 0 {
		signers = slices.DeleteFunc(slices.Clone(intermediates), func(cert *x509.Certificate) bool {
			return !bytes.Equal(cert.SubjectKeyId, opts.SenderKID)
		})
		if len(signers) == 0 {
			if !opts.AllowSenderKIDMismatch {
				return nil, &VerificationError{
					Reason: ReasonSenderKIDMismatch,
					Err:    fmt.Errorf("no certificate has subject key identifier %X", opts.SenderKID),
				}
			}
			signers = intermediates
		}
	}

	// named counts the candidates whose subject is the sender, the only ones
	// that may be the protection certificate. The failure of a named candidate
	// is reported, so the CA certificates a server sends along with its own do
	// not hide why its certificate was refused. With no named candidate the
	// failure is an identity problem rather than a cryptographic one.
	named := 0
	// chained counts the named candidates that reach a trust anchor. untrusted
	// keeps the chain error of the first one that does not, which is the
	// reported cause when none does. keyUsageRejected records a trusted named
	// certificate that is not allowed to sign.
	chained := 0
	var untrusted error
	keyUsageRejected := false

	// RFC 9810 §5.1.3.3: Verify the signature using certificates from extraCerts.
	for _, x509Cert := range signers {
		// RFC 9483 §3.5: the sender field must match the subject of the CMP
		// protection certificate. Chaining to a trust anchor only proves the
		// certificate is trusted, not that it belongs to the claimed sender, so
		// without this any certificate under any configured anchor would pass.
		if !senderMatchesCertificate(m.Header.Sender, x509Cert) {
			continue
		}
		named++
		// Verify trust chain. Any extended key usage is accepted because
		// crypto/x509 otherwise demands serverAuth, which no CMP specification
		// asks for and which rejects the RFC 9810 §4.5 certificates
		// id-kp-cmcCA, id-kp-cmcRA and id-kp-cmKGA.
		if err := certpath.Verify(x509Cert, opts.TrustPool, intermediates, now); err != nil {
			if untrusted == nil {
				untrusted = err
			}
			continue
		}
		chained++
		if opts.RequireDigitalSignatureKeyUsage && !permittedToSign(x509Cert) {
			keyUsageRejected = true
			continue
		}
		// Check signature over protected part.
		if err := checkSignature(x509Cert, data, m.Protection); err == nil {
			return &VerifyResult{MACVerified: false, ProtectionCertificate: x509Cert}, nil
		}
	}

	if named == 0 {
		return nil, &VerificationError{Reason: ReasonSenderMismatch}
	}
	// A signature is checked only with a trusted certificate, so a message
	// signed by a certificate outside the trust pool is reported as untrusted
	// rather than as a bad signature.
	if chained == 0 {
		return nil, &VerificationError{Reason: ReasonUntrustedSigner, Err: untrusted}
	}
	if keyUsageRejected {
		return nil, &VerificationError{Reason: ReasonKeyUsageNotPermitted}
	}
	return nil, &VerificationError{Reason: ReasonSignatureFailed}
}

// verificationTime returns the time at which certificates must be valid.
func (o *VerifyOptions) verificationTime() time.Time {
	if o.CurrentTime.IsZero() {
		return time.Now()
	}
	return o.CurrentTime
}

// signatureChecker returns the check of a protection signature made with the
// key of a certificate, for classical, ML-DSA and composite ML-DSA algorithms.
func signatureChecker(alg AlgorithmIdentifier, allowSHA1 bool) (func(cert *x509.Certificate, data, signature []byte) error, error) {
	composite, ok, err := compositeSignatureAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	if ok {
		return func(cert *x509.Certificate, data, signature []byte) error {
			pub, err := compositex509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
			if err != nil {
				return err
			}
			key, isComposite := pub.(*compositemldsa.PublicKey)
			if !isComposite || key.Algorithm() != composite {
				return errors.New("certificate key does not match the protection algorithm")
			}
			return compositemldsa.Verify(key, data, signature, nil)
		}, nil
	}
	sigAlg, err := signatureAlgorithm(alg, allowSHA1)
	if err != nil {
		return nil, err
	}
	return func(cert *x509.Certificate, data, signature []byte) error {
		return cert.CheckSignature(sigAlg, data, signature)
	}, nil
}

// permittedToSign reports whether a CMP protection certificate may sign, per the RFC 9483 §3.5 digitalSignature rule.
func permittedToSign(cert *x509.Certificate) bool {
	// The requirement is conditional on the extension being present, so a
	// certificate without keyUsage is unconstrained and remains acceptable.
	// crypto/x509 reports KeyUsage as zero in both cases, so the extension list
	// is what distinguishes "absent" from "present and empty".
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionKeyUsage) {
			return cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		}
	}
	return true
}

// senderMatchesCertificate reports whether the header sender names the subject of the protection certificate.
func senderMatchesCertificate(sender GeneralName, cert *x509.Certificate) bool {
	// RFC 4210 §5.1.1 requires a NULL DN when the sender does not know its own
	// name, and GeneralName has variants other than directoryName. There is no
	// directory name to compare in those cases, so the binding does not apply
	// and authenticity rests on the trust chain alone.
	if len(sender.DirectoryName) == 0 {
		return true
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil {
		return false
	}
	// Compare the decoded forms so that a name encoded as PrintableString in one
	// place and UTF8String in the other still matches.
	return sender.DirectoryName.String() == subject.String()
}
