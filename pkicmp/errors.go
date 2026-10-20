package pkicmp

import (
	"fmt"
)

// InvalidReason defines specific reasons for protection or verification failure.
type InvalidReason int

const (
	// ReasonUnknown indicates an unspecified failure.
	ReasonUnknown InvalidReason = iota
	// ReasonUnsupportedAlgorithm indicates an unrecognized or unavailable OID.
	ReasonUnsupportedAlgorithm
	// ReasonMissingSharedSecret indicates a MAC-based operation lacked a key.
	ReasonMissingSharedSecret
	// ReasonMissingSigner indicates a signature-based operation lacked a key.
	ReasonMissingSigner
	// ReasonBadMAC indicates the message integrity check failed.
	ReasonBadMAC
	// ReasonSignatureFailed indicates the cryptographic signature was invalid.
	ReasonSignatureFailed
	// ReasonMissingTrustAnchors indicates no trust anchors were provided for signature verification.
	ReasonMissingTrustAnchors
	// ReasonUnexpectedProtection indicates the message used a different protection
	// mechanism than the caller required. RFC 9810 §5.2.3 defines the matching
	// failInfo bit wrongIntegrity, "password based instead of signature or vice versa".
	ReasonUnexpectedProtection
	// ReasonSenderMismatch indicates that the subject of the protection
	// certificate, or of every candidate for it, is not the sender named in the
	// header (RFC 9483 §3.5).
	ReasonSenderMismatch
	// ReasonKeyUsageNotPermitted indicates the CMP protection certificate carries
	// a keyUsage extension without the digitalSignature bit, which RFC 9483 §3.5
	// requires for signature-based protection.
	ReasonKeyUsageNotPermitted
	// ReasonCertificateExpired indicates that [VerifyOptions.TrustedCert] is
	// outside its validity period at [VerifyOptions.CurrentTime]. An expired
	// certificate on the chain path gives [ReasonUntrustedSigner] instead.
	ReasonCertificateExpired
	// ReasonNoCandidateSigner indicates that no certificate was available to
	// verify a signature: [VerifyOptions.ExtraCerts] held no certificate that
	// could be parsed.
	ReasonNoCandidateSigner
	// ReasonUntrustedSigner indicates that no candidate protection certificate
	// with the sender's name chains to [VerifyOptions.TrustPool], so no
	// signature was checked. Err holds the chain error of the first of them.
	ReasonUntrustedSigner
	// ReasonSenderKIDMismatch indicates that [VerifyOptions.SenderKID] names
	// the subject key identifier of none of the candidate certificates. Either
	// the signer's certificate is missing from [VerifyOptions.ExtraCerts] or
	// the sender filled senderKID with another value, which
	// [VerifyOptions.AllowSenderKIDMismatch] tolerates.
	ReasonSenderKIDMismatch
)

func (r InvalidReason) String() string {
	switch r {
	case ReasonUnsupportedAlgorithm:
		return "unsupported algorithm"
	case ReasonMissingSharedSecret:
		return "missing shared secret"
	case ReasonMissingSigner:
		return "missing signer"
	case ReasonBadMAC:
		return "MAC verification failed"
	case ReasonSignatureFailed:
		return "signature verification failed"
	case ReasonMissingTrustAnchors:
		return "missing trust anchors"
	case ReasonUnexpectedProtection:
		return "unexpected protection mechanism"
	case ReasonSenderMismatch:
		return "sender does not match protection certificate subject"
	case ReasonKeyUsageNotPermitted:
		return "protection certificate is not permitted to sign"
	case ReasonCertificateExpired:
		return "protection certificate is outside its validity period"
	case ReasonNoCandidateSigner:
		return "no candidate signer certificate"
	case ReasonUntrustedSigner:
		return "protection certificate is not trusted"
	case ReasonSenderKIDMismatch:
		return "senderKID names no candidate signer certificate"
	default:
		return "unknown"
	}
}

// VerificationError indicates that message protection verification failed.
type VerificationError struct {
	Reason InvalidReason
	Err    error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: verification failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("pkicmp: verification failed: %s", e.Reason)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// ProtectionError indicates that applying message protection failed.
type ProtectionError struct {
	Reason InvalidReason
	Err    error
}

func (e *ProtectionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: protection failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("pkicmp: protection failed: %s", e.Reason)
}

func (e *ProtectionError) Unwrap() error {
	return e.Err
}

// ParseError indicates that a CMP message or structure could not be decoded.
type ParseError struct {
	Detail string // human-readable description of what failed
	Err    error  // optional wrapped error
	// Header is the message header when it was decoded before the failure,
	// so a receiver can still answer the sender with an error message. It is
	// nil when the header itself could not be decoded.
	Header *PKIHeader
}

// ParseError details reported from more than one place.
const (
	detailInvalidCertReqID       = "invalid certReqId"
	detailMissingMessageBody     = "missing message body"
	detailPoposkInputAuthMissing = "poposkInput authInfo missing"
)

func (e *ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("pkicmp: %s", e.Detail)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}
