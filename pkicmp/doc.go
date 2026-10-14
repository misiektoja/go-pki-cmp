// Package pkicmp implements the Certificate Management Protocol (CMP) as defined
// in RFC 9810, with CRMF support per RFC 4211.
//
// This is the foundational package of the go-pkicmp module. It defines the
// protocol types, message construction, protection, and verification. The
// [server] and [client] packages build on it. Callers who need direct control
// over CMP messages — for custom tooling, RA proxying, or testing — can use
// this package independently.
//
// # Message construction
//
// [PKIMessage] is the top-level type, corresponding to the ASN.1 PKIMessage
// structure. Create one with [NewPKIMessage], supplying a [PKIBody] and
// [MessageOptions]. TransactionID and SenderNonce default to 128 bits of random
// data per RFC 9810 §5.1.1.
//
// [PKIBody] constructors (e.g., [NewIRBody], [NewIPBody], [NewPKIConfBody]) wrap
// the corresponding CHOICE variant. [PKIBody] is lazy: it carries the raw DER
// and decodes into the appropriate Go type only when a typed getter
// (e.g., [PKIBody.IR], [PKIBody.IP]) is called.
//
// [PKIMessage.MarshalBinary] and [ParsePKIMessage] are the only points where
// CMP messages become wire bytes and back; all other types exist only in memory.
// Implementing [encoding.BinaryMarshaler] and [encoding.BinaryUnmarshaler] makes
// [PKIMessage] compatible with standard Go HTTP tooling.
//
// # Protection
//
// [Credentials] is the interface for applying message protection. Two concrete
// types cover all standard CMP protection schemes:
//
//   - [MACCredentials]: password-based MAC, created with [NewMACCredentials].
//     Defaults to PBMAC1 (RFC 8018), the recommended algorithm per RFC 9481 §7.
//     Use [WithPBM] for PasswordBasedMac and [WithPBMAlgorithms] to choose its
//     hash functions, such as the SHA-1 profile RFC 4210 requires.
//   - [SignatureCredentials]: X.509 signature, created with [NewSignatureCredentials].
//
// Apply protection by calling [Credentials.Protect]:
//
//	creds, err := pkicmp.NewMACCredentials([]byte("shared-secret"))
//	if err != nil { ... }
//	err = creds.Protect(msg)
//
// # Verification
//
// [PKIMessage.Verify] verifies message protection. [VerifyOptions] accepts a
// shared secret (MAC), a [crypto/x509.CertPool] (signature), or both when the
// protection algorithm is not known in advance:
//
//	result, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("shared-secret")})
//
// When both are supplied, the message decides which mechanism is used. Set
// [VerifyOptions.RequiredProtection] to [ProtectionMAC] or [ProtectionSignature]
// to pin it instead, which RFC 9483 §3.1 asks for within one PKI management
// operation. The zero value accepts either mechanism. That is what a server needs
// for the first message of an operation, and what a client needs to talk to a CA
// that authenticates by shared secret and signs its responses.
//
// Signature verification also binds the protection certificate to the identity
// the message claims: when the header sender carries a directory name, it must
// equal the subject of the certificate that produced the signature (RFC 9483 §3.5).
// A NULL DN sender, which RFC 4210 §5.1.1 requires when the sender does not know
// its own name, carries no name to bind and is accepted on the trust chain alone.
//
// SHA-1 signatures, which RFC 9481 §7.1 deprecates, fail with
// [ReasonUnsupportedAlgorithm] unless [VerifyOptions.AllowSHA1Signatures] is
// set. [VerifyPOPWithOptions] offers the same choice for proof of possession.
//
// The sender of a MAC-protected message chooses the PasswordBasedMac or PBKDF2
// iteration count. The receiver runs every iteration before it can check the
// MAC. [VerifyOptions.MinMACIterationCount] and [VerifyOptions.MaxMACIterationCount]
// bound the count, by default from [DefaultMinMACIterationCount] to
// [DefaultMaxMACIterationCount]. [WithMACIterationLimits] applies the same range
// when protecting.
//
// [VerifyResult.ProtectionParams] captures the algorithm parameters from a verified
// MAC-protected message, together with the iteration limits it was verified
// against. Pass it to [NewMACCredentials] to protect a response with the same
// algorithm suite (with a fresh salt), as required by RFC 9483 §3.2.
// [WithProtectionAlgorithm] does the same from a raw [AlgorithmIdentifier].
//
// # Caller responsibilities
//
// This package verifies message protection and parses CMP on the wire. It does
// not implement a full enrollment client or CA policy. Integrators remain
// responsible for the checks below.
//
// Pin the protection mechanism you expect on the message being verified, which
// is not always the one you send with: a client that enrolls with a shared
// secret but reads signature-protected responses pins [ProtectionSignature] for
// those. Holding both kinds of trust material under the default
// [ProtectionAny] lets a peer pick whichever is easier to forge.
//
// Retain the protection certificate across a transaction. extraCerts may appear
// only on the first response (RFC 9810 §5.1), so a later pkiConf can arrive with
// no candidate signer and fail with [ReasonNoCandidateSigner] or
// [ReasonSenderKIDMismatch]. Offer
// [VerifyResult.ProtectionCertificate] back through [VerifyOptions.ExtraCerts]
// or [VerifyOptions.TrustedCert]. A peer certificate known out of band can be
// appended to ExtraCerts the same way.
//
// Bind the issued certificate to the request by comparing its public key to the
// key you asked for. This package does not check that. Subjects may differ
// legitimately under [StatusGrantedWithMods].
//
// Trust caPubs only when [VerifyResult.MACVerified] is set, per RFC 9810 §5.3.2.
//
// Clamp checkAfter yourself. [PollRepContent] carries a peer-chosen seconds
// value that this package parses as sent.
//
// Enable [VerifyOptions.RequireDigitalSignatureKeyUsage] only for a
// known-conforming fleet. RFC 9483 §3.5 requires the bit, but deployed CAs
// protect CMP with a CA certificate carrying only keyCertSign and cRLSign.
//
// Sanitize peer text before logging. [PKIStatusInfo.AsError] joins server free
// text without validating UTF-8 or stripping control characters. [PKIFailureInfo]
// parsing does not fully validate BIT STRING unused bits, so treat an ambiguous
// rare failure bit as absent.
//
// # Errors
//
// All errors from this package are typed:
//
//   - [ParseError]: malformed message, missing required field, or an algorithm
//     parameter outside the range this package accepts from an untrusted peer.
//   - [ProtectionError]: failure applying protection.
//   - [VerificationError]: bad MAC or signature, a protection mechanism the caller
//     did not require, a sender that does not match the protection certificate
//     or no certificate to verify a signature with.
//
// Each carries an [InvalidReason] for programmatic inspection.
package pkicmp
