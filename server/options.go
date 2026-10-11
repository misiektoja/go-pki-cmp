package server

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// Option configures a Server.
type Option func(*serverConfig)

// SecretLookup resolves shared secrets for verifying MAC-protected messages.
//
// The sender parameter is the DN from the PKIHeader sender field. It may be
// a NULL-DN (len(sender.Names) == 0) when the sender identity is unknown,
// e.g., during initial enrollment (RFC 9810 §5.1.1).
//
// The senderKID parameter is the reference number that identifies the shared
// secret (RFC 4210 §5.1.3.1). When sender is a NULL-DN, senderKID MUST be
// present (non-nil) and is the sole means of identifying the shared secret.
//
// Implementations may use either or both fields to locate the shared secret.
type SecretLookup interface {
	LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error)
}

// SecretLookupFunc adapts a function to the SecretLookup interface.
type SecretLookupFunc func(sender pkix.Name, senderKID []byte) ([]byte, error)

func (f SecretLookupFunc) LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error) {
	return f(sender, senderKID)
}

// CertificateLookup resolves sender certificates for verifying signature-protected messages.
//
// The issuer parameter is the DN from the PKIHeader recipient field (the CA's identity).
// It may be a NULL-DN (len(issuer.Names) == 0) if the client did not set a recipient.
//
// The subject parameter is the DN from the PKIHeader sender field (the end entity's identity).
// It may be a NULL-DN (len(subject.Names) == 0) when the sender identity is not yet known,
// e.g., during initial enrollment (RFC 9810 §5.1.1).
//
// The senderKID parameter is the key identifier from the PKIHeader senderKID field. It is
// OPTIONAL and may be nil if the client did not include it (RFC 9810 §5.1.1).
//
// Implementations may use any combination of these fields to locate the certificate.
type CertificateLookup interface {
	LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)
}

// CertificateLookupFunc adapts a function to the CertificateLookup interface.
type CertificateLookupFunc func(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)

func (f CertificateLookupFunc) LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return f(issuer, subject, senderKID)
}

type serverConfig struct {
	signerKey                    crypto.Signer
	signerCert                   *x509.Certificate
	signerChain                  []*x509.Certificate
	secretLookup                 SecretLookup
	certificateLookup            CertificateLookup
	extraCerts                   []*x509.Certificate
	sender                       pkix.Name
	confirmWait                  time.Duration
	implicitConfirm              bool
	maxTransactions              int
	maxTransactionsPerCredential int
	strictProfile                bool
	allowSHA1Signatures          bool
	messageTimeTolerance         time.Duration
	raAuthorizer                 RAAuthorizer
	minMACIterationCount         int                  // zero selects pkicmp.DefaultMinMACIterationCount
	maxMACIterationCount         int                  // zero selects pkicmp.DefaultMaxMACIterationCount
	confirmer                    CertificateConfirmer // set automatically by NewCAServer

	// Built once by New from signerKey and signerCert. signerErr records a
	// rejected pair so responses fail visibly instead of going out unprotected.
	signerCreds *pkicmp.SignatureCredentials
	signerErr   error
}

// WithSigner configures signature-based response protection. The key must match
// the certificate; [New] reports a mismatch through [Server.Err]. The key may be
// a composite ML-DSA key from github.com/misiektoja/go-composite-mldsa.
func WithSigner(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) Option {
	return func(c *serverConfig) {
		c.signerKey = key
		c.signerCert = cert
		c.signerChain = chain
	}
}

// WithSecretLookup configures lookup of shared secrets for MAC-protected requests.
func WithSecretLookup(lookup SecretLookup) Option {
	return func(c *serverConfig) {
		c.secretLookup = lookup
	}
}

// WithCertificateLookup configures lookup of sender certificates for signature-protected requests.
func WithCertificateLookup(lookup CertificateLookup) Option {
	return func(c *serverConfig) {
		c.certificateLookup = lookup
	}
}

// WithExtraCerts provides additional certificates to include in responses.
func WithExtraCerts(certs []*x509.Certificate) Option {
	return func(c *serverConfig) {
		c.extraCerts = certs
	}
}

// WithSender sets the server's identity used in response headers.
func WithSender(name pkix.Name) Option {
	return func(c *serverConfig) {
		c.sender = name
	}
}

// WithConfirmWaitTime sets the confirmWaitTime included in certificate responses
// and controls when [Server.CleanupExpired] considers transactions stale.
// The default is 10 seconds. RFC 9810 §5.1.1.2.
func WithConfirmWaitTime(d time.Duration) Option {
	return func(c *serverConfig) {
		c.confirmWait = d
	}
}

// WithImplicitConfirm configures the server to always include id-it-implicitConfirm
// in successful certificate responses, skipping the certConf/pkiConf exchange.
// RFC 9810 §5.1.1.1.
func WithImplicitConfirm() Option {
	return func(c *serverConfig) {
		c.implicitConfirm = true
	}
}

// WithStrictProfileValidation enforces the RFC 9483 message construction rules
// that a receiver can check but does not need to authenticate a peer. It adds
// seven rejections:
//
//   - a MAC-protected message whose sender is not a directoryName naming the
//     shared secret (§3.1), unless it is a nested message (§5.2.2.1),
//   - a signature-protected request or nested message that carries no
//     extraCerts (§3.3, §5.2.2),
//   - a signature-protected request whose extraCerts do not lead with the CMP
//     protection certificate followed by its issuer chain (§3.3),
//   - a certConf whose senderNonce repeats one used earlier in the transaction (§3.1),
//   - a request without a transactionID (§3.5), which RFC 4210 and RFC 9810
//     let the server assign instead,
//   - a message whose senderNonce is missing or shorter than 128 bits (§3.5),
//     which RFC 4210 and RFC 9810 leave optional,
//   - a certConf with more than one CertStatus (§4.1.1).
//
// Off by default because deployed clients fail them: Nokia ssh-cmpclient
// sends a NULL-DN sender, omits its own certificate and reuses the senderNonce,
// openssl cmp omits a self-signed issuer and RFC 4210 clients may omit the
// transactionID or send a shorter senderNonce. None of them affects
// authentication, which comes from senderKID or CertificateLookup plus
// recipNonce. Turn it on for a conformance suite or a known-conforming fleet.
func WithStrictProfileValidation() Option {
	return func(c *serverConfig) {
		c.strictProfile = true
	}
}

// WithSHA1Signatures accepts requests signed with sha1WithRSAEncryption or
// ecdsa-with-SHA1, in the message protection and in the CRMF proof of
// possession.
//
// RFC 4210 era devices may still sign this way, but RFC 9481 §7.1 deprecates
// SHA-1, so the server refuses such requests with badAlg by default. The option
// does not cover DSA. A p10cr whose CSR is signed with SHA-1 is accepted either
// way, because crypto/x509 allows SHA-1 on certificate requests.
func WithSHA1Signatures() Option {
	return func(c *serverConfig) {
		c.allowSHA1Signatures = true
	}
}

// WithMessageTimeTolerance rejects a messageTime further than tolerance from
// server time, with failInfo badTime (RFC 9483 §3.5).
//
// The threshold varies by use case, so the check is off by default and a
// non-positive duration disables it. A message with no messageTime is not
// rejected; one carrying any value, including the zero GeneralizedTime, is
// checked.
func WithMessageTimeTolerance(tolerance time.Duration) Option {
	return func(c *serverConfig) {
		c.messageTimeTolerance = tolerance
	}
}

// WithRAAuthorizer accepts requests that a registration authority forwards in a
// nested message, as far as authorizer allows (RFC 9483 §5.2.2.1). Without it,
// nested messages are rejected with badRequest. Batches of several messages
// are always rejected.
func WithRAAuthorizer(authorizer RAAuthorizer) Option {
	return func(c *serverConfig) {
		c.raAuthorizer = authorizer
	}
}

// WithMACIterationLimits sets the range of PasswordBasedMac and PBMAC1
// iteration counts accepted in MAC-protected requests. A request outside it is
// rejected with badMessageCheck before any key derivation. Responses echo the
// request's count, so the same range applies to them.
//
// The defaults are [pkicmp.DefaultMinMACIterationCount] and
// [pkicmp.DefaultMaxMACIterationCount]. Zero selects a default and a maximum
// below the minimum is raised to it.
//
// The client chooses the count and every iteration runs before the MAC can be
// checked, so the maximum bounds the work an unauthenticated request costs.
// Only a request naming a known shared secret reaches that point. Raise the
// maximum for devices configured with more iterations. Raise the minimum, for
// example to the 100 that RFC 4211 §4.4 requires, to refuse protection too
// cheap to slow an offline guess of a weak shared secret.
func WithMACIterationLimits(minimum, maximum int) Option {
	return func(c *serverConfig) {
		c.minMACIterationCount = minimum
		c.maxMACIterationCount = maximum
	}
}

// WithMaxTransactions sets the maximum number of concurrent transactions.
// Default is 10000.
func WithMaxTransactions(n int) Option {
	return func(c *serverConfig) {
		c.maxTransactions = n
	}
}

// WithMaxTransactionsPerCredential sets the maximum number of concurrent
// transactions per credential. Default is 100.
func WithMaxTransactionsPerCredential(n int) Option {
	return func(c *serverConfig) {
		c.maxTransactionsPerCredential = n
	}
}
