package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"slices"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Client handles CMP message transport and polling.
type Client struct {
	endpoint            string
	httpClient          *http.Client
	recipient           pkix.Name
	extraCerts          []*x509.Certificate
	trustedCAs          *x509.CertPool
	serverCerts         []*x509.Certificate
	responseProtection  pkicmp.ProtectionMechanism
	maxResponseBytes    int64
	maxPolls            int
	minCheckAfter       time.Duration
	maxCheckAfter       time.Duration
	allowSHA1Signatures bool
	allowKIDMismatch    bool
	ignoreCAPubsTrust   bool
	minMACIterations    int
	maxMACIterations    int
}

const (
	// DefaultMaxResponseBytes limits CMP HTTP response size to reduce memory DoS risk.
	DefaultMaxResponseBytes int64 = 10 * 1024 * 1024 // 10 MiB

	// DefaultMaxPolls limits how many pollReq messages are attempted before the
	// client gives up. Total polling time is this many checkAfter intervals, so
	// use a context deadline to bound an operation.
	DefaultMaxPolls = 60

	// DefaultMinCheckAfter is the shortest interval between poll attempts,
	// however short a checkAfter the server sends. RFC 9810 §5.3.22 asks the end
	// entity to wait at least the interval it was given, so a floor is always safe.
	DefaultMinCheckAfter = 1 * time.Second

	// DefaultMaxCheckAfter is the longest interval between poll attempts. A
	// ceiling polls sooner than the CA asked for, so it sits far above any
	// interval a CA is expected to request and only guards against a checkAfter
	// large enough to park the operation or to overflow into no wait at all.
	DefaultMaxCheckAfter = 60 * time.Minute
)

// Option is a functional option for configuring a Client.
type Option func(*Client)

// NewClient creates a new CMP client.
func NewClient(endpoint string, opts ...Option) *Client {
	c := &Client{
		endpoint:         endpoint,
		httpClient:       http.DefaultClient,
		maxResponseBytes: DefaultMaxResponseBytes,
		maxPolls:         DefaultMaxPolls,
		minCheckAfter:    DefaultMinCheckAfter,
		maxCheckAfter:    DefaultMaxCheckAfter,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithRecipient sets the expected CA name in the header.
//
// Many CAs route on this field and refuse a request that omits it, so set it
// whenever the CA name is known.
func WithRecipient(name pkix.Name) Option {
	return func(c *Client) { c.recipient = name }
}

// WithResponseProtection requires every response in an operation to use the
// given protection mechanism.
//
// The default, [pkicmp.ProtectionAny], accepts whichever mechanism the server
// used. RFC 9483 §3.1 asks for one kind of protection per operation, but
// deployed CAs answer a shared-secret request with a signature and RFC 9810
// §5.3.21 requires error messages to be signed either way, so pinning is the
// caller's decision. It is not what binds a response to the request: the
// transaction ID, the nonces, the trust anchor and the issued key check do that.
func WithResponseProtection(mechanism pkicmp.ProtectionMechanism) Option {
	return func(c *Client) { c.responseProtection = mechanism }
}

// WithExtraCerts sets extra certificates to include in requests.
func WithExtraCerts(certs []*x509.Certificate) Option {
	return func(c *Client) { c.extraCerts = certs }
}

// WithTrustedCAs sets the trusted CA pool used to verify responses and issued
// certificates. Signature-protected responses need it (RFC 9810 §8.9).
//
// A shared-secret enrollment can succeed without a pool, since the MAC provides
// authenticity and caPubs may then be trusted as roots (RFC 9810 §5.3.2), which
// is how a device gets its first anchor. Configure one anyway when an anchor is
// available: error messages are signed however the request was protected
// (RFC 9810 §5.3.21), so without a pool a rejection such as transactionIdInUse
// arrives unverifiable, as an [UnverifiedStatusError]. Some CAs sign every
// response, which a client with no anchor cannot complete at all.
//
// A CA with a composite ML-DSA key is trusted as an issuer only when the
// response also carries its certificate in extraCerts or caPubs. The pool
// entry still decides whether that certificate is trusted.
func WithTrustedCAs(trustedCAs *x509.CertPool) Option {
	return func(c *Client) { c.trustedCAs = trustedCAs }
}

// WithServerCerts sets CMP protection certificates of the server that the
// caller knows out of band, like the -srvcert option of openssl cmp.
//
// Use it for a CA that signs a response without attaching its protection
// certificate in extraCerts. RFC 9483 §3.3 requires the certificate on the
// first response of an operation, but RFC 9810 §5.1 makes extraCerts optional
// and some CAs leave it out of revocation responses. Pass the certificate the
// CA signs its responses with, often the issuing CA certificate. Without it
// such a response fails with [pkicmp.ReasonNoCandidateSigner].
//
// The certificates are tried only after those the response carries and the
// one authenticated earlier in the operation. Unlike -srvcert they are not
// trusted directly: each must still chain to [WithTrustedCAs], match the
// sender in the response header and verify the signature. As with extraCerts,
// a keyUsage extension without digitalSignature is accepted. Nil entries are
// ignored.
func WithServerCerts(certs []*x509.Certificate) Option {
	certs = slices.DeleteFunc(slices.Clone(certs), func(cert *x509.Certificate) bool { return cert == nil })
	return func(c *Client) { c.serverCerts = certs }
}

// WithSHA1Signatures accepts responses signed with sha1WithRSAEncryption or
// ecdsa-with-SHA1, which RFC 4210 era CAs may still use.
//
// RFC 9481 §7.1 deprecates SHA-1, so such responses fail verification by
// default. The option covers only the message signature: the signer
// certificate and the issued certificate are still validated by crypto/x509,
// which rejects SHA-1 certificate signatures.
func WithSHA1Signatures() Option {
	return func(c *Client) { c.allowSHA1Signatures = true }
}

// WithSenderKIDMismatch accepts a signed response whose senderKID names none
// of the candidate signer certificates, by trying all of them.
//
// RFC 9483 §3.1 requires senderKID to hold the subject key identifier of the
// certificate that signed the response, but some CAs copy the senderKID of the
// request instead. Such a response fails with [pkicmp.ReasonSenderKIDMismatch]
// by default. The candidates are those the response carries, the one
// authenticated earlier in the operation and [WithServerCerts]. Each must
// still chain to [WithTrustedCAs], match the sender in the response header and
// verify the signature. See [pkicmp.VerifyOptions.AllowSenderKIDMismatch].
func WithSenderKIDMismatch() Option {
	return func(c *Client) { c.allowKIDMismatch = true }
}

// WithoutCAPubsTrust keeps caPubs from extending [WithTrustedCAs], so an issued
// certificate must chain to the configured trusted CAs.
//
// By default the CA certificates in caPubs of a MAC-protected response are
// trusted as roots for the rest of the operation (RFC 9810 §5.3.2), which is
// how a device gets its first anchor. RFC 9483 §4.1 leaves it to the end
// entity whether the sender may install new anchors. Use this option when the
// anchors are known out of band. caPubs are still returned in
// [EnrollResult.CAPubs] and may serve as intermediates. Without a trusted CA
// pool the issued certificate of a MAC-protected response is then accepted
// unverified, as when the response carries no caPubs.
func WithoutCAPubsTrust() Option {
	return func(c *Client) { c.ignoreCAPubsTrust = true }
}

// WithMACIterationLimits sets the range of PasswordBasedMac and PBMAC1
// iteration counts accepted in MAC-protected responses. The defaults are
// [pkicmp.DefaultMinMACIterationCount] and [pkicmp.DefaultMaxMACIterationCount].
// Zero selects a default and a maximum below the minimum is raised to it.
//
// Requests are not affected. To send a count outside the defaults, set it on
// the credentials with [pkicmp.WithMACIterationCount] and widen
// [pkicmp.WithMACIterationLimits] to match.
func WithMACIterationLimits(minimum, maximum int) Option {
	return func(c *Client) {
		c.minMACIterations = minimum
		c.maxMACIterations = maximum
	}
}

// WithMaxResponseBytes sets the maximum number of bytes accepted from a CMP
// HTTP response body. Set to 0 or a negative value to disable the limit.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) { c.maxResponseBytes = n }
}

// WithMaxPolls sets the maximum number of poll attempts. Total polling time is
// this many server-chosen checkAfter intervals, so prefer a context deadline to
// bound an operation.
func WithMaxPolls(n int) Option {
	return func(c *Client) { c.maxPolls = n }
}

// WithCheckAfterLimits clamps the server-provided checkAfter into a range.
// Defaults are [DefaultMinCheckAfter] and [DefaultMaxCheckAfter].
//
// checkAfter is an unbounded peer-chosen integer: unclamped it can park the
// operation indefinitely or overflow into a tight request loop. Lowering the
// maximum polls sooner than RFC 9810 §5.3.22 says to wait, so do it only for a
// CA known to issue quickly.
//
// A negative bound becomes zero and a maximum below the minimum is raised to it.
// Both zero polls as fast as the server asks.
func WithCheckAfterLimits(minimum, maximum time.Duration) Option {
	return func(c *Client) {
		if minimum < 0 {
			minimum = 0
		}
		if maximum < minimum {
			maximum = minimum
		}
		c.minCheckAfter = minimum
		c.maxCheckAfter = maximum
	}
}

// EnrollResult holds the result of a successful enrollment.
type EnrollResult struct {
	// Certificate is the issued end-entity certificate from the server.
	Certificate *x509.Certificate
	// CAPubs contains CA certificates from the caPubs field of the response (RFC 9810 §5.3.4).
	CAPubs []*x509.Certificate
	// ExtraCertificates contains certificates from the PKIMessage extraCerts field (RFC 9810 §5.1).
	ExtraCertificates []*x509.Certificate
	// ImplicitConfirm is true when the CA granted implicit confirmation, so the
	// transaction ended with the certificate response and no certConf was sent.
	ImplicitConfirm bool
	// Pending holds the transaction state when [WithDeferredPolling] stopped the
	// call at an answer with status waiting. The other fields are then empty.
	Pending *PendingEnrollment
}
