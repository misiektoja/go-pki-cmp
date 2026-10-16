package server

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
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
	optionalCertConfRecipNonce   bool
	optionalPollReqRecipNonce    bool
	allowSHA1Signatures          bool
	allowPoposkInputVariants     bool
	rawSubject                   bool
	optionalSubject              bool
	optionalRevocationReason     bool
	optionalRevocationIssuer     bool
	macRevocation                bool
	signatureProtectionPOP       bool
	encryptedCertPOP             bool
	envelopedDataForVersion2     bool
	challengeResponsePOP         bool
	messageTimeTolerance         time.Duration
	raAuthorizer                 RAAuthorizer
	minMACIterationCount         int                  // zero selects pkicmp.DefaultMinMACIterationCount
	maxMACIterationCount         int                  // zero selects pkicmp.DefaultMaxMACIterationCount
	confirmer                    CertificateConfirmer // set automatically by NewCAServer
	waitingLifetime              time.Duration        // zero selects defaultWaitingLifetime
	waitingExpirer               WaitingExpirer       // set by WithWaitingExpirer or NewCAServer

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
// and controls when [Server.CleanupExpired] considers transactions stale, except
// waiting requests, which [WithWaitingLifetime] governs. The default is 10
// seconds. RFC 9810 §5.1.1.2.
func WithConfirmWaitTime(d time.Duration) Option {
	return func(c *serverConfig) {
		c.confirmWait = d
	}
}

// WithWaitingLifetime sets how long a waiting request stays after its last
// message when the client stops polling. [Server.CleanupExpired] then removes
// it and tells the [WaitingExpirer]. The default is 24 hours.
//
// The lifetime counts from the waiting response or the last pollRep, so it must
// exceed the CheckAfter a CA returns. It does not limit how long a CA may take
// to decide, which is the CA's own policy: a client that keeps polling keeps
// the request. Confirmation of an issued certificate keeps using
// [WithConfirmWaitTime].
func WithWaitingLifetime(d time.Duration) Option {
	return func(c *serverConfig) {
		c.waitingLifetime = d
	}
}

// WithWaitingExpirer sets the [WaitingExpirer] that [Server.CleanupExpired]
// tells about waiting requests whose client stopped polling. [NewCAServer] sets
// it for a CA that implements the interface.
func WithWaitingExpirer(expirer WaitingExpirer) Option {
	return func(c *serverConfig) {
		c.waitingExpirer = expirer
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
// eight rejections:
//
//   - a MAC-protected message whose sender is not a directoryName naming the
//     shared secret (§3.1), unless it is a nested message (§5.2.2.1),
//   - a signature-protected request or nested message that carries no
//     extraCerts (§3.3, §5.2.2),
//   - a signature-protected request whose extraCerts do not lead with the CMP
//     protection certificate or that hold a certificate not certifying the one
//     before it (§3.3). The chain may stop below a self-signed root, which §3.3
//     recommends leaving out,
//   - a certConf whose senderNonce repeats one used earlier in the transaction (§3.1),
//   - a request without a transactionID (§3.5), which RFC 4210 and RFC 9810
//     let the server assign instead,
//   - a message whose senderNonce is missing or shorter than 128 bits (§3.5),
//     which RFC 4210 and RFC 9810 leave optional,
//   - a certConf with more than one CertStatus (§4.1.1),
//   - a CRMF request whose signature proof of possession carries poposkInput
//     (§4.1.1), even with [WithPoposkInputVariants].
//
// It also limits [WithEncryptedCertificatePOP] and [WithChallengeResponsePOP]
// to keys that cannot sign (§4.1.1).
//
// It also overrides the options that relax RFC 9483 rules:
// [WithOptionalCertConfRecipNonce], [WithPoposkInputVariants],
// [WithOptionalSubject], [WithOptionalRevocationReason],
// [WithOptionalRevocationIssuer], [WithMACRevocation] and
// [WithSignatureProtectionPOP].
//
// Off by default because deployed clients fail them: the Insta Certifier 7
// ssh-cmpclient sends a NULL-DN sender, omits its own certificate and reuses
// the senderNonce.
// RFC 4210 clients may omit the transactionID or send a shorter senderNonce.
// None of them affects authentication, which comes from senderKID or
// CertificateLookup plus recipNonce. Turn it on for a conformance suite or a
// known-conforming fleet.
func WithStrictProfileValidation() Option {
	return func(c *serverConfig) {
		c.strictProfile = true
	}
}

// WithOptionalCertConfRecipNonce accepts a certConf that carries no recipNonce.
// RFC 9810 Appendix C.4 and RFC 9483 §3.5 require certConf to repeat the
// senderNonce of the certificate response, so the server answers a certConf
// without one with badRecipientNonce by default. Use the option for clients
// that leave the field out.
//
// A recipNonce that is present must still match. The confirmation stays bound
// to the issued certificate by its protection, its transactionID and the
// certificate hash in every CertStatus, which the server checks either way.
// [WithStrictProfileValidation] refuses a certConf without recipNonce whether
// or not this option is set.
func WithOptionalCertConfRecipNonce() Option {
	return func(c *serverConfig) {
		c.optionalCertConfRecipNonce = true
	}
}

// WithOptionalPollReqRecipNonce accepts a pollReq that carries no recipNonce.
// RFC 9483 §3.1 requires every message after the first of a transaction to
// repeat the senderNonce of the previous message, so the server answers a
// pollReq without one with badRecipientNonce by default. Use the option for
// clients that leave the field out, such as the Insta Certifier 10 cmpclient
// and the Insta Certifier 7 ssh-cmpclient. Without it they cannot collect a
// certificate or a revocation that waited for a decision.
//
// A recipNonce that is present must still match. The poll stays bound to the
// waiting request by its protection, the sender's credential and its
// transactionID. Without the nonce a recorded pollReq of the same transaction
// can be sent again, which can collect the final response before the device
// does. That response holds no secret: a certificate, a refusal or an
// encrypted certificate only the requested key can read.
// [WithStrictProfileValidation] refuses a pollReq without recipNonce whether
// or not this option is set.
func WithOptionalPollReqRecipNonce() Option {
	return func(c *serverConfig) {
		c.optionalPollReqRecipNonce = true
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

// WithPoposkInputVariants accepts the signature proof of possession that the
// Insta Certifier 10 cmpclient sends with a CRMF request. It carries
// poposkInput although the template holds both the subject and the public key,
// which RFC 4211 §4.1 forbids. It also encodes the signed data and the
// publicKeyMAC differently from RFC 4211. [pkicmp.POPOptions]
// AllowPoposkInputVariants lists the variants.
//
// The server refuses such a proof with badPOP by default. With the option it
// still verifies the signature with the requested key, the publicKeyMAC with
// the shared secret that protected the request and a sender against the
// certificate that signed it. The proof then does not cover the template, so
// only the message protection binds the requested names to the key holder.
// [WithStrictProfileValidation] refuses poposkInput whether or not this option
// is set.
func WithPoposkInputVariants() Option {
	return func(c *serverConfig) {
		c.allowPoposkInputVariants = true
	}
}

// WithRawSubject sets template.RawSubject to the subject name exactly as the
// request encoded it, in a CRMF certificate template or a PKCS#10 request. The
// issued certificate then keeps every requested attribute with its order and
// string type. Without it the subject is rebuilt from pkix.Name, which drops
// attribute types pkix.Name does not model, such as domainComponent and
// emailAddress, reorders the rest and may change their string type.
//
// [x509.CreateCertificate] uses RawSubject instead of Subject. A CA that
// changes the subject must therefore clear RawSubject. A CA that checks the
// subject must check every attribute in Subject.Names, because CommonName and
// SerialNumber hold only the last value of their type and the raw name may
// repeat it. Only handlers built with [NewCAHandler] or [NewCAServer] apply the
// option.
func WithRawSubject() Option {
	return func(c *serverConfig) {
		c.rawSubject = true
	}
}

// WithOptionalSubject accepts a CRMF certificate template that leaves out the
// subject field when it requests a subjectAltName extension. RFC 9483 §4.1.1
// requires the field and lets it be a NULL-DN when subjectAltName names the
// entity, so [LightweightPolicy] accepts a NULL-DN subject without this option
// and refuses a missing one with badCertTemplate.
//
// Either way the template carries an empty subject and the requested
// subjectAltName in ExtraExtensions, marked critical as RFC 5280 §4.2.1.6
// requires. The CA must check its names.
func WithOptionalSubject() Option {
	return func(c *serverConfig) {
		c.optionalSubject = true
	}
}

// WithOptionalRevocationReason accepts a revocation request whose
// crlEntryDetails carry no reasonCode. RFC 9483 §4.2 requires one, so
// [LightweightPolicy] refuses such a request with badRequest by default. With
// the option it reaches the CA with reason unspecified, which RFC 5280 §5.3.1
// treats the same as an absent code.
func WithOptionalRevocationReason() Option {
	return func(c *serverConfig) {
		c.optionalRevocationReason = true
	}
}

// WithOptionalRevocationIssuer accepts a revocation request that names a
// serial number but no issuer. RFC 9483 §4.2 requires both, so the server
// refuses such a request with addInfoNotAvailable by default.
//
// A request signed with a certificate of that serial number revokes the
// signer's own certificate. The server fills in its issuer. Any other
// request reaches [RevocationAuthorizer] with an empty
// [RevocationRequest.RawIssuer]. The CA must then find the certificate by
// serial number and refuse the request when certificates from more than one
// issuer carry it.
func WithOptionalRevocationIssuer() Option {
	return func(c *serverConfig) {
		c.optionalRevocationIssuer = true
	}
}

// WithMACRevocation lets [LightweightPolicy] pass MAC-protected revocation
// requests to the CA. RFC 9483 §4.2 requires signature protection, so they are
// refused with wrongIntegrity by default.
//
// A shared secret proves who holds the secret, not who holds the certificate.
// Such a request therefore always goes to [RevocationAuthorizer], which must
// decide whether that secret may revoke the certificate, for example only one
// it enrolled. A CA without that interface refuses it with notAuthorized.
func WithMACRevocation() Option {
	return func(c *serverConfig) {
		c.macRevocation = true
	}
}

// WithSignatureProtectionPOP accepts a CRMF request without a proof of
// possession when its signature protection was verified with a certificate for
// the requested public key. Such a request renews a certificate for the same
// key. The protection signature proves possession of it, which RFC 4211 §4
// lets a server establish by other means. RFC 9483 §4.1 requires popo, so the
// server refuses such a request with badPOP by default.
//
// A request protected with a MAC still needs a proof of possession. So does a
// request signed with a certificate for another key.
func WithSignatureProtectionPOP() Option {
	return func(c *serverConfig) {
		c.signatureProtectionPOP = true
	}
}

// WithEncryptedCertificatePOP accepts the encrypted certificate method of proof
// of possession (RFC 9810 §5.2.8.3.2): a request whose popo is keyEncipherment
// or keyAgreement with subsequentMessage encrCert. The server returns the
// certificate in an EnvelopedData for the requested key, and the client proves
// possession by sending certConf with the hash of the decrypted certificate.
// A request with a key the server cannot encrypt for is refused with badAlg.
// See the cms package for the supported keys.
//
// EnvelopedData is cmp2021 syntax, so the response is version 3. A version 2
// request for an RSA key gets the certificate in the EncryptedValue of CMP
// version 2 instead and a version 2 response, because clients such as OpenSSL
// 3.0 and 3.2 cannot parse EnvelopedData there. Other keys have no EncryptedValue
// form. A client that sends version 2 but reads only EnvelopedData, such as one
// built on the CertificateResponse class of Bouncy Castle 1.86, must send version
// 3 for an RSA key, as RFC 9810 §7 asks of a client that expects cmp2021 syntax,
// or the server must use [WithEnvelopedDataForVersion2].
//
// Implicit confirmation is never granted to such a request. A certConf with
// another hash is refused with badPOP. Until a matching certConf arrives the
// certificate must be treated as undelivered: [CA.IssueCertificate] and
// [CertificateConfirmer.ConfirmCertificate] see the method through
// [POPMethodFromContext], and a CA should not publish the certificate before
// [ConfirmAccepted] and should revoke it on [ConfirmExpired] or [ConfirmRejected]
// (RFC 9810 §5.2.8.3.2 and §8.11).
//
// RFC 9483 §4.1.1 requires a signature proof for a key that can sign. Under
// [WithStrictProfileValidation] only an ML-KEM key may use this method.
func WithEncryptedCertificatePOP() Option {
	return func(c *serverConfig) {
		c.encryptedCertPOP = true
	}
}

// WithEnvelopedDataForVersion2 sends EnvelopedData and a version 3 response to a
// version 2 request for an RSA key that uses [WithEncryptedCertificatePOP], as
// for every other key, instead of the EncryptedValue of CMP version 2. Use it
// for clients that send version 2 but read only EnvelopedData, such as those
// built on the CertificateResponse class of Bouncy Castle 1.86. OpenSSL 3.0 and
// 3.2 clients cannot read the certificate in such a response.
func WithEnvelopedDataForVersion2() Option {
	return func(c *serverConfig) {
		c.envelopedDataForVersion2 = true
	}
}

// WithChallengeResponsePOP accepts the challenge-response method of proof of
// possession (RFC 9810 §5.2.8.3.3): a request whose popo is keyEncipherment or
// keyAgreement with subsequentMessage challengeResp. Before the request reaches
// the [Handler], the server answers it with a popdecc that encrypts a random
// number for the requested key. A popdecr with that number continues the request
// as if it had just arrived, and the response to the popdecr is the ip, cp or kup.
// A wrong number ends the transaction with badPOP, and the certificate is never
// created.
//
// The challenge waits for its answer as long as an issued certificate waits for
// certConf, see [WithConfirmWaitTime]. The same profile restriction as for
// [WithEncryptedCertificatePOP] applies.
func WithChallengeResponsePOP() Option {
	return func(c *serverConfig) {
		c.challengeResponsePOP = true
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
