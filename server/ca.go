package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- used for SKI computation (opaque identifier)
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"

	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// CA is the interface a certificate authority must implement.
type CA interface {
	// IssueCertificate signs a certificate request. The template has subject,
	// public key, extensions, and SKI populated from the CMP request.
	// SerialNumber is nil - the CA must set it.
	//
	// The CA may modify the template before signing (e.g., enforce policy on
	// validity period, add extensions). Return Response.Waiting to trigger
	// the polling flow for async issuance.
	//
	// With [WithRawSubject] the template also carries RawSubject, which
	// [x509.CreateCertificate] uses instead of Subject. Clear it before
	// changing the subject.
	//
	// A composite ML-DSA subject key arrives as *compositemldsa.PublicKey,
	// which only compositex509.CreateCertificate can certify.
	IssueCertificate(
		ctx context.Context, reqType RequestType, template *x509.Certificate, sender *SenderIdentity,
	) (*Response, error)
}

// PendingChecker is an optional interface for CAs that support async issuance.
// Implement this if IssueCertificate may return Response.Waiting.
type PendingChecker interface {
	// CheckPending checks the status of a pending certificate request.
	// pollRef is the value returned in WaitingResponse.PollRef.
	CheckPending(ctx context.Context, pollRef string, sender *SenderIdentity) (*Response, error)
}

// ConfirmStatus indicates the outcome of a certificate confirmation.
type ConfirmStatus int

const (
	// ConfirmAccepted means the client sent a certConf message accepting the certificate.
	ConfirmAccepted ConfirmStatus = iota
	// ConfirmRejected means the client sent a certConf message rejecting the certificate.
	ConfirmRejected
	// ConfirmImplicit means the server granted implicit confirm (id-it-implicitConfirm).
	// The certificate is considered accepted without a certConf round-trip.
	ConfirmImplicit
	// ConfirmExpired means the transaction timed out without receiving certConf.
	// The CA may want to revoke the certificate.
	ConfirmExpired
)

// String returns a human-readable name for the confirmation status.
func (s ConfirmStatus) String() string {
	switch s {
	case ConfirmAccepted:
		return "accepted"
	case ConfirmRejected:
		return "rejected"
	case ConfirmImplicit:
		return "implicit"
	case ConfirmExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// CertificateConfirmer is an optional interface a CA can implement to receive
// certificate confirmation notifications.
type CertificateConfirmer interface {
	// ConfirmCertificate is called when a certificate's confirmation status
	// is determined.
	//
	// The issueRef parameter is the [Response.IssueRef] value set by the CA
	// in [CA.IssueCertificate], allowing the CA to correlate the confirmation
	// with the original issuance without looking up by certificate fields.
	ConfirmCertificate(ctx context.Context, cert *x509.Certificate, status ConfirmStatus, issueRef any) error
}

// pollRefKey is the context key for passing pollRef to handlers.
type pollRefKey struct{}

// PollRefFromContext extracts the pollRef from context, if present.
// Used by handlers to detect poll requests.
func PollRefFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(pollRefKey{}).(string)
	return v, ok
}

// contextWithPollRef adds pollRef to context.
func contextWithPollRef(ctx context.Context, pollRef string) context.Context {
	return context.WithValue(ctx, pollRefKey{}, pollRef)
}

// policyConfigKey is the context key that carries the server settings for
// request checks that run inside handlers, such as [LightweightPolicy], which
// do not see the server configuration.
type policyConfigKey struct{}

// policyConfig holds the server options that change request checks. The server
// clears every relaxation under [WithStrictProfileValidation].
type policyConfig struct {
	allowSHA1Signatures      bool
	allowPoposkInputVariants bool
	minMACIterationCount     int
	maxMACIterationCount     int
	optionalSubject          bool
	optionalRevocationReason bool
	optionalRevocationIssuer bool
	macRevocation            bool
	signatureProtectionPOP   bool
}

// contextWithPolicyConfig attaches the request check settings to ctx.
func contextWithPolicyConfig(ctx context.Context, c policyConfig) context.Context {
	return context.WithValue(ctx, policyConfigKey{}, c)
}

// policyConfigFrom returns the request check settings in ctx. A context without
// settings yields the defaults.
func policyConfigFrom(ctx context.Context) policyConfig {
	c, _ := ctx.Value(policyConfigKey{}).(policyConfig)
	return c
}

// popOptions returns the proof of possession options for a request from sender
// under the settings in ctx.
func popOptions(ctx context.Context, sender *SenderIdentity) pkicmp.POPOptions {
	c := policyConfigFrom(ctx)
	opts := pkicmp.POPOptions{
		AllowSHA1Signatures:      c.allowSHA1Signatures,
		AllowPoposkInputVariants: c.allowPoposkInputVariants,
		MinMACIterationCount:     c.minMACIterationCount,
		MaxMACIterationCount:     c.maxMACIterationCount,
	}
	if sender == nil {
		return opts
	}
	if sender.MACVerified {
		opts.SharedSecret = sender.secret
	}
	// RFC 4211 §4.1 uses the sender alternative of poposkInput only for an
	// authenticated name, such as the subject of a valid certificate. A
	// MAC-protected request has none and must use publicKeyMAC.
	if sender.Certificate != nil {
		name := pkicmp.NewDirectoryNameFromRawDER(sender.Certificate.RawSubject)
		opts.Sender = &name
	}
	return opts
}

// rawSubjectKey is the context key that carries the WithRawSubject setting to
// the CA handler, which does not see the server configuration.
type rawSubjectKey struct{}

// contextWithRawSubject marks ctx so certificate templates carry the requested subject DER.
func contextWithRawSubject(ctx context.Context) context.Context {
	return context.WithValue(ctx, rawSubjectKey{}, true)
}

// rawSubjectEnabled reports whether ctx asks for the requested subject DER in certificate templates.
func rawSubjectEnabled(ctx context.Context) bool {
	v, _ := ctx.Value(rawSubjectKey{}).(bool)
	return v
}

// caHandler implements Handler by delegating to a CA.
type caHandler struct {
	ca CA
}

// NewCAHandler creates a Handler that delegates certificate issuance to a CA.
// It handles CRMF/P10CR parsing, template building, and the CMP ceremony.
// Revocation requests go to the CA when it implements [Revoker].
//
// Use with middleware for policy enforcement:
//
//	srv := server.New(
//	    server.Chain(server.NewCAHandler(ca), server.LightweightPolicy()),
//	    server.WithSigner(caKey, caCert),
//	    server.WithSecretLookup(secretLookup),
//	    server.WithCertificateLookup(certLookup),
//	)
func NewCAHandler(ca CA) Handler {
	return &caHandler{ca: ca}
}

func (h *caHandler) HandleCMP(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return h.handleCertRequest(ctx, msg, sender)
	case pkicmp.BodyTypeCertConf:
		return h.handleCertConf(ctx, msg)
	case pkicmp.BodyTypePollReq:
		return h.handlePollReq(ctx, sender)
	case pkicmp.BodyTypeRR:
		return nil, h.handleRevocation(ctx, msg, sender)
	default:
		return nil, rejection(pkicmp.FailBadRequest, "")
	}
}

func (h *caHandler) handleCertRequest(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	var subject pkix.Name
	var rawSubject []byte
	var pubKey any
	var extensions []pkix.Extension

	// Proof of possession is checked before anything reaches the CA, because a
	// server may be built without a policy wrapper and a certificate issued for
	// a key the requester does not hold is an authorization failure rather than
	// a matter of site policy.
	if err := enforceProofOfPossession(ctx, msg, sender); err != nil {
		return nil, err
	}

	switch msg.Body.Type {
	case pkicmp.BodyTypeP10CR:
		csr, err := msg.Body.P10CR()
		if err != nil {
			return nil, rejection(pkicmp.FailBadDataFormat, "")
		}
		// crypto/x509 leaves PublicKey nil for a composite ML-DSA key.
		pubKey, err = compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, rejection(pkicmp.FailBadAlg, err.Error())
		}
		subject, rawSubject, extensions = csr.Subject, csr.RawSubject, csr.Extensions
	default:
		crmf, err := parseCRMFMsg(msg)
		if err != nil {
			return nil, err
		}
		subject, rawSubject, pubKey, extensions = crmf.subject, crmf.rawSubject, crmf.publicKey, crmf.extensions
	}

	// An extension that cannot be decoded must not travel on to the CA in
	// ExtraExtensions, where a signer outside this process would interpret bytes
	// no check here has understood.
	if _, err := decodeBasicConstraints(extensions); err != nil {
		return nil, err
	}

	// Compute SubjectKeyIdentifier from public key per RFC 5280 §4.2.1.2.
	pubDER, err := compositex509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, rejection(pkicmp.FailBadAlg, err.Error())
	}
	ski := sha1.Sum(pubDER) // #nosec G401 -- SHA-1 of SPKI for SKI (opaque identifier, collision resistance not required)

	// Build template with data from the request only. The CA sets serial and
	// validity, and decides what else to honor.
	//
	// ExtraExtensions carries the extensions the requester asked for, still
	// unvetted. [x509.CreateCertificate] gives an extension here precedence over
	// the matching typed field, so assigning template.KeyUsage does not override
	// a requested keyUsage extension: it is silently dropped in favor of the
	// requested one. A CA that means to control an extension must remove it from
	// ExtraExtensions before signing. See [CA.IssueCertificate].
	template := &x509.Certificate{
		Subject:         subject,
		PublicKey:       pubKey,
		SubjectKeyId:    ski[:],
		ExtraExtensions: extensions,
	}
	// A request without a subject leaves RawSubject nil, so the CA can still
	// supply one through Subject.
	if rawSubjectEnabled(ctx) && len(rawSubject) > 0 {
		template.RawSubject = bytes.Clone(rawSubject)
	}

	reqType := bodyTypeToRequestType(msg.Body.Type)
	return h.ca.IssueCertificate(ctx, reqType, template, sender)
}

func (h *caHandler) handleCertConf(ctx context.Context, msg *pkicmp.PKIMessage) (*Response, error) {
	confirmer, ok := h.ca.(CertificateConfirmer)
	if !ok {
		return nil, nil
	}

	conf, err := msg.Body.CertConf()
	if err != nil {
		return nil, rejection(pkicmp.FailBadDataFormat, "")
	}

	// Get the issued certificate from context (set by Server.handleCertConf).
	cert := IssuedCertFromContext(ctx)
	if cert == nil {
		return nil, rejection(pkicmp.FailBadRequest, "no issued certificate")
	}

	issueRef := IssueRefFromContext(ctx)

	// The server has checked that every CertStatus names this certificate and
	// that they agree, so the CA is told once. RFC 4210 and RFC 9810 §5.3.18:
	// a certConf without a CertStatus for an issued certificate rejects it.
	status := ConfirmRejected
	if len(*conf) > 0 && !certStatusRejects(&(*conf)[0]) {
		status = ConfirmAccepted
	}
	return nil, confirmer.ConfirmCertificate(ctx, cert, status, issueRef)
}

// handlePollReq asks the CA for the result of the pending request that the pollRef in ctx identifies.
func (h *caHandler) handlePollReq(ctx context.Context, sender *SenderIdentity) (*Response, error) {
	checker, ok := h.ca.(PendingChecker)
	if !ok {
		return nil, rejection(pkicmp.FailBadRequest, "polling not supported")
	}

	pollRef, ok := PollRefFromContext(ctx)
	if !ok {
		return nil, rejection(pkicmp.FailBadRequest, "no pending certificate")
	}

	return checker.CheckPending(ctx, pollRef, sender)
}

func bodyTypeToRequestType(t pkicmp.BodyType) RequestType {
	switch t {
	case pkicmp.BodyTypeIR:
		return RequestIR
	case pkicmp.BodyTypeCR:
		return RequestCR
	case pkicmp.BodyTypeKUR:
		return RequestKUR
	case pkicmp.BodyTypeP10CR:
		return RequestP10CR
	default:
		return RequestIR
	}
}

// NewCAServer creates a complete CMP server from a CA implementation.
// The CA is responsible only for certificate issuance, and for revocation when
// it implements [Revoker]. Configure request
// verification separately with [WithSecretLookup] and/or
// [WithCertificateLookup]. Use policy enforcement wrappers (e.g., [LightweightPolicy]).
// Use [WithSigner] and [WithExtraCerts] options to configure the signing
// credentials for CMP response protection.
func NewCAServer(ca CA, policy func(Handler) Handler, opts ...Option) *Server {
	// Detect if the CA implements CertificateConfirmer so the server can
	// call it on implicit confirm (not just explicit certConf).
	if confirmer, ok := ca.(CertificateConfirmer); ok {
		opts = append([]Option{func(c *serverConfig) { c.confirmer = confirmer }}, opts...)
	}
	handler := NewCAHandler(ca)
	if policy != nil {
		handler = policy(handler)
	}
	return New(
		handler,
		opts...,
	)
}

// GenerateSerial generates a random 128-bit serial number.
// Convenience function for CA implementations.
func GenerateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
