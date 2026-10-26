package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Handler processes CMP messages.
type Handler interface {
	HandleCMP(ctx context.Context, req *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error)
}

// HandlerFunc is an adapter to allow ordinary functions as Handlers.
type HandlerFunc func(context.Context, *pkicmp.PKIMessage, *SenderIdentity) (*Response, error)

func (f HandlerFunc) HandleCMP(ctx context.Context, req *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	return f(ctx, req, sender)
}

// MiddlewareChain composes multiple wrapper functions into a single wrapper function.
// The first wrapper in the list is the outermost.
func MiddlewareChain(mw ...func(Handler) Handler) func(Handler) Handler {
	return func(h Handler) Handler {
		for _, wrap := range slices.Backward(mw) {
			h = wrap(h)
		}
		return h
	}
}

// Response is what the Handler returns.
type Response struct {
	Certificate *x509.Certificate
	CACerts     []*x509.Certificate
	Waiting     *WaitingResponse
	// GrantedWithMods answers grantedWithMods instead of accepted (RFC 9810 §5.2.3) for a
	// certificate that differs from the request, such as one without a requested extension.
	GrantedWithMods bool
	// StatusText is sent as the statusString of an issued certificate, for example to name
	// what the CA changed. Clients may show it to a person.
	StatusText string
	// GeneralResponse holds the items of the genp that answers a general
	// message (RFC 9810 §5.3.20). Other requests ignore it.
	GeneralResponse []pkicmp.InfoTypeAndValue
	// IssueRef is an opaque value set by the CA during issuance and passed back
	// to [CertificateConfirmer.ConfirmCertificate] when the certificate is
	// confirmed, rejected, or expires. Use it to correlate the confirmation
	// with the original issuance (e.g., a database row ID or job reference):
	//
	//     return &server.Response{
	//         Certificate: cert,
	//         IssueRef:    dbRowID,
	//     }, nil
	IssueRef any
}

// SenderIdentity represents the authenticated message sender.
type SenderIdentity struct {
	// Certificate is set when the request was signature-protected.
	Certificate *x509.Certificate
	// Sender is the DN from the PKIHeader sender field. May be empty (NULL-DN)
	// for initial enrollment with MAC protection.
	//
	// For a signature-protected request this is the subject of Certificate,
	// because RFC 9483 §3.5 requires the two to agree and verification rejects
	// the message otherwise. A CA may therefore authorize on this name. For a
	// MAC-protected request the name is whatever resolved the shared secret,
	// so authorize on SenderKID or on the name the secret is registered to.
	Sender pkix.Name
	// SenderKID is the reference number from MAC-protected requests.
	SenderKID []byte
	// MACVerified is true when protection was verified via shared secret.
	MACVerified bool
	// RA identifies the registration authority that forwarded the request in a
	// nested message, once [RAAuthorizer] accepted it. It is nil for a request
	// sent directly.
	RA *SenderIdentity

	// secret is the verified shared secret, cached to avoid redundant lookups
	// when protecting the response.
	secret []byte

	// protectionParams captures the decoded MAC parameters from the verified
	// request, used to protect responses with the same algorithm suite.
	protectionParams pkicmp.MACCredentialOption
}

// credentialID returns a hash identifying the credentials used for protection.
// Used to verify that follow-up messages use the same credentials per RFC 9483 §3.2.
func (s *SenderIdentity) credentialID() ([]byte, error) {
	switch {
	case s.MACVerified:
		// The identity is the shared secret itself, not the senderKID and sender
		// name that selected it. The peer chooses those fields and a lookup may
		// ignore one of them, so deriving the identity from them would let one
		// secret mint a fresh identity, with a fresh per-credential quota, for
		// every sender name. An HMAC keyed with the secret does not reveal it,
		// and clients that share a secret share one identity, which is what
		// RFC 9483 §3.2 means by the same credentials.
		if len(s.secret) == 0 {
			return nil, errors.New("no shared secret in SenderIdentity")
		}
		mac := hmac.New(sha256.New, s.secret)
		mac.Write([]byte("cmp-mac"))
		return mac.Sum(nil), nil
	case s.Certificate != nil:
		sum := sha256.Sum256(s.Certificate.Raw)
		return sum[:], nil
	default:
		return nil, errors.New("no credentials in SenderIdentity")
	}
}

// WaitingResponse tells the server to respond with "waiting" status.
type WaitingResponse struct {
	CheckAfter time.Duration
	Reason     string
	PollRef    string // Opaque reference for CA to identify pending request on poll
}

// RequestType identifies the CMP operation type.
type RequestType int

const (
	RequestIR    RequestType = 0 // Initialization Request
	RequestCR    RequestType = 2 // Certification Request
	RequestP10CR RequestType = 4 // PKCS#10 Certification Request
	RequestKUR   RequestType = 7 // Key Update Request
)

// String returns a human-readable name for the request type.
func (r RequestType) String() string {
	switch r {
	case RequestIR:
		return "IR"
	case RequestCR:
		return "CR"
	case RequestP10CR:
		return "P10CR"
	case RequestKUR:
		return "KUR"
	default:
		return fmt.Sprintf("RequestType(%d)", int(r))
	}
}
