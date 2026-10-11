package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

	// headerSender is the sender field of a MAC-protected message, which
	// together with SenderKID names the shared secret.
	headerSender pkicmp.GeneralName
}

// credentialID returns a hash identifying the credentials used for protection.
// Used to verify that follow-up messages use the same credentials per RFC 9483 §3.2.
func (s *SenderIdentity) credentialID() ([]byte, error) {
	h := sha256.New()
	switch {
	case s.MACVerified:
		// SecretLookup may find the secret by senderKID, by the sender name or by
		// both. RFC 4210 §5.1.1 tells a sender whose name identifies the secret
		// to omit senderKID. Keying on senderKID alone would give all such
		// clients one identity. RFC 4210 Appendix D.4 keeps both fields the same
		// for the whole transaction. The prefix keeps this input apart from a
		// certificate, whose DER encoding starts with a SEQUENCE tag.
		h.Write([]byte("cmp-mac"))
		writeLengthPrefixed(h, s.SenderKID)
		writeLengthPrefixed(h, senderNameKey(s.headerSender))
	case s.Certificate != nil:
		h.Write(s.Certificate.Raw)
	default:
		return nil, errors.New("no credentials in SenderIdentity")
	}
	return h.Sum(nil), nil
}

// senderNameKey returns a stable encoding of a header sender for credential binding.
func senderNameKey(name pkicmp.GeneralName) []byte {
	// The decoded form lets a directory name match however its strings are
	// encoded, as SecretLookup sees it. Other GeneralName variants, including
	// the NULL-DN, are compared by their DER encoding.
	if len(name.DirectoryName) > 0 {
		return []byte("dn:" + name.DirectoryName.String())
	}
	return name.Raw
}

// writeLengthPrefixed writes b preceded by its length, so that adjacent fields cannot run into each other.
func writeLengthPrefixed(w io.Writer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b))) // #nosec G115 -- header fields are bounded by MaxRequestBodySize
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
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
