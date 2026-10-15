package server

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// MaxRequestBodySize limits the size of incoming CMP request bodies to prevent DoS.
var MaxRequestBodySize int64 = 1 << 20 // 1 MiB

// Server implements http.Handler for CMP over HTTP as specified by RFC 9811 Section 3.
type Server struct {
	handler Handler
	cfg     serverConfig
	*transactionTracker
}

// New creates a CMP server with the given handler and options.
// NOTE: A signer SHOULD be configured (WithSigner) for RFC 9810 compliance,
// as error messages MUST be signature-protected per RFC 9810 §5.3.21.
func New(handler Handler, opts ...Option) *Server {
	s := &Server{handler: handler}
	for _, o := range opts {
		o(&s.cfg)
	}
	if s.cfg.confirmWait == 0 {
		s.cfg.confirmWait = 10 * time.Second
	}
	if s.cfg.waitingLifetime == 0 {
		s.cfg.waitingLifetime = defaultWaitingLifetime
	}
	maxTxn := s.cfg.maxTransactions
	if maxTxn == 0 {
		maxTxn = 10000
	}
	maxPerCred := s.cfg.maxTransactionsPerCredential
	if maxPerCred == 0 {
		maxPerCred = 100
	}
	s.transactionTracker = newTransactionTracker(maxTxn, maxPerCred)

	// Build the signing credentials once so a key that does not match its
	// certificate is caught here rather than silently dropping protection from
	// every response.
	if s.cfg.signerKey != nil || s.cfg.signerCert != nil {
		s.cfg.signerCreds, s.cfg.signerErr = pkicmp.NewSignatureCredentials(
			s.cfg.signerKey, s.cfg.signerCert, s.cfg.signerChain...,
		)
	}
	return s
}

// Err reports a configuration error detected by [New], such as a signer key that
// does not match its certificate. A server with a non-nil Err answers every
// request with systemFailure, so callers should check it at startup.
func (s *Server) Err() error { return s.cfg.signerErr }

// isCMPMediaType reports whether a Content-Type value identifies the CMP media type.
func isCMPMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/pkixcmp"
}

// ServeHTTP implements http.Handler according to RFC 9811 Section 3.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// RFC 9811 Section 3.1: Only POST is allowed.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// RFC 9811 Section 3.2: Content-Type must identify application/pkixcmp.
	if ct := r.Header.Get("Content-Type"); !isCMPMediaType(ct) {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	msg, err := pkicmp.ParsePKIMessage(body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	resp := s.processMessage(r.Context(), msg)

	respDER, err := resp.MarshalBinary()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkixcmp")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

// processMessage handles a parsed PKIMessage and returns a response.
func (s *Server) processMessage(ctx context.Context, msg *pkicmp.PKIMessage) *pkicmp.PKIMessage {
	return s.process(ctx, msg, nil)
}

// process verifies and answers a request, which fwd carried inside a nested message when it is not nil.
//
// A forwarded request passes the same checks as one sent directly, so the end
// entity is still authenticated by its own protection and the response is
// protected for it.
func (s *Server) process(ctx context.Context, msg *pkicmp.PKIMessage, fwd *forwarding) *pkicmp.PKIMessage {
	// A signer that New rejected cannot protect anything. Refuse before the CA
	// issues a certificate that could never be delivered.
	if s.cfg.signerErr != nil {
		return s.buildErrorResponse(msg, nil, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailSystemFailure,
			StatusString: pkicmp.PKIFreeText{"server misconfigured"},
		})
	}

	// RFC 9810 §7: Validate PVNO.
	if msg.Header.PVNO < pkicmp.PVNO2 || msg.Header.PVNO > pkicmp.PVNO3 {
		resp := s.buildErrorResponse(msg, nil, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailUnsupportedVersion,
			StatusString: pkicmp.PKIFreeText{fmt.Sprintf("unsupported pvno %d", msg.Header.PVNO)},
		})
		// RFC 9810 §7: Use the closest supported PVNO in the error response.
		if msg.Header.PVNO > pkicmp.PVNO3 {
			resp.Header.PVNO = pkicmp.PVNO3
		} else if msg.Header.PVNO < pkicmp.PVNO2 {
			resp.Header.PVNO = pkicmp.PVNO2
		}
		return resp
	}

	// RFC 9810 §5.1.1: Verify that the recipient matches the server's identity.
	if err := s.verifyRecipient(msg); err != nil {
		resp := s.buildErrorResponse(msg, nil, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{err.Error()},
		})
		return resp
	}

	// Verify message protection.
	sender, err := s.verifyProtection(msg)
	if err != nil {
		// RFC 9810 §5.2.3 defines badAlg for an unsupported algorithm, which
		// tells a legacy peer why it failed. Every other failure stays
		// badMessageCheck.
		failInfo := pkicmp.FailBadMessageCheck
		var srvErr *Error
		if errors.As(err, &srvErr) && srvErr.FailureInfo == pkicmp.FailBadAlg {
			failInfo = pkicmp.FailBadAlg
		}
		resp := s.buildErrorResponse(msg, nil, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     failInfo,
			StatusString: pkicmp.PKIFreeText{err.Error()},
		})
		return resp
	}

	if s.cfg.strictProfile {
		if err := validateProfileSender(msg, sender); err != nil {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadMessageCheck,
				StatusString: pkicmp.PKIFreeText{err.Error()},
			})
		}
		if err := validateProfileExtraCerts(msg, sender); err != nil {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadMessageCheck,
				StatusString: pkicmp.PKIFreeText{err.Error()},
			})
		}
		if err := validateProfilePOP(msg); err != nil {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadPOP,
				StatusString: pkicmp.PKIFreeText{err.Error()},
			})
		}
		if err := validateProfileGenM(msg); err != nil {
			return s.buildErrorResponse(msg, sender, errorToStatusInfo(err))
		}
	}

	// RFC 9483 §5.2.2.1: other header fields of a nested message can be
	// ignored, so it skips the header validation below. The forwarded request
	// gets it instead.
	if msg.Body.Type == pkicmp.BodyTypeNested {
		return s.handleNested(ctx, msg, sender)
	}
	if fwd != nil {
		sender.RA = fwd.ra
		if err := s.cfg.raAuthorizer.AuthorizeRA(ctx, fwd.ra, msg, sender); err != nil {
			return s.buildErrorResponse(fwd.msg, fwd.ra, errorToStatusInfo(err))
		}
	}

	// RFC 9483 §4.1: Validate header fields.
	if err := s.validateHeader(msg, sender); err != nil {
		if srvErr, ok := errors.AsType[*Error](err); ok {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       srvErr.Status,
				FailInfo:     srvErr.FailureInfo,
				StatusString: pkicmp.PKIFreeText{srvErr.StatusText},
			})
		}
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	ctx = contextWithPolicyConfig(ctx, s.policyConfig())
	if s.cfg.rawSubject {
		ctx = contextWithRawSubject(ctx)
	}

	// Dispatch by body type.
	var resp *pkicmp.PKIMessage
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		resp = s.handleCertRequest(ctx, msg, sender)
	case pkicmp.BodyTypeCertConf:
		resp = s.handleCertConf(ctx, msg, sender)
	case pkicmp.BodyTypePollReq:
		resp = s.handlePollReq(ctx, msg, sender)
	case pkicmp.BodyTypeRR:
		resp = s.handleRevocation(ctx, msg, sender)
	case pkicmp.BodyTypeGenM:
		resp = s.handleGenM(ctx, msg, sender)
	case pkicmp.BodyTypeError:
		// RFC 9810 §5.3.21: Respond with PKIConf. Protection verification above
		// already catches invalid headers, so reaching here means the header is valid.
		resp = s.buildResponse(msg, pkicmp.NewPKIConfBody(), sender)
	default:
		// Clients probe with general messages, so the text says why they fail.
		resp = s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"message type not supported"},
		})
	}
	return resp
}

// policyConfig returns the settings for request checks inside handlers.
// WithStrictProfileValidation clears every option that relaxes an RFC 9483 rule.
func (s *Server) policyConfig() policyConfig {
	relaxed := !s.cfg.strictProfile
	return policyConfig{
		allowSHA1Signatures:      s.cfg.allowSHA1Signatures,
		allowPoposkInputVariants: s.cfg.allowPoposkInputVariants && relaxed,
		minMACIterationCount:     s.cfg.minMACIterationCount,
		maxMACIterationCount:     s.cfg.maxMACIterationCount,
		optionalSubject:          s.cfg.optionalSubject && relaxed,
		optionalRevocationReason: s.cfg.optionalRevocationReason && relaxed,
		optionalRevocationIssuer: s.cfg.optionalRevocationIssuer && relaxed,
		macRevocation:            s.cfg.macRevocation && relaxed,
		signatureProtectionPOP:   s.cfg.signatureProtectionPOP && relaxed,
	}
}

// defaultWaitingLifetime is how long a waiting request stays without a poll unless
// [WithWaitingLifetime] says otherwise.
const defaultWaitingLifetime = 24 * time.Hour

// CleanupExpired removes transactions idle for longer than the configured
// confirmWaitTime (default 10s) and waiting requests whose client has not
// polled within the waiting lifetime (default 24h). Call this periodically.
//
// If the CA implements [CertificateConfirmer], it is notified with
// [ConfirmExpired] for each issued certificate that timed out without
// receiving a certConf message. A [WaitingExpirer] hears about each waiting
// request removed.
func (s *Server) CleanupExpired() {
	expired := s.transactionTracker.cleanupExpired(s.cfg.confirmWait, s.cfg.waitingLifetime)
	if s.cfg.confirmer != nil {
		for _, e := range expired.issued {
			_ = s.cfg.confirmer.ConfirmCertificate(context.Background(), e.cert, ConfirmExpired, e.issueRef)
		}
	}
	if s.cfg.waitingExpirer != nil {
		for _, pollRef := range expired.waiting {
			s.cfg.waitingExpirer.ExpireWaiting(context.Background(), pollRef)
		}
	}
}

// verifyRecipient checks that the recipient field in the request matches the
// server's identity. RFC 9810 §5.1.1: the recipient field contains the name
// of the intended recipient. Validation is skipped if the server has no
// configured identity or if the recipient is a NULL-DN.
func (s *Server) verifyRecipient(msg *pkicmp.PKIMessage) error {
	// Determine server's identity name.
	var serverName pkix.Name
	switch {
	case len(s.cfg.sender.CommonName) > 0 || len(s.cfg.sender.Organization) > 0:
		serverName = s.cfg.sender
	case s.cfg.signerCert != nil:
		serverName = s.cfg.signerCert.Subject
	default:
		// No server identity is configured, so validation is skipped.
		return nil
	}

	// NULL-DN (empty RDNSequence) means the client doesn't know the server's name.
	if len(msg.Header.Recipient.DirectoryName) == 0 {
		return nil
	}

	// Compare recipient to server identity.
	var recipientName pkix.Name
	recipientName.FillFromRDNSequence(&msg.Header.Recipient.DirectoryName)

	if recipientName.String() != serverName.String() {
		return rejection(pkicmp.FailBadRequest, "recipient does not match server identity")
	}
	return nil
}

// validateHeader validates PKIHeader fields per RFC 9483 §4.1.
func (s *Server) validateHeader(msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	// Determine if this is a first message (starts a new transaction).
	isFirstMessage := isInitialRequest(msg.Body.Type)

	// RFC 4210 and RFC 9810 §5.1.1 let a client omit transactionID from the
	// first request and have the server assign one, which every later message
	// must then carry. Only RFC 9483 §3.5 requires the client to set it.
	if len(msg.Header.TransactionID) == 0 {
		if s.cfg.strictProfile || !isFirstMessage {
			return rejection(pkicmp.FailBadDataFormat, "missing transactionID")
		}
		// Protection was verified over the received header, so assigning the
		// field now only changes what the handler sees and the response echoes.
		msg.Header.TransactionID = newTransactionID()
	}

	// RFC 9483 §3.5 requires a senderNonce of at least 128 bits. RFC 4210 and
	// RFC 9810 §5.1.1 make it optional and only "typically" 128 bits. The
	// client's nonce protects the client, while follow-up messages are bound to
	// the server's own nonce through recipNonce, so the profile rule is optional.
	if s.cfg.strictProfile {
		if len(msg.Header.SenderNonce) == 0 {
			return rejection(pkicmp.FailBadSenderNonce, "missing senderNonce")
		}
		if len(msg.Header.SenderNonce) < 16 {
			return rejection(pkicmp.FailBadSenderNonce, "senderNonce too short")
		}
	}

	// RFC 9483 §3.5: a present messageTime must be close to reliable receiver
	// time when local policy enables the check. The profile leaves the threshold
	// to the use case. Presence is read from the wire, so a peer cannot skip the
	// check by sending the zero GeneralizedTime.
	if s.cfg.messageTimeTolerance > 0 && msg.Header.HasMessageTime() {
		now := time.Now()
		tolerance := s.cfg.messageTimeTolerance
		if msg.Header.MessageTime.Before(now.Add(-tolerance)) || msg.Header.MessageTime.After(now.Add(tolerance)) {
			return rejection(pkicmp.FailBadTime, "messageTime outside allowed tolerance")
		}
	}

	// RFC 9483 §4.1: recipNonce MUST NOT be present in first message.
	if isFirstMessage && len(msg.Header.RecipNonce) > 0 {
		return rejection(pkicmp.FailBadRecipientNonce, "recipNonce in first message")
	}

	// RFC 9483 §4.1: Check for duplicate transactionID (scoped to this client's credentials).
	credID, err := sender.credentialID()
	if err != nil {
		return rejection(pkicmp.FailBadMessageCheck, "invalid sender credentials")
	}
	txnID := msg.Header.TransactionID
	if isFirstMessage {
		alreadyExists, err := s.startIfAbsent(credID, txnID)
		if err != nil {
			return rejection(pkicmp.FailSystemUnavail, err.Error())
		}
		if alreadyExists {
			return rejection(pkicmp.FailTransactionIdInUse, "transactionID already in use")
		}
	}

	return nil
}

// isInitialRequest returns true if the body type starts a new transaction.
func isInitialRequest(bodyType pkicmp.BodyType) bool {
	switch bodyType {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR,
		pkicmp.BodyTypeRR, pkicmp.BodyTypeGenM:
		return true
	default:
		return false
	}
}

// validateProfilePOP applies the RFC 9483 §4.1.1 rule that a signature proof
// of possession carries no poposkInput.
func validateProfilePOP(msg *pkicmp.PKIMessage) error {
	var msgs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		msgs, err = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		msgs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		msgs, err = msg.Body.KUR()
	default:
		return nil
	}
	if err != nil {
		// The request handler reports the malformed body.
		return nil
	}
	for _, m := range *msgs {
		if m.Popo != nil && m.Popo.Signature != nil && m.Popo.Signature.PoposkInput != nil {
			return errors.New("poposkInput is not allowed in the proof of possession")
		}
	}
	return nil
}

// validateProfileSender applies the RFC 9483 §3.1 rule that a MAC-protected
// message names the shared secret in the sender field.
func validateProfileSender(msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	if sender == nil || !sender.MACVerified {
		return nil
	}
	// RFC 9483 §5.2.2.1 lets the receiver ignore the sender of a nested
	// message. Whether a MAC may protect one at all is for the RAAuthorizer.
	if msg.Body.Type == pkicmp.BodyTypeNested {
		return nil
	}
	if len(msg.Header.Sender.DirectoryName) == 0 {
		return errors.New("MAC protection requires directoryName sender")
	}
	return nil
}

// validateProfileExtraCerts applies the RFC 9483 §3.3 extraCerts rules to a signature-protected request.
func validateProfileExtraCerts(msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	if sender == nil || sender.MACVerified {
		return nil
	}
	// §3.3 allows extraCerts to be omitted in certConf, PKIConf, pollReq and
	// pollRep. §5.2.2 requires them in a nested message.
	if !isInitialRequest(msg.Body.Type) && msg.Body.Type != pkicmp.BodyTypeNested {
		return nil
	}
	if len(msg.ExtraCerts) == 0 {
		return errors.New("signature protection without extraCerts")
	}

	certs := make([]*x509.Certificate, 0, len(msg.ExtraCerts))
	for _, ec := range msg.ExtraCerts {
		parsed, err := ec.Parse()
		if err != nil {
			return errors.New("undecodable certificate in extraCerts")
		}
		certs = append(certs, parsed)
	}
	if sender.Certificate != nil && !certs[0].Equal(sender.Certificate) {
		return errors.New("first certificate in extraCerts is not the CMP protection certificate")
	}
	// §3.3 says self-signed certificates should be omitted, so the chain may end
	// below its root. Whether it reaches a trust anchor is for the
	// CertificateLookup that authenticates the signer to decide.
	for i := 0; i < len(certs)-1; i++ {
		if err := compositex509.CheckSignatureFrom(certs[i], certs[i+1]); err != nil {
			return errors.New("extraCerts is not an ordered certificate chain")
		}
	}
	return nil
}
