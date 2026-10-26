package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// buildResponse creates a protected response with the request's transaction and nonce context.
func (s *Server) buildResponse(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity) *pkicmp.PKIMessage {
	return s.buildResponseInternal(req, body, sender, nil, nil)
}

// buildResponseWithEchoProtection creates a protected response echoing the request's MAC parameters.
func (s *Server) buildResponseWithEchoProtection(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity, protectionParams pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	return s.buildResponseInternal(req, body, sender, nil, protectionParams)
}

// newResponse creates an unprotected response to req. It echoes the
// transactionID, answers the senderNonce with recipNonce and carries a fresh
// senderNonce (RFC 9810 §5.1.1). It has no senderKID and no extraCerts, which
// only serve to verify protection.
func (s *Server) newResponse(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, generalInfo []pkicmp.InfoTypeAndValue) *pkicmp.PKIMessage {
	senderNonce := make([]byte, 16)
	_, _ = rand.Read(senderNonce)

	return &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			PVNO:          req.Header.PVNO,
			Sender:        s.responseSender(),
			Recipient:     req.Header.Sender,
			MessageTime:   time.Now(),
			TransactionID: req.Header.TransactionID,
			SenderNonce:   senderNonce,
			RecipNonce:    req.Header.SenderNonce,
			GeneralInfo:   generalInfo,
		},
		Body: body,
	}
}

// buildResponseInternal creates a response and protects it for sender.
func (s *Server) buildResponseInternal(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity, generalInfo []pkicmp.InfoTypeAndValue, protectionParams pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	resp := s.newResponse(req, body, generalInfo)

	// RFC 9810 §5.1.1: senderKID names the key that protects the response.
	// protectResponseWithOptions MAC-protects the response to a MAC-protected
	// request even when a signer is configured, so that response repeats the
	// client's shared-secret reference. Clients that check it refuse the
	// signer's key identifier.
	if sender != nil && sender.MACVerified && len(sender.secret) > 0 {
		resp.Header.SenderKID = sender.SenderKID
	} else if s.cfg.signerCert != nil {
		resp.Header.SenderKID = s.cfg.signerCert.SubjectKeyId
	}

	for _, c := range s.cfg.extraCerts {
		resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: c.Raw})
	}

	if protectionParams == nil && sender != nil {
		protectionParams = sender.protectionParams
	}
	if err := s.protectResponseWithOptions(resp, sender, protectionParams); err != nil {
		// Never hand back an unprotected success. Report the failure instead, as
		// an unprotected error message (RFC 9810 §5.3.21) since protection is
		// exactly what is broken. The detail stays server-side.
		resp.Body = pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailSystemFailure,
			StatusString: pkicmp.PKIFreeText{"response protection unavailable"},
		}})
		resp.Header.ProtectionAlg = nil
		resp.Protection = nil
	}

	return resp
}

// responseSender returns the sender name of every response.
func (s *Server) responseSender() pkicmp.GeneralName {
	if len(s.cfg.sender.CommonName) > 0 || len(s.cfg.sender.Organization) > 0 {
		return pkicmp.NewDirectoryName(s.cfg.sender)
	}
	if s.cfg.signerCert != nil {
		// Use RawSubject to preserve the original DER encoding (e.g., PrintableString
		// vs UTF8String) from the certificate, avoiding re-encoding through pkix.Name.
		return pkicmp.NewDirectoryNameFromRawDER(s.cfg.signerCert.RawSubject)
	}
	return pkicmp.GeneralName{}
}

// buildErrorResponse creates an error response message. Pass the authenticated
// sender whenever there is one: RFC 9483 §3.1 keeps one protection mechanism per
// operation, and a shared-secret client with no trust anchor cannot verify a
// signed error. Pass nil for errors raised before authentication.
func (s *Server) buildErrorResponse(req *pkicmp.PKIMessage, sender *SenderIdentity, si pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
	return s.buildResponse(req, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: si}), sender)
}

// unauthenticatedError creates an error response for a request whose sender was
// not authenticated. It carries no protection when
// WithUnprotectedErrorsBeforeAuthentication is set, unless fwd reports that an
// authenticated registration authority forwarded the request: that error goes
// back to a known peer and is protected as any other.
func (s *Server) unauthenticatedError(req *pkicmp.PKIMessage, fwd *forwarding, si pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
	body := pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: si})
	if s.cfg.unprotectedPreAuthErrors && fwd == nil {
		return s.newResponse(req, body, nil)
	}
	return s.buildResponse(req, body, nil)
}

// buildRevRepResponse creates an rp with one status for the single revocation requested.
func (s *Server) buildRevRepResponse(req *pkicmp.PKIMessage, si pkicmp.PKIStatusInfo, sender *SenderIdentity) *pkicmp.PKIMessage {
	return s.buildResponse(req, pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{si}}), sender)
}

// certRep describes the single CertResponse of an ip, cp or kup.
type certRep struct {
	certReqID int64
	status    pkicmp.PKIStatusInfo
	cert      *x509.Certificate
	// encrypted carries cert instead of the plaintext certificate, for the
	// encrypted certificate proof of possession.
	encrypted *pkicmp.CertOrEncCert
	// privateKey is the DER EnvelopedData of a centrally generated private key.
	privateKey []byte
	caCerts    []*x509.Certificate
	reqType    RequestType
	// implicit reports that the client asked for implicit confirmation and may
	// be granted it. The server grants it only with a certificate, so a waiting
	// or rejected response carries none.
	implicit         bool
	protectionParams pkicmp.MACCredentialOption
}

// buildCertRep creates the ip, cp or kup that answers req, choosing the body from the request type.
func (s *Server) buildCertRep(req *pkicmp.PKIMessage, sender *SenderIdentity, r certRep) *pkicmp.PKIMessage {
	certResp := pkicmp.CertResponse{
		CertReqID: r.certReqID,
		Status:    r.status,
	}

	if r.cert != nil && grantsCertificate(r.status) {
		certOrEncCert := pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: r.cert.Raw}}
		if r.encrypted != nil {
			certOrEncCert = *r.encrypted
		}
		certResp.CertifiedKeyPair = &pkicmp.CertifiedKeyPair{CertOrEncCert: certOrEncCert}
		if r.privateKey != nil {
			certResp.CertifiedKeyPair.SetEncryptedPrivateKey(r.privateKey)
		}
	}

	rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{certResp}}

	for _, ca := range r.caCerts {
		rep.CAPubs = append(rep.CAPubs, pkicmp.CMPCertificate{Raw: ca.Raw})
	}

	// Select response body type: ir→ip, cr→cp, kur→kup, p10cr→cp.
	var body *pkicmp.PKIBody
	switch r.reqType {
	case RequestIR:
		body = pkicmp.NewIPBody(rep)
	case RequestKUR:
		body = pkicmp.NewKUPBody(rep)
	default:
		body = pkicmp.NewCPBody(rep)
	}

	// RFC 9810 §5.1.1.1: Include id-it-implicitConfirm in the response only when
	// the server is configured for implicit confirm AND the client requested it.
	// RFC 9810 §5.1.1.2: Otherwise include confirmWaitTime if configured.
	var generalInfo []pkicmp.InfoTypeAndValue
	if s.grantsImplicitConfirm(r.implicit) && grantsCertificate(r.status) {
		generalInfo = append(generalInfo, pkicmp.ImplicitConfirmInfoValue())
	} else if s.cfg.confirmWait > 0 && grantsCertificate(r.status) {
		generalInfo = append(generalInfo, pkicmp.ConfirmWaitTimeInfoValue(s.cfg.confirmWait))
	}

	return s.buildResponseInternal(req, body, sender, generalInfo, r.protectionParams)
}

// grantsImplicitConfirm reports whether the server skips confirmation when requested
// says that the client asked for implicit confirmation.
func (s *Server) grantsImplicitConfirm(requested bool) bool {
	return s.cfg.implicitConfirm && requested
}

// waitingStatus returns the status of a response that delays a request, carrying the CA's reason when it gave one.
func waitingStatus(w *WaitingResponse) pkicmp.PKIStatusInfo {
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}
	if w.Reason != "" {
		si.StatusString = pkicmp.PKIFreeText{w.Reason}
	}
	return si
}

// advertisedCheckAfter returns the CheckAfter a pollRep advertises: whole seconds, at least one.
// The server enforces the same value, so a client that waits exactly as told is never early.
func advertisedCheckAfter(d time.Duration) time.Duration {
	return time.Duration(max(int64(d/time.Second), 1)) * time.Second
}

// grantsCertificate reports whether si delivers a certificate: accepted or grantedWithMods.
func grantsCertificate(si pkicmp.PKIStatusInfo) bool {
	return si.Status == pkicmp.StatusAccepted || si.Status == pkicmp.StatusGrantedWithMods
}

// issuedStatus returns the status of a response that is not waiting, with the handler's
// grantedWithMods choice and status text.
func issuedStatus(resp *Response) pkicmp.PKIStatusInfo {
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	if resp.GrantedWithMods {
		si.Status = pkicmp.StatusGrantedWithMods
	}
	if resp.StatusText != "" {
		si.StatusString = pkicmp.PKIFreeText{resp.StatusText}
	}
	return si
}

// certRequestInfo is what the server keeps of a certificate request across its messages.
type certRequestInfo struct {
	certReqID int64
	reqType   RequestType
	// implicit reports that the client asked for implicit confirmation.
	implicit bool
	method   POPMethod
	// privateKey and generatedKey are the DER EnvelopedData of a centrally
	// generated private key and the DER SubjectPublicKeyInfo of its public key.
	privateKey   []byte
	generatedKey []byte
}

// handleCertRequest processes certificate requests through the configured handler.
func (s *Server) handleCertRequest(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID

	// RFC 9810 §5.1.1: Reject if transactionID is already pending (waiting for poll).
	if _, exists := s.getPending(credID, txnID); exists {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailTransactionIdInUse,
		})
	}

	req := certRequestInfo{
		certReqID: certReqIDFromRequest(msg),
		reqType:   requestTypeFromBody(msg.Body.Type),
		implicit:  requestHasImplicitConfirm(msg),
		method:    requestPOPMethod(msg),
	}
	ctx = contextWithPOPMethod(ctx, req.method)
	switch req.method {
	case POPChallengeResponse:
		return s.challengePossession(ctx, msg, sender, credID, req)
	case POPCentralKeyGeneration:
		return s.generateKey(ctx, msg, sender, credID, req)
	default:
		return s.issue(ctx, msg, msg, sender, credID, req)
	}
}

// issue passes the certificate request in msg to the handler and answers reply
// with the result. reply is msg itself, or the popdecr that completed the
// challenge of msg and whose header the response must answer.
func (s *Server) issue(ctx context.Context, msg, reply *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, req certRequestInfo) *pkicmp.PKIMessage {
	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		// RFC 9810 §5.3.21: Use error body for fundamental request failures (e.g., unknown
		// algorithm in P10CR CSR) where the request cannot be processed at all.
		if si.FailInfo&pkicmp.FailBadAlg != 0 && msg.Body.Type == pkicmp.BodyTypeP10CR {
			return s.buildErrorResponse(reply, sender, si)
		}
		// Header-level validation failures (e.g., missing directoryName, missing extraCerts)
		// produce error body responses since the request was not processable.
		if si.FailInfo&pkicmp.FailBadMessageCheck != 0 {
			return s.buildErrorResponse(reply, sender, si)
		}
		return s.buildCertRep(reply, sender, certRep{
			certReqID: req.certReqID, status: si, reqType: req.reqType, implicit: req.implicit,
		})
	}

	// Waiting response → keep what the final response needs for polling (RFC 9483 §4.4).
	if resp.Waiting != nil {
		respMsg := s.buildCertRep(reply, sender, certRep{
			certReqID: req.certReqID, status: waitingStatus(resp.Waiting), reqType: req.reqType, implicit: req.implicit,
		})
		if !s.setPending(credID, reply.Header.TransactionID, waitingState{
			reqType:           req.reqType,
			certReqID:         req.certReqID,
			implicitConfirm:   req.implicit,
			popMethod:         req.method,
			privateKey:        req.privateKey,
			generatedKey:      req.generatedKey,
			pollRef:           resp.Waiting.PollRef,
			senderNonce:       respMsg.Header.SenderNonce,
			clientSenderNonce: reply.Header.SenderNonce,
			checkAfter:        advertisedCheckAfter(resp.Waiting.CheckAfter),
		}) {
			return s.buildErrorResponse(reply, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
			})
		}
		return respMsg
	}
	return s.deliver(ctx, reply, sender, credID, req, resp)
}

// deliver answers reply with the certificate the CA issued and records what its
// confirmation needs. The certificate is encrypted for its own key when the
// request chose the encrypted certificate proof of possession, and such a
// request is never granted implicit confirmation, because its certConf is the
// proof. A centrally generated private key goes with the certificate that
// certifies its public key.
func (s *Server) deliver(ctx context.Context, reply *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, req certRequestInfo, resp *Response) *pkicmp.PKIMessage {
	txnID := reply.Header.TransactionID
	// undeliverable answers a certificate that exists but cannot reach its
	// holder. The CA hears that it was not accepted.
	undeliverable := func() *pkicmp.PKIMessage {
		s.setCompleted(credID, txnID)
		if s.cfg.confirmer != nil {
			_ = s.cfg.confirmer.ConfirmCertificate(ctx, resp.Certificate, ConfirmRejected, resp.IssueRef)
		}
		return s.buildCertRep(reply, sender, certRep{
			certReqID: req.certReqID,
			status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure},
			reqType:   req.reqType,
		})
	}
	r := certRep{
		certReqID:        req.certReqID,
		status:           issuedStatus(resp),
		cert:             resp.Certificate,
		caCerts:          resp.CACerts,
		reqType:          req.reqType,
		implicit:         req.implicit && req.method != POPEncryptedCertificate,
		protectionParams: sender.protectionParams,
	}
	if req.method == POPEncryptedCertificate && resp.Certificate != nil && grantsCertificate(r.status) {
		encrypted, err := encryptCertificate(resp.Certificate, reply.Header.PVNO, s.cfg.envelopedDataForVersion2)
		if err != nil {
			return undeliverable()
		}
		r.encrypted = &encrypted
	}
	if req.method == POPCentralKeyGeneration && resp.Certificate != nil && grantsCertificate(r.status) {
		if !samePublicKey(req.generatedKey, certificatePublicKey(resp.Certificate)) {
			return undeliverable()
		}
		r.privateKey = req.privateKey
	}
	respMsg := s.buildCertRep(reply, sender, r)

	if resp.Certificate != nil {
		if s.grantsImplicitConfirm(r.implicit) {
			// Mark the transaction completed but keep it in the table until
			// cleanupExpired runs, so the transactionID cannot be reused within
			// the same confirmWaitTime window (RFC 9483 §3.5).
			s.setCompleted(credID, txnID)
			if s.cfg.confirmer != nil {
				_ = s.cfg.confirmer.ConfirmCertificate(ctx, resp.Certificate, ConfirmImplicit, resp.IssueRef)
			}
		} else if !s.setIssued(credID, txnID, issuedState{
			reqType:             req.reqType,
			certReqID:           req.certReqID,
			cert:                resp.Certificate,
			issueRef:            resp.IssueRef,
			popMethod:           req.method,
			senderNonce:         respMsg.Header.SenderNonce,
			clientSenderNonce:   reply.Header.SenderNonce,
			protectionParams:    sender.protectionParams,
			protectionAlgorithm: reply.Header.ProtectionAlg,
		}) {
			return s.buildErrorResponse(reply, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailTransactionIdInUse,
			})
		}
	}

	return respMsg
}

// handlePollReq answers a pollReq for a waiting request with a pollRep or the final response (RFC 9483 §4.4).
//
// The final response repeats the senderNonce of the pollReq that collects it, as
// OpenSSL sends and checks. RFC 9483 §4.4 has the client keep the delayed
// request's nonce for this check, and the client in this module accepts either.
func (s *Server) handlePollReq(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	pollReq, err := msg.Body.PollReq()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// One request per message is supported, so -1 for the whole message and the
	// request's own certReqId refer to the same request. An empty pollReq does too.
	certReqID := int64(-1)
	if len(*pollReq) > 0 {
		certReqID = (*pollReq)[0]
	}

	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID

	// Look up pending request using composite key — automatically rejects different credentials.
	pending, ok := s.getPending(credID, txnID)
	if !ok {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"no pending certificate"},
		})
	}

	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	// WithStrictProfileValidation overrides WithOptionalPollReqRecipNonce.
	missingRecipNonce := len(msg.Header.RecipNonce) == 0
	if missingRecipNonce && (!s.cfg.optionalPollReqRecipNonce || s.cfg.strictProfile) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !missingRecipNonce && !bytes.Equal(msg.Header.RecipNonce, pending.senderNonce) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}
	// As for a certConf, a repeated senderNonce is only refused under WithStrictProfileValidation.
	if s.cfg.strictProfile && reusesSenderNonce(msg, pending.senderNonce, pending.clientSenderNonce) {
		return s.buildErrorResponse(msg, sender, senderNonceReused())
	}

	waiting := pending.waiting()
	if pending.certReqID != nil && !pollRefersTo(certReqID, waiting.certReqID) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"certReqId does not refer to the waiting request"},
		})
	}
	// A snapshot taken before the certReqId was kept leaves the pollReq to name it.
	if pending.certReqID == nil {
		waiting.certReqID = certReqID
	}

	// RFC 9483 §4.4: polling early only costs another round trip. The answer is
	// another pollRep with the time left, and the CA is not asked.
	if !pending.lastPollTime.IsZero() {
		if left := pending.checkAfter - time.Since(pending.lastPollTime); left > 0 {
			return s.answerPoll(msg, sender, credID, waiting, certReqID, (left+time.Second-1)/time.Second*time.Second, "")
		}
	}

	ctx = contextWithPollRef(ctx, pending.pollRef)
	ctx = contextWithPOPMethod(ctx, waiting.popMethod)
	if waiting.popMethod == POPCentralKeyGeneration {
		if pub, err := pkicmp.ParsePublicKey(waiting.generatedKey); err == nil {
			ctx = contextWithGeneratedPublicKey(ctx, pub)
		}
	}

	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		return s.rejectWaiting(msg, sender, credID, waiting, errorToStatusInfo(err))
	}

	// Still waiting → keep the request and respond with a pollRep.
	if resp != nil && resp.Waiting != nil {
		if resp.Waiting.PollRef != "" {
			waiting.pollRef = resp.Waiting.PollRef
		}
		waiting.lastPollTime = time.Now()
		waiting.checkAfter = advertisedCheckAfter(resp.Waiting.CheckAfter)
		return s.answerPoll(msg, sender, credID, waiting, certReqID, waiting.checkAfter, resp.Waiting.Reason)
	}

	if waiting.reqType == requestRR {
		s.setCompleted(credID, txnID)
		return s.buildRevRepResponse(msg, pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, sender)
	}
	if resp == nil || resp.Certificate == nil {
		return s.rejectWaiting(msg, sender, credID, waiting, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
		})
	}

	// Certificate ready → respond with ip/cp/kup matching original request type.
	return s.deliver(ctx, msg, sender, credID, certRequestInfo{
		certReqID:    waiting.certReqID,
		reqType:      waiting.reqType,
		implicit:     waiting.implicitConfirm,
		method:       waiting.popMethod,
		privateKey:   waiting.privateKey,
		generatedKey: waiting.generatedKey,
	}, resp)
}

// pollRefersTo reports whether the certReqId of a pollReq names the waiting request with certReqId original.
//
// RFC 9483 §4.4 polls with 0 for the CertResponse of an ip, cp or kup and -1 for
// the whole message. RFC 9810 §5.3.22 uses the CertResponse's own certReqId,
// which is -1 for a p10cr.
func pollRefersTo(certReqID, original int64) bool {
	return certReqID == original || certReqID == -1 || original == -1 && certReqID == 0
}

// answerPoll keeps a request waiting and answers its pollReq with a pollRep that asks the client to wait checkAfter.
func (s *Server) answerPoll(msg *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, waiting waitingState, certReqID int64, checkAfter time.Duration, reason string) *pkicmp.PKIMessage {
	// RFC 9483 §4.4: the pollRep repeats the certReqId of the pollReq.
	item := pkicmp.PollRepItem{CertReqID: certReqID, CheckAfter: int64(checkAfter / time.Second)}
	if reason != "" {
		item.Reason = pkicmp.PKIFreeText{reason}
	}
	pollRep := pkicmp.PollRepContent{item}
	respMsg := s.buildResponse(msg, pkicmp.NewPollRepBody(&pollRep), sender)
	waiting.senderNonce = respMsg.Header.SenderNonce
	waiting.clientSenderNonce = msg.Header.SenderNonce
	if !s.setPending(credID, msg.Header.TransactionID, waiting) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
		})
	}
	return respMsg
}

// rejectWaiting ends a waiting transaction with the rejection si, sent as the final response to the delayed request.
//
// RFC 9810 §5.3.22 lets the final response be an ip, cp or kup, which a client
// handles like an immediate one, so a rejected certificate request gets the
// same body as one refused at once. A revocation gets an rp. A problem with the
// message itself gets an error message, as for a request that did not wait.
func (s *Server) rejectWaiting(msg *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, waiting waitingState, si pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
	s.setCompleted(credID, msg.Header.TransactionID)
	switch {
	case si.FailInfo&pkicmp.FailBadMessageCheck != 0:
		return s.buildErrorResponse(msg, sender, si)
	case waiting.reqType == requestRR:
		return s.buildRevRepResponse(msg, si, sender)
	default:
		return s.buildCertRep(msg, sender, certRep{certReqID: waiting.certReqID, status: si, reqType: waiting.reqType})
	}
}

// certReqIDFromRequest extracts the certReqID from a cert request message.
func certReqIDFromRequest(msg *pkicmp.PKIMessage) int64 {
	if msg.Body.Type == pkicmp.BodyTypeP10CR {
		return -1
	}
	crmf, err := parseCRMFMsg(msg)
	if err != nil {
		return 0
	}
	return crmf.certReqID
}

// requestHasImplicitConfirm checks for id-it-implicitConfirm in generalInfo.
func requestHasImplicitConfirm(msg *pkicmp.PKIMessage) bool {
	oidImplicitConfirm := pkicmp.ImplicitConfirmInfoValue().InfoType
	for _, info := range msg.Header.GeneralInfo {
		if info.InfoType.Equal(oidImplicitConfirm) {
			return true
		}
	}
	return false
}

// requestRR is the request type of a delayed revocation request.
const requestRR = RequestType(pkicmp.BodyTypeRR & 0x1f)

// requestTypeFromBody maps a CMP body type to the handler's request type.
func requestTypeFromBody(bodyType pkicmp.BodyType) RequestType {
	switch bodyType {
	case pkicmp.BodyTypeIR:
		return RequestIR
	case pkicmp.BodyTypeCR:
		return RequestCR
	case pkicmp.BodyTypeKUR:
		return RequestKUR
	case pkicmp.BodyTypeP10CR:
		return RequestP10CR
	default:
		return RequestType(bodyType & 0x1f)
	}
}
