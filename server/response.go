package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// buildResponse creates a protected response with the request's transaction and nonce context.
func (s *Server) buildResponse(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity) *pkicmp.PKIMessage {
	return s.buildResponseInternal(req, body, sender, nil, nil)
}

// buildResponseWithEchoProtection creates a protected response echoing the request's MAC parameters.
func (s *Server) buildResponseWithEchoProtection(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity, protectionParams pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	return s.buildResponseInternal(req, body, sender, nil, protectionParams)
}

// Echo transactionID and senderNonce as recipNonce and generate a fresh senderNonce
// per RFC 9810 section 5.1.1.
func (s *Server) buildResponseInternal(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity, generalInfo []pkicmp.InfoTypeAndValue, protectionParams pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	senderNonce := make([]byte, 16)
	_, _ = rand.Read(senderNonce)

	senderName := pkicmp.GeneralName{}
	if len(s.cfg.sender.CommonName) > 0 || len(s.cfg.sender.Organization) > 0 {
		senderName = pkicmp.NewDirectoryName(s.cfg.sender)
	} else if s.cfg.signerCert != nil {
		// Use RawSubject to preserve the original DER encoding (e.g., PrintableString
		// vs UTF8String) from the certificate, avoiding re-encoding through pkix.Name.
		senderName = pkicmp.NewDirectoryNameFromRawDER(s.cfg.signerCert.RawSubject)
	}

	resp := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			PVNO:          req.Header.PVNO,
			Sender:        senderName,
			Recipient:     req.Header.Sender,
			MessageTime:   time.Now(),
			TransactionID: req.Header.TransactionID,
			SenderNonce:   senderNonce,
			RecipNonce:    req.Header.SenderNonce,
			GeneralInfo:   generalInfo,
		},
		Body: body,
	}

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

// buildErrorResponse creates an error response message. Pass the authenticated
// sender whenever there is one: RFC 9483 §3.1 keeps one protection mechanism per
// operation, and a shared-secret client with no trust anchor cannot verify a
// signed error. Pass nil for errors raised before authentication.
func (s *Server) buildErrorResponse(req *pkicmp.PKIMessage, sender *SenderIdentity, si pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
	return s.buildResponse(req, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: si}), sender)
}

// buildRevRepResponse creates an rp with one status for the single revocation requested.
func (s *Server) buildRevRepResponse(req *pkicmp.PKIMessage, si pkicmp.PKIStatusInfo, sender *SenderIdentity) *pkicmp.PKIMessage {
	return s.buildResponse(req, pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{si}}), sender)
}

// buildCertRepResponseForType creates a CertRepMessage with the specified response type.
func (s *Server) buildCertRepResponseForType(req *pkicmp.PKIMessage, certReqID int64, si pkicmp.PKIStatusInfo, cert *x509.Certificate, caCerts []*x509.Certificate, sender *SenderIdentity, reqType RequestType, protectionParams ...pkicmp.MACCredentialOption) *pkicmp.PKIMessage {
	certResp := pkicmp.CertResponse{
		CertReqID: certReqID,
		Status:    si,
	}

	if cert != nil && si.Status == pkicmp.StatusAccepted {
		certResp.CertifiedKeyPair = &pkicmp.CertifiedKeyPair{
			CertOrEncCert: pkicmp.CertOrEncCert{
				Certificate: &pkicmp.CMPCertificate{Raw: cert.Raw},
			},
		}
	}

	rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{certResp}}

	for _, ca := range caCerts {
		rep.CAPubs = append(rep.CAPubs, pkicmp.CMPCertificate{Raw: ca.Raw})
	}

	// Select response body type: ir→ip, cr→cp, kur→kup, p10cr→cp.
	var body *pkicmp.PKIBody
	switch reqType {
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
	if s.cfg.implicitConfirm && requestHasImplicitConfirm(req) {
		generalInfo = append(generalInfo, pkicmp.ImplicitConfirmInfoValue())
	} else if s.cfg.confirmWait > 0 && si.Status == pkicmp.StatusAccepted {
		generalInfo = append(generalInfo, pkicmp.ConfirmWaitTimeInfoValue(s.cfg.confirmWait))
	}

	return s.buildResponseInternal(req, body, sender, generalInfo, func() pkicmp.MACCredentialOption {
		if len(protectionParams) > 0 {
			return protectionParams[0]
		}
		return nil
	}())
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

	certReqID := certReqIDFromRequest(msg)
	reqType := requestTypeFromBody(msg.Body.Type)

	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		// RFC 9810 §5.3.21: Use error body for fundamental request failures (e.g., unknown
		// algorithm in P10CR CSR) where the request cannot be processed at all.
		if si.FailInfo&pkicmp.FailBadAlg != 0 && msg.Body.Type == pkicmp.BodyTypeP10CR {
			return s.buildErrorResponse(msg, sender, si)
		}
		// Header-level validation failures (e.g., missing directoryName, missing extraCerts)
		// produce error body responses since the request was not processable.
		if si.FailInfo&pkicmp.FailBadMessageCheck != 0 {
			return s.buildErrorResponse(msg, sender, si)
		}
		return s.buildCertRepResponseForType(msg, certReqID, si, nil, nil, sender, reqType)
	}

	// Waiting response → store request type and pollRef for polling.
	if resp.Waiting != nil {
		si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}
		respMsg := s.buildCertRepResponseForType(msg, certReqID, si, nil, nil, sender, reqType)
		if !s.setPending(
			credID, txnID, reqType, resp.Waiting.PollRef,
			respMsg.Header.SenderNonce, resp.Waiting.CheckAfter, time.Time{},
		) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
			})
		}
		return respMsg
	}

	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	protectionParams := sender.protectionParams
	respMsg := s.buildCertRepResponseForType(
		msg, certReqID, si, resp.Certificate, resp.CACerts, sender, reqType, protectionParams,
	)

	if resp.Certificate != nil {
		if s.cfg.implicitConfirm && requestHasImplicitConfirm(msg) {
			// Mark the transaction completed but keep it in the table until
			// cleanupExpired runs, so the transactionID cannot be reused within
			// the same confirmWaitTime window (RFC 9483 §3.5).
			s.setCompleted(credID, txnID)
			if s.cfg.confirmer != nil {
				_ = s.cfg.confirmer.ConfirmCertificate(ctx, resp.Certificate, ConfirmImplicit, resp.IssueRef)
			}
		} else if !s.setIssued(
			credID, txnID, reqType, certReqID, resp.Certificate, resp.IssueRef,
			respMsg.Header.SenderNonce, msg.Header.SenderNonce, protectionParams, msg.Header.ProtectionAlg,
		) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailTransactionIdInUse,
			})
		}
	}

	return respMsg
}

// handlePollReq resumes pending certificate requests through the configured handler.
func (s *Server) handlePollReq(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	pollReq, err := msg.Body.PollReq()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	var certReqID int64
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
	if len(msg.Header.RecipNonce) == 0 {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !bytes.Equal(msg.Header.RecipNonce, pending.senderNonce) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}

	if !pending.lastPollTime.IsZero() && time.Since(pending.lastPollTime) < pending.checkAfter {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"polling too frequently"},
		})
	}

	ctx = contextWithPollRef(ctx, pending.pollRef)

	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		return s.buildErrorResponse(msg, sender, si)
	}

	// Still waiting → update pollRef and respond with PollRep.
	if resp.Waiting != nil {
		checkAfter := max(int64(resp.Waiting.CheckAfter/time.Second), 1)
		item := pkicmp.PollRepItem{CertReqID: certReqID, CheckAfter: checkAfter}
		if resp.Waiting.Reason != "" {
			item.Reason = pkicmp.PKIFreeText{resp.Waiting.Reason}
		}
		pollRep := pkicmp.PollRepContent{item}
		respMsg := s.buildResponse(msg, pkicmp.NewPollRepBody(&pollRep), sender)
		if !s.setPending(
			credID, txnID, pending.reqType, resp.Waiting.PollRef,
			respMsg.Header.SenderNonce, resp.Waiting.CheckAfter, time.Now(),
		) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
			})
		}
		return respMsg
	}

	// Certificate ready → respond with ip/cp/kup matching original request type.
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	respMsg := s.buildCertRepResponseForType(msg, certReqID, si, resp.Certificate, resp.CACerts, sender, pending.reqType)

	if resp.Certificate != nil {
		if s.cfg.implicitConfirm && requestHasImplicitConfirm(msg) {
			// Mark the transaction completed but keep it in the table until
			// cleanupExpired runs, so the transactionID cannot be reused within
			// the same confirmWaitTime window (RFC 9483 §3.5).
			s.setCompleted(credID, txnID)
			if s.cfg.confirmer != nil {
				_ = s.cfg.confirmer.ConfirmCertificate(ctx, resp.Certificate, ConfirmImplicit, resp.IssueRef)
			}
		} else if !s.setIssued(
			credID, txnID, pending.reqType, certReqID, resp.Certificate, resp.IssueRef,
			respMsg.Header.SenderNonce, msg.Header.SenderNonce, sender.protectionParams, msg.Header.ProtectionAlg,
		) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailTransactionIdInUse,
			})
		}
	}
	return respMsg
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
