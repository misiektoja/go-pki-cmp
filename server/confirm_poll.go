package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// issuedInfoContextKey passes issuance details to the handler during certConf.
type issuedInfoContextKey struct{}

// issuedInfo bundles the issued certificate and the CA's opaque IssueRef.
type issuedInfo struct {
	cert     *x509.Certificate
	issueRef any
}

// IssuedCertFromContext retrieves the issued certificate stored by the server
// during certConf processing. Handlers can use this for certHash verification.
func IssuedCertFromContext(ctx context.Context) *x509.Certificate {
	info, _ := ctx.Value(issuedInfoContextKey{}).(issuedInfo)
	return info.cert
}

// IssueRefFromContext retrieves the opaque IssueRef stored by the server
// during certConf processing. This is the value the CA set in
// [Response.IssueRef] when it issued the certificate.
func IssueRefFromContext(ctx context.Context) any {
	info, _ := ctx.Value(issuedInfoContextKey{}).(issuedInfo)
	return info.issueRef
}

// handleCertConf processes certConf messages (RFC 9810 §5.3.18).
func (s *Server) handleCertConf(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	conf, err := msg.Body.CertConf()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// RFC 9483 §4.1: Reject contradictory CertStatus entries where status is
	// accepted but failInfo bits are set.
	for _, cs := range *conf {
		if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusAccepted && cs.StatusInfo.FailInfo != 0 {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadRequest,
				StatusString: pkicmp.PKIFreeText{"accepted status with failInfo set"},
			})
		}
	}

	// Look up the issued cert entry using composite key — automatically rejects different credentials.
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID
	entry, exists := s.getIssued(credID, txnID)
	if !exists {
		// No pending transaction — reject.
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"unknown transaction"},
		})
	}

	// RFC 9483 §4.1.1: a certConf that misses confirmWaitTime is handled like
	// a rejection, also when CleanupExpired has not removed the transaction yet.
	if s.cfg.confirmWait > 0 && time.Since(entry.lastActivity) > s.cfg.confirmWait {
		if s.remove(credID, txnID, entry) && s.cfg.confirmer != nil {
			_ = s.cfg.confirmer.ConfirmCertificate(contextWithPOPMethod(ctx, entry.popMethod),
				entry.cert, ConfirmExpired, entry.issueRef)
		}
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"certConf after confirmWaitTime"},
		})
	}

	// Each CertStatus reaches the CA as a verdict on the issued certificate, so
	// every one of them must name it (RFC 9810 §5.3.18).
	if statusErr := s.checkCertStatuses(*conf, entry); statusErr != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       statusErr.Status,
			FailInfo:     statusErr.FailureInfo,
			StatusString: pkicmp.PKIFreeText{statusErr.StatusText},
		})
	}

	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	// WithStrictProfileValidation overrides WithOptionalCertConfRecipNonce.
	missingRecipNonce := len(msg.Header.RecipNonce) == 0
	if missingRecipNonce && (!s.cfg.optionalCertConfRecipNonce || s.cfg.strictProfile) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !missingRecipNonce && !bytes.Equal(msg.Header.RecipNonce, entry.issuedSenderNonce) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}

	// A repeated senderNonce is only rejected under WithStrictProfileValidation.
	// RFC 9483 §3.1 tells the sender to generate a fresh nonce, but the
	// receiver-side checks §3.5 requires are just that senderNonce is present
	// and long enough, which validateHeader applies under the same option, and
	// that recipNonce matches, which is enforced above whenever it is present.
	// Rejecting a repeat by default would discard an already-issued certificate
	// over a peer-side generation defect that deployed clients exhibit.
	// The pollReq and popdecr handlers apply the same check.
	if s.cfg.strictProfile && reusesSenderNonce(msg, entry.issuedSenderNonce, entry.clientSenderNonce) {
		return s.buildErrorResponse(msg, sender, senderNonceReused())
	}

	// RFC 9483 §4.1.1: certConf MUST use the same credentials as the first
	// request. getIssued enforces this, because the transaction is keyed by the
	// request's credential, so a certConf signed with the newly issued
	// certificate finds no transaction. The public keys are not compared,
	// because a key update may keep the signer's key.

	// Notify handler about the confirmation, passing issuance details via context.
	ctx = context.WithValue(ctx, issuedInfoContextKey{}, issuedInfo{cert: entry.cert, issueRef: entry.issueRef})
	ctx = contextWithPOPMethod(ctx, entry.popMethod)
	if _, err := s.handler.HandleCMP(ctx, msg, sender); err != nil {
		// RFC 9483 §3.6.2: an error condition on a certConf MUST be reported
		// downstream. Keep the transaction so the client can retry and so the
		// CA still gets ConfirmExpired if no retry succeeds.
		return s.buildResponseWithEchoProtection(msg, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
			PKIStatusInfo: errorToStatusInfo(err),
		}), sender, entry.protectionParams)
	}

	// Confirmation recorded — release the transaction.
	s.delete(credID, txnID)

	return s.buildResponseWithEchoProtection(msg, pkicmp.NewPKIConfBody(), sender, entry.protectionParams)
}

// checkCertStatuses verifies that every CertStatus of a certConf names the
// certificate issued in entry and that all of them agree.
func (s *Server) checkCertStatuses(statuses pkicmp.CertConfirmContent, entry *transactionEntry) *Error {
	// RFC 9483 §4.1.1 allows exactly one CertStatus. RFC 4210 and RFC 9810
	// allow one per certificate. A transaction here issues one certificate, so
	// further entries can only repeat the first.
	if s.cfg.strictProfile && len(statuses) > 1 {
		return rejection(pkicmp.FailBadRequest, "more than one CertStatus")
	}
	for i := range statuses {
		cs := &statuses[i]
		expectedHash, err := cs.CertificateHash(entry.cert)
		if err != nil {
			return rejection(pkicmp.FailBadAlg, "cannot compute certHash")
		}
		if !bytes.Equal(cs.CertHash, expectedHash) {
			// The hash of an encrypted certificate is the proof of possession
			// (RFC 9810 §5.2.8.3.1), so a wrong one fails that proof.
			if entry.popMethod == POPEncryptedCertificate {
				return rejection(pkicmp.FailBadPOP, "certHash does not match the encrypted certificate")
			}
			return rejection(pkicmp.FailBadCertId, "certHash mismatch")
		}
		if !certReqIDMatches(entry, cs.CertReqID) {
			return rejection(pkicmp.FailBadCertId, "certReqId does not match the issued certificate")
		}
		if certStatusRejects(cs) != certStatusRejects(&statuses[0]) {
			return rejection(pkicmp.FailBadRequest, "CertStatus entries disagree")
		}
	}
	return nil
}

// certReqIDMatches reports whether certReqID names the certificate issued in entry.
func certReqIDMatches(entry *transactionEntry, certReqID int64) bool {
	if entry.certReqID == nil || certReqID == *entry.certReqID {
		return true
	}
	// A p10cr carries no certReqId. RFC 9810 §5.3.4 answers it with -1, but
	// RFC 9483 §4.1.4 changes only the cp and keeps 0 from §4.1.1 for the
	// certConf. EJBCA answers a p10cr with 0. Either value can only name the
	// one certificate of the transaction, so both are accepted.
	return entry.reqType == RequestP10CR && (certReqID == 0 || certReqID == -1)
}

// certStatusRejects reports whether a CertStatus rejects its certificate, an absent statusInfo meaning acceptance.
func certStatusRejects(cs *pkicmp.CertStatus) bool {
	return cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusRejection
}

// certificatePublicKey returns the key a certificate certifies. crypto/x509
// leaves PublicKey nil for composite ML-DSA and ML-KEM keys, so those are parsed here.
func certificatePublicKey(cert *x509.Certificate) crypto.PublicKey {
	if cert.PublicKey != nil {
		return cert.PublicKey
	}
	pub, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil
	}
	return pub
}

// reusesSenderNonce reports whether msg repeats the senderNonce of response, the
// last message of the server, or of request, the client message that response
// answered. request is empty when it was not recorded.
func reusesSenderNonce(msg *pkicmp.PKIMessage, response, request []byte) bool {
	nonce := msg.Header.SenderNonce
	return bytes.Equal(nonce, response) || len(request) > 0 && bytes.Equal(nonce, request)
}

// senderNonceReused is the refusal of a message that [reusesSenderNonce] finds.
func senderNonceReused() pkicmp.PKIStatusInfo {
	return pkicmp.PKIStatusInfo{
		Status:       pkicmp.StatusRejection,
		FailInfo:     pkicmp.FailBadSenderNonce,
		StatusString: pkicmp.PKIFreeText{"senderNonce reused"},
	}
}
