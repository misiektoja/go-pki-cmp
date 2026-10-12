package server

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// CACertificatesProvider is an optional interface for CAs that answer CA
// certificate requests (RFC 9483 §4.3.1).
type CACertificatesProvider interface {
	// CACertificates returns the intermediate and issuing CA certificates a
	// client may need to build chains. None means no CA certificate is
	// available, which the response reports with an absent value.
	CACertificates(ctx context.Context, sender *SenderIdentity) ([]*x509.Certificate, error)
}

// RootCAUpdateProvider is an optional interface for CAs that answer root CA
// certificate update requests (RFC 9483 §4.3.2).
type RootCAUpdateProvider interface {
	// RootCAUpdate returns the update of oldRoot, or nil when none is
	// available. oldRoot is nil when the request does not name a root, and the
	// CA then decides which root the sender means.
	//
	// The update must carry NewWithOld, and the server verifies it against
	// oldRoot before sending it. A failure becomes systemFailure.
	RootCAUpdate(ctx context.Context, oldRoot *x509.Certificate, sender *SenderIdentity) (*pkicmp.RootCAKeyUpdate, error)
}

// CertReqTemplateProvider is an optional interface for CAs that answer
// certificate request template requests (RFC 9483 §4.3.3).
type CertReqTemplateProvider interface {
	// CertReqTemplate returns the template for the named certificate profile,
	// or nil when the CA imposes no requirements. profile is empty when the
	// request names none.
	CertReqTemplate(ctx context.Context, profile string, sender *SenderIdentity) (*pkicmp.CertReqTemplate, error)
}

// CRLProvider is an optional interface for CAs that answer CRL update
// requests (RFC 9483 §4.3.4) and current CRL requests (RFC 9810 §5.3.19.6).
type CRLProvider interface {
	// LatestCRL returns the latest CRL from source, or nil when the CA has
	// none. RFC 9483 §4.3.4 treats a distribution point name as a pointer to a
	// CRL the CA holds, not a location to fetch from, and
	// [pkicmp.CRLSource.DirectoryNames] lists the CA names a source carries.
	// For a CRL update the server returns the CRL only when it is newer than
	// the one the client reports holding.
	//
	// A zero source, see [pkicmp.CRLSource.IsZero], asks for the current CRL
	// of the CA's choice, for example that of the CA that issued the sender's
	// certificate.
	LatestCRL(ctx context.Context, source pkicmp.CRLSource, sender *SenderIdentity) (*x509.RevocationList, error)
}

// errNotSupported marks an info type the CA does not answer.
var errNotSupported = errors.New("info type not supported")

// handleGenM answers each item of a general message from the matching optional
// CA interface. Info types without one are listed in an unsupportedOIDs item
// (RFC 9810 §5.3.19.7), which tells the client why it got no answer.
func (h *caHandler) handleGenM(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	content, err := msg.Body.GenM()
	if err != nil {
		return nil, rejection(pkicmp.FailBadDataFormat, "malformed general message")
	}
	items := make([]pkicmp.InfoTypeAndValue, 0, len(*content))
	var unsupported []asn1.ObjectIdentifier
	for _, req := range *content {
		item, err := h.answerGeneral(ctx, msg, req, sender)
		if errors.Is(err, errNotSupported) {
			unsupported = append(unsupported, req.InfoType)
			continue
		}
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if len(unsupported) > 0 {
		items = append(items, pkicmp.NewUnsupportedOIDsInfo(unsupported...))
	}
	return &Response{GeneralResponse: items}, nil
}

// answerGeneral returns the response item for one requested info type.
func (h *caHandler) answerGeneral(ctx context.Context, msg *pkicmp.PKIMessage, req pkicmp.InfoTypeAndValue, sender *SenderIdentity) (pkicmp.InfoTypeAndValue, error) {
	switch {
	case req.InfoType.Equal(pkicmp.InfoTypeCACerts):
		p, ok := h.ca.(CACertificatesProvider)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, errNotSupported
		}
		certs, err := p.CACertificates(ctx, sender)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, err
		}
		return pkicmp.NewCACertsInfo(certs), nil

	case req.InfoType.Equal(pkicmp.InfoTypeRootCACert):
		p, ok := h.ca.(RootCAUpdateProvider)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, errNotSupported
		}
		return answerRootCAUpdate(ctx, p, req, sender)

	case req.InfoType.Equal(pkicmp.InfoTypeCertReqTemplate):
		p, ok := h.ca.(CertReqTemplateProvider)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, errNotSupported
		}
		t, err := p.CertReqTemplate(ctx, msg.Header.CertProfile(), sender)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, err
		}
		item, err := pkicmp.NewCertReqTemplateInfo(t)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailSystemFailure, "invalid certificate request template")
		}
		return item, nil

	case req.InfoType.Equal(pkicmp.InfoTypeCRLStatusList):
		p, ok := h.ca.(CRLProvider)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, errNotSupported
		}
		return answerCRLUpdate(ctx, p, req, sender)

	case req.InfoType.Equal(pkicmp.InfoTypeCurrentCRL):
		p, ok := h.ca.(CRLProvider)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, errNotSupported
		}
		crl, err := p.LatestCRL(ctx, pkicmp.CRLSource{}, sender)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, err
		}
		return pkicmp.NewCurrentCRLInfo(crl), nil

	default:
		return pkicmp.InfoTypeAndValue{}, errNotSupported
	}
}

// answerRootCAUpdate returns the root CA key update for the root the request names.
func answerRootCAUpdate(ctx context.Context, p RootCAUpdateProvider, req pkicmp.InfoTypeAndValue, sender *SenderIdentity) (pkicmp.InfoTypeAndValue, error) {
	oldRoot, err := pkicmp.ParseRootCACertInfo(req)
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailBadDataFormat, "malformed root CA certificate")
	}
	update, err := p.RootCAUpdate(ctx, oldRoot, sender)
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, err
	}
	if update != nil {
		// RFC 9483 §4.3.2 requires newWithOld, without which a client that
		// trusts only the old root has no way to trust the new one. Checking
		// the update here keeps a CA mistake from reaching every device.
		if update.NewWithOld == nil {
			return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailSystemFailure, "root CA update has no newWithOld")
		}
		if err := update.Verify(oldRoot); err != nil {
			return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailSystemFailure, "invalid root CA update")
		}
	}
	item, err := pkicmp.NewRootCAKeyUpdateInfo(update)
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailSystemFailure, "invalid root CA update")
	}
	return item, nil
}

// answerCRLUpdate returns the CRLs that are newer than the ones the client
// holds, one lookup per CRLStatus. RFC 9483 §4.3.4 sends one status, while
// RFC 9810 allows several.
func answerCRLUpdate(ctx context.Context, p CRLProvider, req pkicmp.InfoTypeAndValue, sender *SenderIdentity) (pkicmp.InfoTypeAndValue, error) {
	statuses, err := pkicmp.ParseCRLStatusListInfo(req)
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, rejection(pkicmp.FailBadDataFormat, "malformed CRL status list")
	}
	var crls []*x509.RevocationList
	for _, status := range statuses {
		crl, err := p.LatestCRL(ctx, status.Source, sender)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, err
		}
		if crl != nil && (status.ThisUpdate.IsZero() || crl.ThisUpdate.After(status.ThisUpdate)) {
			crls = append(crls, crl)
		}
	}
	return pkicmp.NewCRLsInfo(crls), nil
}

// handleGenM answers a genm with a genp carrying the handler's items (RFC 9483 §4.3).
func (s *Server) handleGenM(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	// The genp ends the transaction. The entry stays until cleanup so the
	// transactionID cannot be reused within the same window (RFC 9483 §3.5).
	defer s.setCompleted(credID, msg.Header.TransactionID)

	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		return s.buildErrorResponse(msg, sender, errorToStatusInfo(err))
	}
	if resp != nil && resp.Waiting != nil {
		// Delayed general responses are not supported.
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailSystemFailure,
			StatusString: pkicmp.PKIFreeText{"delayed general response not supported"},
		})
	}
	var items []pkicmp.InfoTypeAndValue
	if resp != nil {
		items = resp.GeneralResponse
	}
	// A handler that answers nothing has not understood the request, and the
	// client learns that from an unsupportedOIDs item rather than an empty genp.
	if len(items) == 0 {
		if requested := requestedInfoTypes(msg); len(requested) > 0 {
			items = []pkicmp.InfoTypeAndValue{pkicmp.NewUnsupportedOIDsInfo(requested...)}
		}
	}
	return s.buildResponse(msg, pkicmp.NewGenPBody(items...), sender)
}

// requestedInfoTypes returns the info types a general message asks for.
func requestedInfoTypes(msg *pkicmp.PKIMessage) []asn1.ObjectIdentifier {
	content, err := msg.Body.GenM()
	if err != nil {
		return nil
	}
	oids := make([]asn1.ObjectIdentifier, 0, len(*content))
	for _, item := range *content {
		oids = append(oids, item.InfoType)
	}
	return oids
}

// validateProfileGenM applies the RFC 9483 §4.3 rules on general messages: one
// item, and no value where the operation defines none. A request that breaks a
// rule is well formed but not one the profile permits, so it gets badRequest.
func validateProfileGenM(msg *pkicmp.PKIMessage) error {
	if msg.Body.Type != pkicmp.BodyTypeGenM {
		return nil
	}
	content, err := msg.Body.GenM()
	if err != nil {
		return rejection(pkicmp.FailBadDataFormat, "malformed general message")
	}
	if len(*content) != 1 {
		return rejection(pkicmp.FailBadRequest, "general message must carry one item")
	}
	item := (*content)[0]
	switch {
	case item.InfoType.Equal(pkicmp.InfoTypeCACerts), item.InfoType.Equal(pkicmp.InfoTypeCertReqTemplate),
		item.InfoType.Equal(pkicmp.InfoTypeCurrentCRL):
		if len(item.InfoValue) > 0 {
			return rejection(pkicmp.FailBadRequest, "request value must be absent")
		}
	case item.InfoType.Equal(pkicmp.InfoTypeCRLStatusList):
		statuses, err := pkicmp.ParseCRLStatusListInfo(item)
		if err != nil {
			return rejection(pkicmp.FailBadDataFormat, "malformed CRL status list")
		}
		if len(statuses) != 1 {
			return rejection(pkicmp.FailBadRequest, "CRL status list must carry one status")
		}
	default:
	}
	return nil
}
