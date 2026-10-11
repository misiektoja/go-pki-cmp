package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"

	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// oidCRLReason identifies the RFC 5280 §5.3.1 reasonCode CRL entry extension.
var oidCRLReason = asn1.ObjectIdentifier{2, 5, 29, 21}

// Revoker is an optional interface for CAs that handle revocation requests (RFC 9483 §4.2).
type Revoker interface {
	// RevokeCertificate revokes the certificate req identifies, or releases it
	// from hold when req.Reason is [pkicmp.CRLReasonRemoveFromCRL].
	//
	// The server calls it only for an authorized request: one signed with the
	// certificate it names, or one [RevocationAuthorizer] approved. The CA must
	// still find the certificate itself and report, as RFC 9483 §5.1.3 asks:
	//
	//   - badCertId when it did not issue the certificate. [RevocationRequest.Match]
	//     also checks the optional template fields against the certificate found.
	//   - certRevoked when the certificate is already revoked.
	//
	// Return an [*Error] to choose the rejection sent to the peer. A nil error
	// reports the revocation as accepted.
	RevokeCertificate(ctx context.Context, req *RevocationRequest, sender *SenderIdentity) error
}

// RevocationAuthorizer is an optional interface for CAs that accept revocation
// requests not signed with the certificate being revoked.
type RevocationAuthorizer interface {
	// AuthorizeRevocation decides whether sender may revoke the certificate req
	// identifies, for example a registration authority acting for an end entity
	// (RFC 9483 §5.3.2). Return nil to allow it, or an [*Error], normally with
	// notAuthorized, to refuse it.
	//
	// Without this interface such requests are rejected with notAuthorized.
	// It also receives MAC-protected requests that [WithMACRevocation] lets
	// through [LightweightPolicy] or that reach a handler without that policy.
	AuthorizeRevocation(ctx context.Context, req *RevocationRequest, sender *SenderIdentity) error
}

// RevocationRequest identifies the certificate an rr asks to revoke (RFC 9483 §4.2).
type RevocationRequest struct {
	// Issuer is the issuer name of the certificate, decoded from RawIssuer.
	Issuer pkix.Name
	// RawIssuer is the DER issuer name as the requester encoded it. It is empty
	// only under [WithOptionalRevocationIssuer], for a request that names no
	// issuer and is not signed with the certificate it names. The CA must then
	// find the certificate by SerialNumber alone.
	RawIssuer []byte
	// SerialNumber is the serial number of the certificate.
	SerialNumber *big.Int
	// Reason is the requested reason code. It is unspecified when the request
	// carries none, which RFC 5280 §5.3.1 treats the same way.
	Reason pkicmp.CRLReason
	// Extensions holds every requested CRL entry extension, including reasonCode.
	Extensions []pkix.Extension

	subject   pkix.RDNSequence // optional subject from the template
	publicKey []byte           // optional DER SubjectPublicKeyInfo from the template
	hasReason bool             // whether crlEntryDetails carried a reasonCode
}

// Match returns a badCertId Error unless cert is the certificate the request
// identifies, including any subject or public key the template names.
func (r *RevocationRequest) Match(cert *x509.Certificate) error {
	if cert == nil || !r.identifies(cert) {
		return rejection(pkicmp.FailBadCertId, "certificate not found")
	}
	if len(r.subject) > 0 {
		var subject pkix.RDNSequence
		rest, err := asn1.Unmarshal(cert.RawSubject, &subject)
		if err != nil || len(rest) > 0 || !equalRDNSequences(r.subject, subject) {
			return rejection(pkicmp.FailBadCertId, "subject does not match the certificate")
		}
	}
	if len(r.publicKey) > 0 && !bytes.Equal(r.publicKey, cert.RawSubjectPublicKeyInfo) &&
		!samePublicKey(r.publicKey, certificatePublicKey(cert)) {
		return rejection(pkicmp.FailBadCertId, "public key does not match the certificate")
	}
	return nil
}

// identifies reports whether cert carries the issuer and serial number the
// request names. A request without an issuer is matched by serial number.
func (r *RevocationRequest) identifies(cert *x509.Certificate) bool {
	return r.namesSerialOf(cert) && (len(r.RawIssuer) == 0 || equalNames(r.RawIssuer, cert.RawIssuer))
}

// namesSerialOf reports whether the request names the serial number of cert.
func (r *RevocationRequest) namesSerialOf(cert *x509.Certificate) bool {
	return cert.SerialNumber != nil && r.SerialNumber.Cmp(cert.SerialNumber) == 0
}

// parseRevocationRequest extracts the single revocation RFC 9483 §4.2 allows in
// an rr body. optionalIssuer admits a template without an issuer.
func parseRevocationRequest(msg *pkicmp.PKIMessage, optionalIssuer bool) (*RevocationRequest, error) {
	content, err := msg.Body.RR()
	if err != nil {
		return nil, rejection(pkicmp.FailBadDataFormat, "malformed revocation request")
	}
	if len(*content) == 0 {
		return nil, rejection(pkicmp.FailBadDataFormat, "empty RevReqContent")
	}
	if len(*content) > 1 {
		return nil, rejection(pkicmp.FailBadRequest, "multiple RevDetails not supported")
	}
	details := (*content)[0]
	tmpl := details.CertDetails

	// RFC 9483 §4.2 identifies the certificate by issuer and serial number.
	if tmpl.SerialNumber == nil {
		return nil, rejection(pkicmp.FailAddInfoNotAvailable, "serialNumber required")
	}
	var issuer pkix.RDNSequence
	if len(tmpl.Issuer) > 0 {
		if rest, err := asn1.Unmarshal(tmpl.Issuer, &issuer); err != nil || len(rest) > 0 {
			return nil, rejection(pkicmp.FailBadDataFormat, "malformed issuer")
		}
	}
	req := &RevocationRequest{
		SerialNumber: tmpl.SerialNumber,
		subject:      tmpl.Subject.DirectoryName,
		publicKey:    tmpl.PublicKey,
	}
	// An empty name identifies no issuer, so it counts as absent.
	if len(issuer) > 0 {
		req.RawIssuer = tmpl.Issuer
		req.Issuer.FillFromRDNSequence(&issuer)
	} else if !optionalIssuer {
		return nil, rejection(pkicmp.FailAddInfoNotAvailable, "issuer required")
	}

	req.Extensions, err = details.CRLEntryExtensions()
	if err != nil {
		return nil, rejection(pkicmp.FailBadDataFormat, "malformed crlEntryDetails")
	}
	for _, ext := range req.Extensions {
		if !ext.Id.Equal(oidCRLReason) {
			continue
		}
		// Two reason codes, such as a revocation and a release from hold, leave
		// the request without a single meaning.
		if req.hasReason {
			return nil, rejection(pkicmp.FailBadRequest, "more than one reasonCode")
		}
		var code asn1.Enumerated
		rest, err := asn1.Unmarshal(ext.Value, &code)
		if err != nil || len(rest) > 0 || !pkicmp.CRLReason(code).Valid() {
			return nil, rejection(pkicmp.FailBadDataFormat, "invalid reasonCode")
		}
		req.Reason = pkicmp.CRLReason(code)
		req.hasReason = true
	}
	return req, nil
}

// handleRevocation authorizes a revocation request and passes it to the CA.
func (h *caHandler) handleRevocation(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	revoker, ok := h.ca.(Revoker)
	if !ok {
		return rejection(pkicmp.FailBadRequest, "revocation not supported")
	}
	req, err := parseRevocationRequest(msg, policyConfigFrom(ctx).optionalRevocationIssuer)
	if err != nil {
		return err
	}
	// A request that names no issuer and the serial number of its own signer
	// revokes that certificate. Taking the issuer from the signer keeps the CA
	// from matching the serial number to a certificate of another issuer.
	if len(req.RawIssuer) == 0 && sender != nil && sender.Certificate != nil && req.namesSerialOf(sender.Certificate) {
		req.RawIssuer = bytes.Clone(sender.Certificate.RawIssuer)
		req.Issuer = sender.Certificate.Issuer
	}

	// RFC 9483 §4.2: signing with the certificate being revoked proves the
	// authority to revoke it. Any other signer, such as a registration authority
	// under §5.3.2, needs the CA's explicit approval, so a CA that never thinks
	// about authorization cannot be used to revoke other entities' certificates.
	if sender != nil && sender.Certificate != nil && req.identifies(sender.Certificate) {
		if err := req.Match(sender.Certificate); err != nil {
			return err
		}
	} else {
		authorizer, ok := h.ca.(RevocationAuthorizer)
		if !ok {
			return rejection(pkicmp.FailNotAuthorized, "revocation request must be signed with the certificate being revoked")
		}
		if err := authorizer.AuthorizeRevocation(ctx, req, sender); err != nil {
			return err
		}
	}
	return revoker.RevokeCertificate(ctx, req, sender)
}

// handleRevocation answers an rr with an rp carrying the handler's decision (RFC 9483 §4.2).
func (s *Server) handleRevocation(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	// The rp ends the operation. The entry stays until cleanup so the
	// transactionID cannot be reused within the same window (RFC 9483 §3.5).
	defer s.setCompleted(credID, msg.Header.TransactionID)

	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		// RFC 9483 §3.6.2: problems with the header or protection go in an error
		// message, problems with the request itself in the rp.
		if si.FailInfo&pkicmp.FailBadMessageCheck != 0 {
			return s.buildErrorResponse(msg, sender, si)
		}
		return s.buildRevRepResponse(msg, si, sender)
	}
	if resp != nil && resp.Waiting != nil {
		// Delayed revocation is not supported, and reporting acceptance would
		// claim a revocation that has not happened.
		return s.buildRevRepResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailSystemFailure,
		}, sender)
	}
	return s.buildRevRepResponse(msg, pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, sender)
}

// equalNames reports whether two DER names are identical or decode to the same attributes regardless of string type.
func equalNames(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var an, bn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(a, &an); err != nil || len(rest) > 0 {
		return false
	}
	if rest, err := asn1.Unmarshal(b, &bn); err != nil || len(rest) > 0 {
		return false
	}
	return equalRDNSequences(an, bn)
}

// equalRDNSequences compares two names attribute by attribute, in order.
func equalRDNSequences(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if !a[i][j].Type.Equal(b[i][j].Type) || !reflect.DeepEqual(a[i][j].Value, b[i][j].Value) {
				return false
			}
		}
	}
	return true
}

// samePublicKey reports whether a DER SubjectPublicKeyInfo holds the same key as pub.
func samePublicKey(spki []byte, pub crypto.PublicKey) bool {
	parsed, err := compositex509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	comparable, ok := parsed.(interface{ Equal(crypto.PublicKey) bool })
	return ok && comparable.Equal(pub)
}
