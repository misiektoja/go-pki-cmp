package server

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// LightweightPolicy returns a handler wrapper that enforces RFC 9483 Lightweight CMP Profile requirements.
// This is the default policy used by the server. Users can replace it with their own policy wrappers.
func LightweightPolicy() func(Handler) Handler {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
			// RFC 9483 §3.1 wants a MAC-protected message to name the shared
			// secret in the sender commonName, but RFC 4210 §5.1.1 requires the
			// opposite of an end entity that does not yet know its own name: a
			// NULL-DN sender with the reference number in senderKID, which is
			// what a bootstrapping enrollment normally is. Either form
			// identifies the secret, so only the absence of both is rejected
			// here. WithStrictProfileValidation applies the profile rule.
			if sender.MACVerified && len(msg.Header.Sender.DirectoryName) == 0 && len(msg.Header.SenderKID) == 0 {
				return nil, rejection(pkicmp.FailBadMessageCheck, "MAC protection requires a sender name or senderKID")
			}

			// The RFC 9483 §3.3 rules on extraCerts, that it is present for
			// signature-based protection and that the CMP protection certificate
			// comes first, are enforced only under WithStrictProfileValidation.
			// They exist so a recipient can resolve and validate the signer from
			// the message, and this server never does that: it authenticates
			// through CertificateLookup against its own store. Enforcing them by
			// default would reject deployed clients over a field the server
			// ignores. Outgoing responses always follow §3.3.

			if msg.Body.Type == pkicmp.BodyTypeRR {
				if err := validateRR(ctx, msg, sender); err != nil {
					return nil, err
				}
				return next.HandleCMP(ctx, msg, sender)
			}

			// Only validate cert requests further.
			if !isCertRequest(msg.Body.Type) {
				return next.HandleCMP(ctx, msg, sender)
			}

			// RFC 9483 §4.1.3: KUR MUST be signature-protected.
			if msg.Body.Type == pkicmp.BodyTypeKUR && sender.MACVerified {
				return nil, rejection(pkicmp.FailWrongIntegrity, "KUR requires signature protection")
			}

			// Validate based on request type.
			switch msg.Body.Type {
			case pkicmp.BodyTypeP10CR:
				if err := validateP10CR(ctx, msg, sender); err != nil {
					return nil, err
				}
			case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR:
				if err := validateCRMF(ctx, msg, sender); err != nil {
					return nil, err
				}
			default:
				// isCertRequest above lets no other body type through.
			}

			return next.HandleCMP(ctx, msg, sender)
		})
	}
}

// isCertRequest reports whether t is the body type of a certificate request.
func isCertRequest(t pkicmp.BodyType) bool {
	switch t {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return true
	default:
		return false
	}
}

// validateP10CR applies the RFC 9483 §4.1.4 rules to a PKCS#10 request.
func validateP10CR(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	csr, err := msg.Body.P10CR()
	if err != nil {
		return rejection(pkicmp.FailBadDataFormat, "")
	}
	// RFC 4211 §4: the CSR self-signature proves possession of the key.
	if err := enforceProofOfPossession(ctx, msg, sender); err != nil {
		return err
	}
	// A PKCS#10 request always has a subject field, which may be a NULL-DN.
	if err := checkSubject(ctx, csr.Subject, true, csr.Extensions); err != nil {
		return err
	}
	// RFC 5280 §4.2.1.9 path-length rules, plus the policy decision to refuse a
	// request for a CA certificate.
	return checkBasicConstraints(csr.Extensions)
}

// validateRR applies the RFC 9483 §4.2 rules to a revocation request.
func validateRR(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	cfg := policyConfigFrom(ctx)
	// RFC 9483 §4.2 and §5.3.2: the request is signed, either with the
	// certificate being revoked or by a PKI management entity.
	// WithMACRevocation sends a MAC-protected request on to the
	// RevocationAuthorizer instead.
	if sender.MACVerified && !cfg.macRevocation {
		return rejection(pkicmp.FailWrongIntegrity, "revocation requires signature protection")
	}
	req, err := parseRevocationRequest(msg, cfg.optionalRevocationIssuer)
	if err != nil {
		return err
	}
	// RFC 9483 §4.2: crlEntryDetails MUST contain a reasonCode.
	if !req.hasReason && !cfg.optionalRevocationReason {
		return rejection(pkicmp.FailBadRequest, "reasonCode required")
	}
	return nil
}

// validateCRMF applies the RFC 9483 §4.1 rules to an ir, cr or kur.
func validateCRMF(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	crmf, err := parseCRMFMsg(msg)
	if err != nil {
		return err
	}

	// RFC 9483 §4.1.3: certReqId MUST be 0.
	if crmf.certReqID != 0 {
		return rejection(pkicmp.FailBadRequest, "certReqId must be 0")
	}

	// RFC 4211 §4 and RFC 9483 §5.1.1: the request must prove possession of the
	// requested key.
	if err := enforceProofOfPossession(ctx, msg, sender); err != nil {
		return err
	}

	if err := checkSubject(ctx, crmf.subject, crmf.rawSubject != nil, crmf.extensions); err != nil {
		return err
	}

	// RFC 5280 §4.2.1.9 path-length rules, plus the policy decision to refuse a
	// request for a CA certificate.
	return checkBasicConstraints(crmf.extensions)
}

// oidExtensionSubjectAltName identifies the RFC 5280 §4.2.1.6 subjectAltName extension.
var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// checkSubject enforces the RFC 9483 §4.1.1 identity rule: the subject names the
// entity, or it is a NULL-DN and a requested subjectAltName extension does.
// present reports whether the request has a subject field at all. A CRMF
// template may omit it, which only WithOptionalSubject accepts.
func checkSubject(ctx context.Context, subject pkix.Name, present bool, extensions []pkix.Extension) error {
	if len(subject.String()) > 0 {
		return nil
	}
	if !present && !policyConfigFrom(ctx).optionalSubject {
		return rejection(pkicmp.FailBadCertTemplate, "subject required")
	}
	if !hasSubjectAltName(extensions) {
		return rejection(pkicmp.FailBadCertTemplate, "subject or subjectAltName required")
	}
	return nil
}

// hasSubjectAltName reports whether extensions request a subjectAltName.
func hasSubjectAltName(extensions []pkix.Extension) bool {
	return slices.ContainsFunc(extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(oidExtensionSubjectAltName)
	})
}
