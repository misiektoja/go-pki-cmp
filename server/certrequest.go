package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

type parsedCRMF struct {
	certReqID    int64
	subject      pkix.Name
	rawSubject   []byte // DER Name as requested, nil when the template has no subject
	publicKey    crypto.PublicKey
	publicKeyDER []byte // DER SubjectPublicKeyInfo from the template
	extensions   []pkix.Extension
	signaturePOP bool // request carries a signature proof of possession
	popoAbsent   bool // request carries no proof of possession at all
	// subsequentMessage is the method a keyEncipherment or keyAgreement proof asks for.
	subsequentMessage *int64
}

// parseCRMFMsg extracts fields from a CRMF request body.
func parseCRMFMsg(msg *pkicmp.PKIMessage) (*parsedCRMF, error) {
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
		return nil, rejection(pkicmp.FailBadRequest, "")
	}
	if err != nil {
		return nil, rejection(pkicmp.FailBadDataFormat, "malformed certificate request")
	}
	if len(*msgs) == 0 {
		return nil, rejection(pkicmp.FailBadDataFormat, "empty CertReqMessages")
	}
	if len(*msgs) > 1 {
		return nil, rejection(pkicmp.FailBadRequest, "multiple CertReqMsg not supported")
	}

	reqMsg := (*msgs)[0]
	result := &parsedCRMF{certReqID: reqMsg.CertReq.CertReqID}

	// Extract subject.
	if len(reqMsg.CertReq.CertTemplate.Subject.DirectoryName) > 0 {
		var name pkix.Name
		name.FillFromRDNSequence(&reqMsg.CertReq.CertTemplate.Subject.DirectoryName)
		result.subject = name
	}
	result.rawSubject = reqMsg.CertReq.CertTemplate.RawSubject

	// Extract public key.
	if len(reqMsg.CertReq.CertTemplate.PublicKey) > 0 {
		pub, err := pkicmp.ParsePublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
		if err != nil {
			return nil, rejection(pkicmp.FailBadAlg, err.Error())
		}
		result.publicKey = pub
		result.publicKeyDER = reqMsg.CertReq.CertTemplate.PublicKey
	}

	result.signaturePOP = reqMsg.Popo != nil && reqMsg.Popo.Signature != nil
	result.popoAbsent = reqMsg.Popo == nil
	if reqMsg.Popo != nil {
		if v, ok := reqMsg.Popo.SubsequentMessage(); ok {
			result.subsequentMessage = &v
		}
	}

	// Extract extensions.
	if len(reqMsg.CertReq.CertTemplate.Extensions) > 0 {
		var exts []pkix.Extension
		rest := reqMsg.CertReq.CertTemplate.Extensions
		// Parse DER SEQUENCE OF Extension using encoding/asn1.
		if _, err := asn1.Unmarshal(rest, &exts); err != nil {
			return nil, rejection(pkicmp.FailBadDataFormat, "malformed certificate template extensions")
		}
		result.extensions = exts
	}

	return result, nil
}

// enforceProofOfPossession rejects a certificate request that does not prove possession of the requested private key.
//
// RFC 4211 §4 and RFC 9483 §5.1.1 require the proof, and without it a requester
// can obtain a certificate for a public key belonging to someone else. It is
// applied in the issuance path itself rather than only in a policy wrapper,
// because a server built without one still issues certificates. [LightweightPolicy]
// applies the same rule, so a request usually passes it once in the policy and
// once here, which costs one extra public key operation and keeps either layer
// correct on its own.
func enforceProofOfPossession(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	switch msg.Body.Type {
	case pkicmp.BodyTypeP10CR:
		csr, err := msg.Body.P10CR()
		if err != nil {
			return rejection(pkicmp.FailBadDataFormat, "")
		}
		// For PKCS#10 the self-signature over the request is the proof.
		if err := pkicmp.CheckCertificateRequestSignature(csr); err != nil {
			if errors.Is(err, x509.ErrUnsupportedAlgorithm) {
				return rejection(pkicmp.FailBadAlg, "unsupported signature algorithm")
			}
			return rejection(pkicmp.FailBadPOP, err.Error())
		}
		return nil

	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR:
		crmf, err := parseCRMFMsg(msg)
		if err != nil {
			return err
		}
		if err := verifyPOPMsg(msg, popOptions(ctx, sender)); err != nil {
			failInfo := pkicmp.FailBadPOP
			var verr *pkicmp.VerificationError
			if errors.As(err, &verr) && verr.Reason == pkicmp.ReasonUnsupportedAlgorithm {
				failInfo = pkicmp.FailBadAlg
			}
			// RFC 9810 §5.2.8.1: An end entity MUST NOT use raVerified.
			var parseErr *pkicmp.ParseError
			if errors.As(err, &parseErr) && parseErr.Detail == "raVerified POP not supported" {
				failInfo = pkicmp.FailNotAuthorized
			}
			return rejection(failInfo, err.Error())
		}
		if crmf.publicKey == nil {
			return rejection(pkicmp.FailBadCertTemplate, "public key required")
		}
		// verifyPOPMsg checks only a signature proof and passes a request that
		// omits popo or uses another variant. The indirect methods of RFC 9810
		// §5.2.8.3 prove possession later in the exchange, so they are accepted
		// here only when the server is configured to complete them.
		if !crmf.signaturePOP {
			if crmf.popoAbsent {
				if policyConfigFrom(ctx).signatureProtectionPOP && signedWithRequestedKey(crmf, sender) {
					return nil
				}
				return rejection(pkicmp.FailBadPOP, "proof of possession by signature required")
			}
			return checkIndirectPOP(ctx, crmf)
		}
		return nil
	default:
		// Only certificate requests carry a proof of possession.
		return nil
	}
}

// signedWithRequestedKey reports whether the message protection was verified
// with a certificate for the public key the template requests. That signature
// then proves possession of the private key, which RFC 4211 §4 lets a server
// establish by other means than the popo field.
func signedWithRequestedKey(crmf *parsedCRMF, sender *SenderIdentity) bool {
	if sender == nil || sender.MACVerified || sender.Certificate == nil || len(crmf.publicKeyDER) == 0 {
		return false
	}
	cert := sender.Certificate
	return bytes.Equal(crmf.publicKeyDER, cert.RawSubjectPublicKeyInfo) ||
		samePublicKey(crmf.publicKeyDER, certificatePublicKey(cert))
}

// verifyPOPMsg verifies the Proof of Possession for CRMF requests.
// RFC 4211 §4: Delegates to pkicmp.VerifyPOP.
func verifyPOPMsg(msg *pkicmp.PKIMessage, opts pkicmp.POPOptions) error {
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
	if err != nil || len(*msgs) == 0 {
		return err
	}

	return pkicmp.VerifyPOPWithOptions(&(*msgs)[0], opts)
}

// oidBasicConstraints identifies the RFC 5280 §4.2.1.9 BasicConstraints extension.
var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// basicConstraints is the RFC 5280 §4.2.1.9 extension value.
//
// pathLenConstraint carries no DEFAULT, so an absent one decodes as zero rather
// than as the -1 crypto/x509 uses. Nothing here distinguishes the two, because a
// path length only constrains a CA certificate and those are rejected outright.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional"`
}

// decodeBasicConstraints returns every BasicConstraints extension in the list
// and an error if any one of them is malformed.
func decodeBasicConstraints(extensions []pkix.Extension) ([]basicConstraints, error) {
	var out []basicConstraints
	for _, ext := range extensions {
		if !ext.Id.Equal(oidBasicConstraints) {
			continue
		}
		// A decode failure must not be read as "the extension is absent". Go's
		// encoding/asn1 accepts only 00 and FF for a BOOLEAN, so a one-byte
		// change such as 01 01 01 makes cA undecodable, and treating that as
		// absence lets a request for a CA certificate past the checks below
		// while the extension itself travels on to the CA unchanged.
		var bc basicConstraints
		rest, err := asn1.Unmarshal(ext.Value, &bc)
		if err != nil || len(rest) != 0 {
			return nil, rejection(pkicmp.FailBadCertTemplate, "malformed BasicConstraints")
		}
		out = append(out, bc)
	}
	return out, nil
}

// checkBasicConstraints rejects a malformed BasicConstraints extension, an
// invalid path length and any request for a CA certificate.
func checkBasicConstraints(extensions []pkix.Extension) error {
	all, err := decodeBasicConstraints(extensions)
	if err != nil {
		return err
	}
	for _, bc := range all {
		// RFC 5280 §4.2.1.9: pathLenConstraint is meaningful only when cA is
		// true, and it is never negative.
		if bc.MaxPathLen < 0 || (!bc.IsCA && bc.MaxPathLen != 0) {
			return rejection(pkicmp.FailBadCertTemplate, "invalid path-length in BasicConstraints")
		}
	}
	for _, bc := range all {
		if bc.IsCA {
			return rejection(pkicmp.FailNotAuthorized, "CA certificates not allowed")
		}
	}
	return nil
}
