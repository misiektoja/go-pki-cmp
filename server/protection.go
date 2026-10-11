package server

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// verifyProtection verifies message protection and returns the sender identity.
func (s *Server) verifyProtection(msg *pkicmp.PKIMessage) (*SenderIdentity, error) {
	if msg.Header.ProtectionAlg == nil || len(msg.Protection) == 0 {
		return nil, rejection(pkicmp.FailBadMessageCheck, "message not protected")
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// MAC-protected message.
	if isMACAlgorithm(alg) {
		if s.cfg.secretLookup == nil {
			return nil, rejection(pkicmp.FailBadMessageCheck, "MAC protection not configured")
		}

		// Resolve sender DN from header (may be NULL-DN for initial enrollment).
		var senderName pkix.Name
		if len(msg.Header.Sender.DirectoryName) > 0 {
			senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
		}

		secret, err := s.cfg.secretLookup.LookupSecret(senderName, msg.Header.SenderKID)
		if err != nil {
			return nil, rejection(pkicmp.FailBadMessageCheck, "unknown sender")
		}
		vr, err := msg.Verify(pkicmp.VerifyOptions{
			SharedSecret:         secret,
			MinMACIterationCount: s.cfg.minMACIterationCount,
			MaxMACIterationCount: s.cfg.maxMACIterationCount,
		})
		if err != nil {
			if isUnsupportedAlgorithm(err) {
				return nil, rejection(pkicmp.FailBadAlg, "unsupported protection algorithm")
			}
			// Parameters outside local policy, such as an iteration count beyond
			// WithMACIterationLimits, are not a wrong secret. Saying so points an
			// operator at the device configuration instead of the credential.
			if _, ok := errors.AsType[*pkicmp.ParseError](err); ok {
				return nil, rejection(pkicmp.FailBadMessageCheck, "MAC protection parameters not accepted")
			}
			return nil, rejection(pkicmp.FailBadMessageCheck, "MAC verification failed")
		}
		return &SenderIdentity{
			Sender:           senderName,
			SenderKID:        msg.Header.SenderKID,
			MACVerified:      true,
			secret:           secret,
			protectionParams: vr.ProtectionParams,
			headerSender:     msg.Header.Sender,
		}, nil
	}

	// Signature-protected message.
	if s.cfg.certificateLookup == nil {
		return nil, rejection(pkicmp.FailSignerNotTrusted, "signature protection not configured")
	}

	// Resolve sender DN from header.
	var senderName pkix.Name
	if len(msg.Header.Sender.DirectoryName) > 0 {
		senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
	}

	// Resolve issuer from recipient header field.
	var issuerName pkix.Name
	if len(msg.Header.Recipient.DirectoryName) > 0 {
		issuerName.FillFromRDNSequence(&msg.Header.Recipient.DirectoryName)
	}

	// Look up the sender's certificate from the server's database.
	// RFC 9810 §5.1.1: senderKID SHOULD be used but is not mandatory.
	signerCert, err := s.cfg.certificateLookup.LookupCertificate(issuerName, senderName, msg.Header.SenderKID)
	if err != nil {
		return nil, rejection(pkicmp.FailSignerNotTrusted, "unknown sender")
	}

	// Verify the signature directly against the looked-up certificate. No chain
	// validation is needed, because the certificate came from the server's own
	// database, but the message must still name that certificate's subject as
	// its sender. SenderIdentity carries both to the CA, and a CA that
	// authorizes on the name would otherwise be handed a name the peer chose
	// alongside a certificate the server itself vouched for.
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert, AllowSHA1Signatures: s.cfg.allowSHA1Signatures})
	if err != nil {
		var verr *pkicmp.VerificationError
		if errors.As(err, &verr) && verr.Reason == pkicmp.ReasonSenderMismatch {
			return nil, rejection(pkicmp.FailBadMessageCheck, "sender does not match the certificate that signed the message")
		}
		if isUnsupportedAlgorithm(err) {
			return nil, rejection(pkicmp.FailBadAlg, "unsupported protection algorithm")
		}
		return nil, rejection(pkicmp.FailSignerNotTrusted, "signature verification failed")
	}

	return &SenderIdentity{Certificate: signerCert, Sender: senderName}, nil
}

// isUnsupportedAlgorithm reports whether verification failed because the
// protection algorithm or one of its parameters is not supported.
func isUnsupportedAlgorithm(err error) bool {
	var verr *pkicmp.VerificationError
	return errors.As(err, &verr) && verr.Reason == pkicmp.ReasonUnsupportedAlgorithm
}

// isMACAlgorithm returns true if the OID is a supported MAC protection algorithm.
func isMACAlgorithm(oid asn1.ObjectIdentifier) bool {
	// OIDPasswordBasedMac = 1.2.840.113533.7.66.13
	// OIDPBMAC1 = 1.2.840.113549.1.5.14
	return oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}) ||
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14})
}

// protectResponseWithOptions applies protection using stored MAC options when available.
// protectionParams carries the decoded protection parameters for echo-back (RFC 9810 §5.1.3).
func (s *Server) protectResponseWithOptions(resp *pkicmp.PKIMessage, sender *SenderIdentity, protectionParams pkicmp.MACCredentialOption) error {
	// MAC-protected request → MAC-protect response with same secret.
	if sender != nil && sender.MACVerified && len(sender.secret) > 0 {
		var opts []pkicmp.MACCredentialOption
		if protectionParams != nil {
			opts = append(opts, protectionParams)
		}
		// Parameters restored from a snapshot carry no limits of their own, and
		// the echoed count was accepted under the configured ones.
		opts = append(opts, pkicmp.WithMACIterationLimits(s.cfg.minMACIterationCount, s.cfg.maxMACIterationCount))
		creds, err := pkicmp.NewMACCredentials(sender.secret, opts...)
		if err != nil {
			return err
		}
		return creds.Protect(resp)
	}

	// Signature protection, using the credentials New validated.
	if s.cfg.signerErr != nil {
		return s.cfg.signerErr
	}
	if s.cfg.signerCreds != nil {
		return s.cfg.signerCreds.Protect(resp)
	}

	return nil
}
