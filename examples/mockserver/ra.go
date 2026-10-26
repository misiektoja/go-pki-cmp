package mockserver

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"slices"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// oidExtKeyUsageCMCRA is the id-kp-cmcRA extended key usage of a registration authority (RFC 6402 §2.10).
var oidExtKeyUsageCMCRA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 28}

// AuthorizeRA implements server.RAAuthorizer. It accepts a registration
// authority that signs the nested message with a certificate this CA issued
// with the id-kp-cmcRA extended key usage and has not revoked. It refuses a MAC
// with wrongIntegrity, because RFC 9483 §5.2.2.1 requires a signature.
//
// The example CA copies a requested extendedKeyUsage into the certificate, so
// any client it enrolls can become an RA. A real CA decides who its RAs are.
func (c *MockCA) AuthorizeRA(_ context.Context, ra *server.SenderIdentity, req *pkicmp.PKIMessage, _ *server.SenderIdentity) error {
	if ra.Certificate == nil {
		return raRefusal(pkicmp.FailWrongIntegrity, "a registration authority must sign the nested message")
	}
	if !slices.ContainsFunc(ra.Certificate.UnknownExtKeyUsage, oidExtKeyUsageCMCRA.Equal) {
		return raRefusal(pkicmp.FailNotAuthorized, "the certificate of the registration authority lacks id-kp-cmcRA")
	}
	if !c.issuedAndValid(ra.Certificate) {
		return raRefusal(pkicmp.FailNotAuthorized, "the registration authority is not known to this CA")
	}
	c.Log.Info("request forwarded by registration authority",
		"type", req.Body.Type.String(),
		"ra", ra.Certificate.Subject.String(),
	)
	return nil
}

// issuedAndValid reports whether this CA issued cert and has not revoked it.
func (c *MockCA) issuedAndValid(cert *x509.Certificate) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, revoked := c.revoked[cert.SerialNumber.String()]; revoked {
		return false
	}
	return slices.ContainsFunc(c.issuedCerts, cert.Equal)
}

// raRefusal returns the rejection of a nested message the example CA does not accept.
func raRefusal(failInfo pkicmp.PKIFailureInfo, text string) error {
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: failInfo, StatusText: text}
}
