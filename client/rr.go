package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// SendRR asks the CA to revoke cert for the given reason (RFC 9483 §4.2).
//
// RFC 9483 requires the request to be signed with the certificate being
// revoked, so creds is normally [pkicmp.NewSignatureCredentials] built from
// cert and its private key. A PKI management entity revoking for an end entity
// signs with its own credentials instead (RFC 9483 §5.3.2). Use
// [pkicmp.CRLReasonRemoveFromCRL] to ask the CA to release a certificate on hold.
//
// A nil error means the CA accepted the request. A rejection is returned as a
// [*pkicmp.PKIStatusError], so [pkicmp.HasFailure] reports bits such as
// certRevoked. A CA that delays its answer is polled as for enrollment.
func (c *Client) SendRR(ctx context.Context, cert *x509.Certificate, reason pkicmp.CRLReason, creds pkicmp.Credentials, opts ...RequestOption) error {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	details, err := pkicmp.NewRevDetails(cert, reason)
	if err != nil {
		return &Error{Op: "build revocation request", Err: err}
	}
	msg, err := c.newRequest(pkicmp.NewRRBody(&pkicmp.RevReqContent{details}), creds, ropts)
	if err != nil {
		return err
	}

	cmpResp, vr, err := c.exchangeFirst(ctx, msg, creds)
	if err != nil {
		return err
	}
	resp := cmpResp.message

	if resp.Body.Type == pkicmp.BodyTypeError {
		err := parseErrorResponse(resp)
		if !errors.Is(err, pkicmp.ErrWaiting) {
			return cmpResp.wrapError(err)
		}
		// RFC 9483 §4.4: a delayed answer to anything but ir, cr, kur and p10cr
		// arrives as an error message with status waiting, and the polls refer
		// to the whole message with certReqId -1.
		var knownSigner *x509.Certificate
		if vr != nil {
			knownSigner = vr.ProtectionCertificate
		}
		cmpResp, _, err = c.poll(ctx, msg.Header, resp, creds, -1, knownSigner)
		if err != nil {
			return err
		}
		resp = cmpResp.message
	}

	if resp.Body.Type != pkicmp.BodyTypeRP {
		return cmpResp.wrapError(&Error{Op: fmt.Sprintf("unexpected response body type: %s", resp.Body.Type)})
	}
	rep, err := resp.Body.RP()
	if err != nil {
		return cmpResp.wrapError(&Error{Op: "parse revocation response", Err: err})
	}
	// RFC 9810 §5.3.10: one status per requested revocation, in request order.
	if len(rep.Status) != 1 {
		return cmpResp.wrapError(&Error{
			Op: fmt.Sprintf("revocation response carries %d statuses for one request", len(rep.Status)),
		})
	}
	if err := rep.Status[0].AsError(); err != nil {
		return cmpResp.wrapError(err)
	}
	return nil
}
