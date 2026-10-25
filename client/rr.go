package client

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// opBuildRR names the step that fails when a revocation request cannot be built.
const opBuildRR = "build revocation request"

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
// [WithInvalidityDate] adds the time the certificate became invalid.
func (c *Client) SendRR(ctx context.Context, cert *x509.Certificate, reason pkicmp.CRLReason, creds pkicmp.Credentials, opts ...RequestOption) error {
	details, err := pkicmp.NewRevDetails(cert, reason)
	if err != nil {
		return &Error{Op: opBuildRR, Err: err}
	}
	return c.sendRR(ctx, details, creds, opts)
}

// SendRRBySerial asks the CA to revoke the certificate that issuer issued
// with the given serial number (RFC 9483 §4.2), for a requester that does not
// hold the certificate, such as a PKI management entity revoking for an end
// entity (RFC 9483 §5.3.2). The CA decides whether creds may revoke it. The
// issuer name is encoded from issuer, so a CA that compares the name bytes
// needs the attributes in the order and with the string types of the
// certificate. The answer is handled as in [Client.SendRR].
func (c *Client) SendRRBySerial(ctx context.Context, issuer pkix.Name, serial *big.Int, reason pkicmp.CRLReason, creds pkicmp.Credentials, opts ...RequestOption) error {
	details, err := pkicmp.NewRevDetailsBySerial(issuer, serial, reason)
	if err != nil {
		return &Error{Op: opBuildRR, Err: err}
	}
	return c.sendRR(ctx, details, creds, opts)
}

// sendRR sends an rr carrying details and reads the rp, polling when the CA delays its answer.
func (c *Client) sendRR(ctx context.Context, details pkicmp.RevDetails, creds pkicmp.Credentials, opts []RequestOption) error {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}
	if !ropts.invalidityDate.IsZero() {
		ext, err := pkicmp.NewInvalidityDateExtension(ropts.invalidityDate)
		if err != nil {
			return &Error{Op: opBuildRR, Err: err}
		}
		if err := details.AddCRLEntryExtension(ext); err != nil {
			return &Error{Op: opBuildRR, Err: err}
		}
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
