package client

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// ErrInfoTypeNotSupported reports that the server listed the requested info
// type as unsupported (RFC 9810 §5.3.19.7) or answered without it. RFC 9810
// §5.3.19 lets a receiver ignore info types it does not recognize, and servers
// built for RFC 4210 do that.
var ErrInfoTypeNotSupported = errors.New("cmp: info type not supported by the server")

// SendGenM sends a general message with the given items and returns the items
// of the general response (RFC 9810 §5.3.19 and §5.3.20). RFC 9483 §4.3 sends
// one item, and the typed calls such as [Client.GetCACertificates] do that.
//
// The response is verified like any other, so its content is as trustworthy
// as the protection the client checked. A rejection is returned as a
// [*pkicmp.PKIStatusError]. A server that delays its answer is polled as for
// enrollment.
func (c *Client) SendGenM(ctx context.Context, items []pkicmp.InfoTypeAndValue, creds pkicmp.Credentials, opts ...RequestOption) ([]pkicmp.InfoTypeAndValue, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	msg, err := c.newRequest(pkicmp.NewGenMBody(items...), creds, ropts)
	if err != nil {
		return nil, err
	}

	cmpResp, vr, err := c.exchangeFirst(ctx, msg, creds)
	if err != nil {
		return nil, err
	}
	resp := cmpResp.message

	if resp.Body.Type == pkicmp.BodyTypeError {
		err := parseErrorResponse(resp)
		if !errors.Is(err, pkicmp.ErrWaiting) {
			return nil, cmpResp.wrapError(err)
		}
		// RFC 9483 §4.4: a delayed answer to anything but ir, cr, kur and p10cr
		// arrives as an error message with status waiting, and the polls refer
		// to the whole message with certReqId -1.
		var knownSigner *x509.Certificate
		if vr != nil {
			knownSigner = vr.ProtectionCertificate
		}
		state := &pollState{
			delayed: msg.Header, recipNonce: resp.Header.SenderNonce, certReqID: -1, knownSigner: knownSigner,
			response: resp, hooks: &ropts.hooks,
		}
		cmpResp, _, err = c.poll(ctx, state, creds, false)
		if err != nil {
			return nil, err
		}
		resp = cmpResp.message
	}

	if resp.Body.Type != pkicmp.BodyTypeGenP {
		return nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unexpected response body type: %s", resp.Body.Type)})
	}
	content, err := resp.Body.GenP()
	if err != nil {
		return nil, cmpResp.wrapError(&Error{Op: "parse general response", Err: err})
	}
	return []pkicmp.InfoTypeAndValue(*content), nil
}

// sendGeneral sends one general message item and returns the response item of
// the expected info type.
func (c *Client) sendGeneral(ctx context.Context, item pkicmp.InfoTypeAndValue, expected asn1.ObjectIdentifier, creds pkicmp.Credentials, opts []RequestOption) (pkicmp.InfoTypeAndValue, error) {
	items, err := c.SendGenM(ctx, []pkicmp.InfoTypeAndValue{item}, creds, opts...)
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, err
	}
	for _, got := range items {
		if got.InfoType.Equal(expected) {
			return got, nil
		}
	}
	for _, got := range items {
		if !got.InfoType.Equal(pkicmp.InfoTypeUnsupportedOIDs) {
			continue
		}
		oids, err := pkicmp.ParseUnsupportedOIDsInfo(got)
		if err != nil {
			return pkicmp.InfoTypeAndValue{}, &Error{Op: "parse general response", Err: err}
		}
		for _, oid := range oids {
			if oid.Equal(item.InfoType) {
				return pkicmp.InfoTypeAndValue{}, fmt.Errorf("%w: %s", ErrInfoTypeNotSupported, item.InfoType)
			}
		}
	}
	// RFC 9810 §5.3.19 lets a server ignore an info type it does not recognize.
	err = fmt.Errorf("%w: general response carries no %s item", ErrInfoTypeNotSupported, expected)
	return pkicmp.InfoTypeAndValue{}, err
}

// GetCACertificates asks for the intermediate and issuing CA certificates
// (RFC 9483 §4.3.1). None and a nil error mean the server has none available.
//
// The certificates are as trustworthy as the response protection. Validate
// them against a trust anchor before using them to build chains.
func (c *Client) GetCACertificates(ctx context.Context, creds pkicmp.Credentials, opts ...RequestOption) ([]*x509.Certificate, error) {
	request := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}
	got, err := c.sendGeneral(ctx, request, pkicmp.InfoTypeCACerts, creds, opts)
	if err != nil {
		return nil, err
	}
	certs, err := pkicmp.ParseCACertsInfo(got)
	if err != nil {
		return nil, &Error{Op: "parse CA certificates", Err: err}
	}
	return certs, nil
}

// GetRootCAUpdate asks for an update of oldRoot (RFC 9483 §4.3.2) and returns
// it after [pkicmp.RootCAKeyUpdate.Verify] has checked it against oldRoot. A
// nil update and a nil error mean the server has no update.
//
// A nil oldRoot sends no certificate, which RFC 9483 permits when the server
// can tell which root is meant. The update then has nothing to be verified
// against, so GetRootCAUpdate refuses to return it.
func (c *Client) GetRootCAUpdate(ctx context.Context, oldRoot *x509.Certificate, creds pkicmp.Credentials, opts ...RequestOption) (*pkicmp.RootCAKeyUpdate, error) {
	got, err := c.sendGeneral(ctx, pkicmp.NewRootCACertInfo(oldRoot), pkicmp.InfoTypeRootCAKeyUpdate, creds, opts)
	if err != nil {
		return nil, err
	}
	update, err := pkicmp.ParseRootCAKeyUpdateInfo(got)
	if err != nil {
		return nil, &Error{Op: "parse root CA update", Err: err}
	}
	if update == nil {
		return nil, nil
	}
	if oldRoot == nil {
		return nil, &Error{Op: "verify root CA update", Err: errors.New("no old root to verify the update against")}
	}
	if err := update.Verify(oldRoot); err != nil {
		return nil, &Error{Op: "verify root CA update", Err: err}
	}
	return update, nil
}

// GetCertReqTemplate asks for the certificate request template (RFC 9483
// §4.3.3). Name a certificate profile with [WithCertProfile]. A nil template
// and a nil error mean the server imposes no requirements.
func (c *Client) GetCertReqTemplate(ctx context.Context, creds pkicmp.Credentials, opts ...RequestOption) (*pkicmp.CertReqTemplate, error) {
	request := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCertReqTemplate}
	got, err := c.sendGeneral(ctx, request, pkicmp.InfoTypeCertReqTemplate, creds, opts)
	if err != nil {
		return nil, err
	}
	t, err := pkicmp.ParseCertReqTemplateInfo(got)
	if err != nil {
		return nil, &Error{Op: "parse certificate request template", Err: err}
	}
	return t, nil
}

// GetCRLUpdate asks for a CRL newer than the one status describes (RFC 9483
// §4.3.4). A nil CRL and a nil error mean the server has no newer CRL.
//
// The caller must verify the CRL signature against the CRL issuer before
// using it. GetCRLUpdate only rejects a CRL that is not newer than
// status.ThisUpdate, which would otherwise roll the caller back.
func (c *Client) GetCRLUpdate(ctx context.Context, status pkicmp.CRLStatus, creds pkicmp.Credentials, opts ...RequestOption) (*x509.RevocationList, error) {
	item, err := pkicmp.NewCRLStatusListInfo(status)
	if err != nil {
		return nil, &Error{Op: "build CRL update request", Err: err}
	}
	got, err := c.sendGeneral(ctx, item, pkicmp.InfoTypeCRLs, creds, opts)
	if err != nil {
		return nil, err
	}
	crls, err := pkicmp.ParseCRLsInfo(got)
	if err != nil {
		return nil, &Error{Op: "parse CRL update", Err: err}
	}
	switch {
	case len(crls) == 0:
		return nil, nil
	case len(crls) > 1:
		return nil, &Error{Op: fmt.Sprintf("CRL update carries %d CRLs for one status", len(crls))}
	}
	crl := crls[0]
	if !status.ThisUpdate.IsZero() && !crl.ThisUpdate.After(status.ThisUpdate) {
		return nil, &Error{Op: "CRL update is not newer than the CRL held"}
	}
	return crl, nil
}

// GetCurrentCRL asks for the current CRL of the server's choice (RFC 9810
// §5.3.19.6), which RFC 9483 §4.3.4 suggests when the client does not want a
// specific CRL. A nil CRL and a nil error mean the server has none. The caller
// must verify the CRL signature against the CRL issuer before using it.
func (c *Client) GetCurrentCRL(ctx context.Context, creds pkicmp.Credentials, opts ...RequestOption) (*x509.RevocationList, error) {
	request := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCurrentCRL}
	got, err := c.sendGeneral(ctx, request, pkicmp.InfoTypeCurrentCRL, creds, opts)
	if err != nil {
		return nil, err
	}
	crl, err := pkicmp.ParseCurrentCRLInfo(got)
	if err != nil {
		return nil, &Error{Op: "parse current CRL", Err: err}
	}
	return crl, nil
}
