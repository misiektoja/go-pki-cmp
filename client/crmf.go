package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// SendIR performs an Initialization Request (RFC 9810 §5.3.1).
// Typically protected by a shared-secret MAC.
func (c *Client) SendIR(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, creds, pkicmp.BodyTypeIP, opts)
}

// SendCR performs a Certification Request for an additional certificate (RFC 9810 §5.3.3).
// Typically protected by an existing certificate's signature.
func (c *Client) SendCR(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, creds, pkicmp.BodyTypeCP, opts)
}

// SendKUR performs a Key Update Request (RFC 9810 §5.3.5).
// Typically protected by an existing certificate's signature.
func (c *Client) SendKUR(ctx context.Context, newKey crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, newKey, creds, pkicmp.BodyTypeKUP, opts)
}

func (c *Client) sendCRMF(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	pubDER, err := compositex509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, &Error{Op: "marshal public key", Err: err}
	}

	tmpl := pkicmp.CertTemplate{
		PublicKey: pubDER,
	}

	var oldCertificate *x509.Certificate
	if expectedRepType == pkicmp.BodyTypeKUP {
		oldCertificate = ropts.oldCertificate
		if oldCertificate == nil {
			if provider, ok := creds.(interface{ Certificate() *x509.Certificate }); ok {
				oldCertificate = provider.Certificate()
			}
		}
	}

	switch {
	case ropts.templateSubject != nil:
		tmpl.Subject = pkicmp.NewDirectoryName(*ropts.templateSubject)
	case oldCertificate != nil && !hasEmptySubject(oldCertificate):
		// RFC 9483 §4.1.3: a key update keeps the subject of the certificate it replaces.
		tmpl.Subject = certificateSubject(oldCertificate)
	}

	if len(ropts.templateExts) > 0 {
		extDER, err := asn1.Marshal(ropts.templateExts)
		if err != nil {
			return nil, &Error{Op: "marshal extensions", Err: err}
		}
		tmpl.Extensions = extDER
	}

	certReq := pkicmp.CertRequest{
		CertReqID:    0,
		CertTemplate: tmpl,
	}
	if oldCertificate != nil {
		control, err := pkicmp.NewOldCertIDControl(oldCertificate)
		if err != nil {
			return nil, &Error{Op: "encode oldCertID", Err: err}
		}
		certReq.Controls = []pkicmp.AttributeTypeAndValue{control}
	}

	certReqMsg := pkicmp.CertReqMsg{
		CertReq: certReq,
	}

	if err := certReqMsg.GeneratePOP(key); err != nil {
		return nil, &Error{Op: "generate POP", Err: err}
	}

	reqs := pkicmp.CertReqMessages{certReqMsg}
	var body *pkicmp.PKIBody
	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		body = pkicmp.NewIRBody(&reqs)
	case pkicmp.BodyTypeCP:
		body = pkicmp.NewCRBody(&reqs)
	case pkicmp.BodyTypeKUP:
		body = pkicmp.NewKURBody(&reqs)
	default:
		return nil, &Error{Op: fmt.Sprintf("unsupported CRMF expected response type %d", expectedRepType)}
	}

	return c.enroll(ctx, body, expectedRepType, creds, ropts, key.Public())
}

// hasEmptySubject reports whether a certificate names its subject only in subjectAltName.
func hasEmptySubject(cert *x509.Certificate) bool {
	if len(cert.RawSubject) > 0 {
		return bytes.Equal(cert.RawSubject, []byte{0x30, 0x00})
	}
	return len(cert.Subject.ToRDNSequence()) == 0 && len(cert.Subject.Names) == 0
}
