package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
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

// sendCRMF requests a certificate for a signing key, which proves possession by signature.
func (c *Client) sendCRMF(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	pop := func(m *pkicmp.CertReqMsg, ropts *requestOptions) error {
		if err := m.GeneratePOPWithHash(key, ropts.popHash); err != nil {
			return &Error{Op: "generate POP", Err: err}
		}
		return nil
	}
	return c.sendCertRequest(ctx, key.Public(), pop, nil, creds, expectedRepType, opts)
}

// sendCertRequest requests a certificate for pub in an ir, cr or kur. pop adds
// the proof of possession to the finished request under the request options,
// and proof is the key that answers an indirect one. pub is nil when the
// request asks the CA to generate the key pair.
func (c *Client) sendCertRequest(ctx context.Context, pub crypto.PublicKey, pop func(*pkicmp.CertReqMsg, *requestOptions) error, proof *decryptionProof, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}
	if ropts.certReqID < 0 {
		return nil, &Error{Op: "build request", Err: fmt.Errorf("certReqId %d is negative", ropts.certReqID)}
	}

	var tmpl pkicmp.CertTemplate
	switch {
	case !ropts.centralKeyGeneration:
		pubDER, err := pkicmp.MarshalPublicKey(pub)
		if err != nil {
			return nil, &Error{Op: "marshal public key", Err: err}
		}
		tmpl.PublicKey = pubDER
	case ropts.centralKeyAlgorithm != nil:
		// RFC 9483 §4.1.6: the algorithm with a zero-length key states a preference.
		tmpl.PublicKey = pkicmp.CentralKeyGenerationPublicKey(*ropts.centralKeyAlgorithm)
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

	extensions := ropts.templateExts
	if len(tmpl.Subject.DirectoryName) == 0 && len(tmpl.Subject.Raw) == 0 {
		// RFC 9483 §4.1.3: a key update repeats the name of the certificate it
		// replaces, which for an empty subject is its subjectAltName.
		if oldCertificate != nil && !hasSubjectAltName(extensions) {
			if san, ok := subjectAltNameOf(oldCertificate); ok {
				extensions = append(slices.Clone(extensions), san)
			}
		}
		// RFC 9483 §4.1.1: an entity named only in subjectAltName has a NULL-DN subject.
		if hasSubjectAltName(extensions) {
			tmpl.Subject = pkicmp.NewDirectoryNameFromRawDER([]byte{0x30, 0x00})
		}
	}

	if len(extensions) > 0 {
		extDER, err := asn1.Marshal(extensions)
		if err != nil {
			return nil, &Error{Op: "marshal extensions", Err: err}
		}
		tmpl.Extensions = extDER
	}

	certReq := pkicmp.CertRequest{
		CertReqID:    ropts.certReqID,
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

	if err := pop(&certReqMsg, ropts); err != nil {
		return nil, err
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

	return c.enroll(ctx, body, expectedRepType, creds, ropts, pub, proof)
}

// oidSubjectAltName identifies the RFC 5280 §4.2.1.6 subjectAltName extension.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// hasSubjectAltName reports whether extensions include a subjectAltName.
func hasSubjectAltName(extensions []pkix.Extension) bool {
	return slices.ContainsFunc(extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(oidSubjectAltName) })
}

// subjectAltNameOf returns the subjectAltName extension of an empty-subject certificate with its encoded value.
func subjectAltNameOf(cert *x509.Certificate) (pkix.Extension, bool) {
	if !hasEmptySubject(cert) {
		return pkix.Extension{}, false
	}
	i := slices.IndexFunc(cert.Extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(oidSubjectAltName) })
	if i < 0 {
		return pkix.Extension{}, false
	}
	return cert.Extensions[i], true
}

// hasEmptySubject reports whether a certificate names its subject only in subjectAltName.
func hasEmptySubject(cert *x509.Certificate) bool {
	if len(cert.RawSubject) > 0 {
		return bytes.Equal(cert.RawSubject, []byte{0x30, 0x00})
	}
	return len(cert.Subject.ToRDNSequence()) == 0 && len(cert.Subject.Names) == 0
}
