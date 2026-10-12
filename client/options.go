package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

type requestOptions struct {
	sender          *pkix.Name
	senderKID       []byte
	templateSubject *pkix.Name
	templateExts    []pkix.Extension
	oldCertificate  *x509.Certificate
	certProfile     string
}

// RequestOption configures a specific enrollment request.
type RequestOption func(*requestOptions)

// WithSender sets the sender name in the PKIHeader. Without it, a signed request names the
// subject of its protection certificate, encoded as in that certificate.
func WithSender(name pkix.Name) RequestOption {
	return func(o *requestOptions) { o.sender = &name }
}

// WithSenderKID sets the PKIHeader senderKID field for all outgoing messages
// in this request. For MAC-protected requests, this carries the reference
// number that identifies the shared secret to the recipient
// (RFC 9810 §5.1.1, RFC 4210 §5.1.3.1).
func WithSenderKID(kid []byte) RequestOption {
	return func(o *requestOptions) { o.senderKID = kid }
}

// WithTemplateSubject sets the subject name in the CRMF CertTemplate. Without it, a key update
// repeats the old certificate's subject as encoded in that certificate, as RFC 9483 §4.1.3
// requires. A template that names the entity only in a subjectAltName extension, including
// the key update of a certificate with an empty subject, gets a NULL-DN subject as RFC 9483
// §4.1.1 requires.
func WithTemplateSubject(subject pkix.Name) RequestOption {
	return func(o *requestOptions) { o.templateSubject = &subject }
}

// WithTemplateExtension adds an extension to the CRMF CertTemplate. A key update of a
// certificate with an empty subject adds that certificate's subjectAltName unless one is set.
func WithTemplateExtension(ext pkix.Extension) RequestOption {
	return func(o *requestOptions) { o.templateExts = append(o.templateExts, ext) }
}

// WithCertProfile names the certificate profile in the id-it-certProfile
// generalInfo header field (RFC 9483 §3.1). It selects the profile of an
// enrollment or the template [Client.GetCertReqTemplate] asks for.
func WithCertProfile(name string) RequestOption {
	return func(o *requestOptions) { o.certProfile = name }
}

// WithOldCertificate overrides the certificate identified by the oldCertID control in a KUR.
func WithOldCertificate(certificate *x509.Certificate) RequestOption {
	return func(o *requestOptions) { o.oldCertificate = certificate }
}
