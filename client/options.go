package client

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

type requestOptions struct {
	// cmp2021 sends the first request as pvno 3, because the response it
	// expects needs cmp2021 syntax (RFC 9810 §7).
	cmp2021         bool
	sender          *pkix.Name
	senderKID       []byte
	templateSubject *pkix.Name
	templateExts    []pkix.Extension
	// templateValidity is the validity period an ir, cr or kur asks for. Nil asks for none.
	templateValidity *pkicmp.OptionalValidity
	oldCertificate   *x509.Certificate
	certProfile      string
	generalInfo      []pkicmp.InfoTypeAndValue
	certReqID        int64
	popHash          crypto.Hash
	implicitConfirm  bool
	// invalidityDate is the invalidityDate CRL entry extension of an rr. Zero sends none.
	invalidityDate time.Time
	// deferredPolling returns the pending state of a waiting enrollment instead of polling.
	deferredPolling bool
	// centralKeyGeneration asks the CA to generate the key pair, of the
	// algorithm centralKeyAlgorithm or of the CA's choice when it is nil.
	centralKeyGeneration bool
	centralKeyAlgorithm  *pkicmp.AlgorithmIdentifier
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

// WithTemplateValidity asks for a validity period in the CRMF CertTemplate of
// an ir, cr or kur (RFC 4211 §5). A zero notBefore or notAfter leaves that
// bound to the CA, and two zero times ask for none. The request fails when
// notAfter is before notBefore. The CA decides the validity it grants and may
// shorten or ignore the request. RFC 9483 does not profile the field, so a
// lightweight CMP server need not honor it. A p10cr ignores the option,
// because PKCS #10 cannot carry it.
func WithTemplateValidity(notBefore, notAfter time.Time) RequestOption {
	return func(o *requestOptions) {
		o.templateValidity = &pkicmp.OptionalValidity{NotBefore: notBefore, NotAfter: notAfter}
	}
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

// WithGeneralInfo adds items to the generalInfo field of the request header
// (RFC 9810 §5.1.1), after the certProfile of [WithCertProfile]. Use it for
// items a CA defines itself, such as a vendor profile identifier. Later
// messages of the transaction do not repeat them.
func WithGeneralInfo(items ...pkicmp.InfoTypeAndValue) RequestOption {
	return func(o *requestOptions) { o.generalInfo = append(o.generalInfo, items...) }
}

// WithCertReqID sets the certReqId of an ir, cr or kur (RFC 4211 §5). The
// default is 0. The CA must repeat the value in its certificate response,
// which the client checks before it confirms the certificate. A negative
// value is refused, because RFC 9810 §5.3.4 reserves -1 for the answer to a
// p10cr. A p10cr ignores the option.
func WithCertReqID(id int64) RequestOption {
	return func(o *requestOptions) { o.certReqID = id }
}

// WithPOPHash selects the digest of the signature proof of possession of an
// ir, cr or kur for an RSA or ECDSA key: SHA-1, SHA-256, SHA-384 or SHA-512.
// Without it the digest follows the key type, as it does for the message
// protection of [pkicmp.NewSignatureCredentials]. Other key types take no
// digest and the request fails. A p10cr and the indirect proofs of
// [Client.SendIRWithIndirectPOP] ignore the option.
func WithPOPHash(hash crypto.Hash) RequestOption {
	return func(o *requestOptions) { o.popHash = hash }
}

// WithImplicitConfirm asks the CA for implicit confirmation of an ir, cr, kur
// or p10cr by adding id-it-implicitConfirm to the generalInfo field of the
// request header (RFC 9810 §5.1.1.1), before the certProfile. A CA that
// grants it repeats the item in its certificate response, and the client then
// returns without sending certConf, with [EnrollResult.ImplicitConfirm] set.
// A CA that wants an explicit confirmation leaves the item out and the client
// confirms as usual. RFC 9483 §4.1.1 asks an end entity to request it unless
// it needs the confirmation. Revocation and general messages ignore the
// option.
func WithImplicitConfirm() RequestOption {
	return func(o *requestOptions) { o.implicitConfirm = true }
}

// WithInvalidityDate adds the invalidityDate CRL entry extension (RFC 5280
// §5.3.2) to a revocation request: the time at which the key is known or
// suspected to have been compromised or the certificate otherwise became
// invalid, which the CA may publish in the CRL entry. It is sent as a
// GeneralizedTime in UTC with a resolution of one second. The zero time sends
// none. Enrollment and general messages ignore the option.
func WithInvalidityDate(t time.Time) RequestOption {
	return func(o *requestOptions) { o.invalidityDate = t }
}

// WithDeferredPolling stops an ir, cr, kur or p10cr at the first answer that
// says the request waits (RFC 9810 §5.3.22) instead of polling until the CA
// decides. The call then returns an [EnrollResult] whose Pending field holds
// the transaction state and whose other fields are empty. Save the state and
// continue later with [Client.ResumeEnrollment], which under this option sends
// one pollReq and returns the state again while the CA still waits. Revocation
// and general messages ignore the option.
func WithDeferredPolling() RequestOption {
	return func(o *requestOptions) { o.deferredPolling = true }
}
