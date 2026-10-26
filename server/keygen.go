package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// KeyGenerator generates the key pair of a request for central key generation
// (RFC 9483 §4.1.6), see [WithCentralKeyGeneration].
type KeyGenerator interface {
	// GenerateKey returns a new key pair for the requester. algorithm is the
	// key algorithm the certificate template asks for with the parameters it
	// gives. It is nil when the template leaves the choice to the server.
	// Return an [*Error] with badAlg for an algorithm the generator does not
	// support.
	GenerateKey(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, sender *SenderIdentity) (*GeneratedKey, error)
}

// KeyGeneratorFunc adapts a function to the KeyGenerator interface.
type KeyGeneratorFunc func(context.Context, *pkicmp.AlgorithmIdentifier, *SenderIdentity) (*GeneratedKey, error)

// GenerateKey calls f.
func (f KeyGeneratorFunc) GenerateKey(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, sender *SenderIdentity) (*GeneratedKey, error) {
	return f(ctx, algorithm, sender)
}

// GeneratedKey is a key pair a [KeyGenerator] made.
type GeneratedKey struct {
	// PrivateKey is the DER PKCS #8 private key. It may be a OneAsymmetricKey
	// (RFC 5958) that already carries the public key.
	PrivateKey []byte
	// PublicKey is the public key of the pair, of a type [pkicmp.MarshalPublicKey] encodes.
	PublicKey crypto.PublicKey
}

// WithCentralKeyGeneration lets a client ask the server to generate its key
// pair (RFC 9483 §4.1.6). The certificate template of such an ir, cr or kur
// has no public key or a public key with an algorithm and an empty key. The
// request has no proof of possession. The server has gen generate the pair and signs
// the private key with key. Its certificate cert must assert id-kp-cmKGA or be
// a CA certificate. OpenSSL accepts only a signer with id-kp-cmKGA. The signed
// key is encrypted for the requester and returned in the privateKey field of
// the certificate response. [New] reports through [Server.Err] a key that does
// not match cert or a cert that may not sign key packages.
//
// The signed content is the private key itself as id-data, the form OpenSSL
// writes and reads, unless [WithCentralKeyGenerationAsymmetricKeyPackage] is
// given.
//
// The private key is encrypted to the shared secret of a MAC-protected request,
// with PBKDF2 and the RFC 3211 key wrap that OpenSSL reads, unless
// [WithCentralKeyGenerationAESKeyWrap] is given. A signature-protected request
// gets it encrypted for the key of its protection certificate, which must be an
// RSA key or an ECDSA key on P-256, P-384 or P-521. The certificate's key usage
// is not checked.
//
// The [Handler] and [CA.IssueCertificate] see [POPCentralKeyGeneration] through
// [POPMethodFromContext]. The template the built-in CA handler passes carries
// the generated public key. A custom [Handler] gets it from
// [GeneratedPublicKeyFromContext] and must certify that key. The response is
// withheld when the certificate does not certify it.
func WithCentralKeyGeneration(gen KeyGenerator, key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) Option {
	return func(c *serverConfig) {
		c.keyGenerator = gen
		c.kgaKey = key
		c.kgaCert = cert
		c.kgaChain = chain
	}
}

// WithCentralKeyGenerationAESKeyWrap encrypts a centrally generated private
// key for a MAC-protected request with the AES-256 key wrap of RFC 9481 §4.3
// instead of the RFC 3211 key wrap. OpenSSL clients cannot read the result.
func WithCentralKeyGenerationAESKeyWrap() Option {
	return func(c *serverConfig) {
		c.kgaAESKeyWrap = true
	}
}

// WithCentralKeyGenerationAsymmetricKeyPackage signs a centrally generated
// private key as an AsymmetricKeyPackage with the id-ct-KP-aKeyPackage content
// type, as RFC 9810 §5.2.2 and RFC 9483 §4.1.6 specify, instead of as id-data.
// OpenSSL clients cannot read the result.
func WithCentralKeyGenerationAsymmetricKeyPackage() Option {
	return func(c *serverConfig) {
		c.kgaKeyPackage = pkicmp.KeyPackageAsymmetricKeyPackage
	}
}

// checkKeyGeneration reports why the central key generation settings cannot work.
func (c *serverConfig) checkKeyGeneration() error {
	if c.keyGenerator == nil && c.kgaKey == nil && c.kgaCert == nil {
		return nil
	}
	if c.keyGenerator == nil {
		return errors.New("server: central key generation needs a key generator")
	}
	if _, err := pkicmp.NewSignatureCredentials(c.kgaKey, c.kgaCert); err != nil {
		return errors.New("server: the key generation authority key does not match its certificate")
	}
	if !pkicmp.IsKeyGenerationAuthority(c.kgaCert) {
		return errors.New("server: the key generation authority certificate asserts neither id-kp-cmKGA nor a CA")
	}
	return nil
}

// generatedKeyKey is the context key that carries the public key of a centrally generated key pair.
type generatedKeyKey struct{}

// contextWithGeneratedPublicKey records the public key the server generated for the request ctx serves.
func contextWithGeneratedPublicKey(ctx context.Context, pub crypto.PublicKey) context.Context {
	return context.WithValue(ctx, generatedKeyKey{}, pub)
}

// GeneratedPublicKeyFromContext returns the public key of the key pair the
// server generated for a request with [POPCentralKeyGeneration]. It returns
// nil for any other request. The server sets it for [Handler.HandleCMP] and
// [CA.IssueCertificate].
func GeneratedPublicKeyFromContext(ctx context.Context) crypto.PublicKey {
	return ctx.Value(generatedKeyKey{})
}

// centralKey is a generated key pair, ready to deliver.
type centralKey struct {
	publicKey crypto.PublicKey
	// spki is the DER SubjectPublicKeyInfo of publicKey.
	spki []byte
	// envelope is the DER EnvelopedData of the signed private key, encrypted for the requester.
	envelope []byte
}

// generateKey answers a request for central key generation: it generates the
// key pair, then passes the request to the handler with the public key in ctx.
func (s *Server) generateKey(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity, credID []byte, req certRequestInfo) *pkicmp.PKIMessage {
	key, err := s.newCentralKey(ctx, msg, sender)
	if err != nil {
		return s.buildCertRep(msg, sender, certRep{
			certReqID: req.certReqID,
			status:    errorToStatusInfo(err),
			reqType:   req.reqType,
		})
	}
	req.privateKey = key.envelope
	req.generatedKey = key.spki
	return s.issue(contextWithGeneratedPublicKey(ctx, key.publicKey), msg, msg, sender, credID, req)
}

// newCentralKey generates the key pair msg asks for and protects its private
// key for sender. Errors are [*Error] values for the certificate response.
func (s *Server) newCentralKey(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*centralKey, error) {
	if s.cfg.keyGenerator == nil {
		// Without a generator the request is one that forgot its key.
		return nil, rejection(pkicmp.FailBadCertTemplate, "public key required")
	}
	if s.cfg.kgaErr != nil {
		return nil, rejection(pkicmp.FailSystemFailure, "central key generation is not available")
	}
	msgs, err := msg.Body.CertReqMessages()
	if err != nil || len(*msgs) != 1 {
		return nil, rejection(pkicmp.FailBadDataFormat, "malformed certificate request")
	}
	reqMsg := (*msgs)[0]
	// RFC 9483 §4.1.6: there is no key to prove possession of.
	if reqMsg.Popo != nil {
		return nil, rejection(pkicmp.FailBadPOP, "a request for central key generation must not carry a proof of possession")
	}
	algorithm, _ := reqMsg.CertReq.CertTemplate.RequestsCentralKeyGeneration()
	recipient, rid, err := s.keyRecipient(sender)
	if err != nil {
		return nil, err
	}

	gk, err := s.cfg.keyGenerator.GenerateKey(ctx, algorithm, sender)
	if err != nil {
		return nil, err
	}
	failure := rejection(pkicmp.FailSystemFailure, "central key generation failed")
	if gk == nil || gk.PublicKey == nil {
		return nil, failure
	}
	spki, err := pkicmp.MarshalPublicKey(gk.PublicKey)
	if err != nil {
		return nil, failure
	}
	if algorithm != nil && !keyHasAlgorithm(spki, algorithm) {
		return nil, rejection(pkicmp.FailBadAlg, "the generated key does not have the requested algorithm")
	}
	privateKey, err := oneAsymmetricKey(gk.PrivateKey, spki)
	if err != nil {
		return nil, failure
	}
	signed, err := pkicmp.NewKeyPackage(privateKey, s.cfg.kgaKeyPackage, s.cfg.kgaKey, s.cfg.kgaCert, s.cfg.kgaChain...)
	if err != nil {
		return nil, failure
	}
	envelope, err := cms.EncryptSignedData(signed, recipient, rid)
	if err != nil {
		return nil, failure
	}
	return &centralKey{publicKey: gk.PublicKey, spki: spki, envelope: envelope}, nil
}

// keyRecipient returns the recipient a generated private key is encrypted for:
// the shared secret of a MAC-protected request or the key of the protection
// certificate (RFC 9483 §4.1.6.1 to §4.1.6.3).
func (s *Server) keyRecipient(sender *SenderIdentity) (any, cms.RecipientID, error) {
	if sender != nil && sender.MACVerified && len(sender.secret) > 0 {
		if s.cfg.kgaAESKeyWrap {
			return cms.Password(sender.secret), cms.RecipientID{}, nil
		}
		return cms.PWRIKEKPassword(sender.secret), cms.RecipientID{}, nil
	}
	if sender == nil || sender.Certificate == nil {
		return nil, cms.RecipientID{}, rejection(pkicmp.FailBadRequest, "central key generation needs a protected request")
	}
	cert := sender.Certificate
	pub := certificatePublicKey(cert)
	if !encryptableKey(pub) {
		return nil, cms.RecipientID{}, rejection(pkicmp.FailBadAlg,
			"the protection certificate key cannot receive an encrypted private key")
	}
	// RFC 9483 §4.1.6.1: the subjectKeyIdentifier when the certificate has one.
	if len(cert.SubjectKeyId) > 0 {
		return pub, cms.RecipientID{SubjectKeyID: cert.SubjectKeyId}, nil
	}
	return pub, cms.IssuerAndSerial(cert), nil
}

// keyHasAlgorithm reports whether the SubjectPublicKeyInfo spki has the
// algorithm a template asked for, with its parameters when it gave any.
func keyHasAlgorithm(spki []byte, want *pkicmp.AlgorithmIdentifier) bool {
	got, ok := spkiAlgorithm(spki)
	if !ok || !got.Algorithm.Equal(want.Algorithm) {
		return false
	}
	return len(want.Parameters) == 0 || bytes.Equal(got.Parameters, want.Parameters)
}

// spkiAlgorithm returns the algorithm of a DER SubjectPublicKeyInfo.
func spkiAlgorithm(spki []byte) (pkicmp.AlgorithmIdentifier, bool) {
	var alg pkicmp.AlgorithmIdentifier
	s := cryptobyte.String(spki)
	var seq, algSeq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&algSeq, cbasn1.SEQUENCE) ||
		!algSeq.ReadASN1ObjectIdentifier(&alg.Algorithm) {
		return alg, false
	}
	if !algSeq.Empty() {
		alg.Parameters = algSeq
	}
	return alg, true
}

// algorithmOf returns the OID of a DER AlgorithmIdentifier.
func algorithmOf(der []byte) (asn1.ObjectIdentifier, bool) {
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	var oid asn1.ObjectIdentifier
	ok := s.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1ObjectIdentifier(&oid)
	return oid, ok
}

// oneAsymmetricKey returns the PKCS #8 key privateKey as the OneAsymmetricKey
// version 2 with the public key that RFC 9483 §4.1.6 requires. The public key
// is the subjectPublicKey of spki. A version 2 key keeps its own public key.
func oneAsymmetricKey(privateKey, spki []byte) ([]byte, error) {
	malformed := errors.New("server: malformed generated private key")
	s := cryptobyte.String(privateKey)
	var seq, alg, key, attrs cryptobyte.String
	var version int64
	var hasAttrs bool
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() || !seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&key, cbasn1.OCTET_STRING) ||
		!seq.ReadOptionalASN1(&attrs, &hasAttrs, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, malformed
	}
	keyAlg, ok1 := spkiAlgorithm(spki)
	privateKeyAlg, ok2 := algorithmOf(alg)
	if !ok1 || !ok2 {
		return nil, malformed
	}
	if !privateKeyAlg.Equal(keyAlg.Algorithm) {
		return nil, errors.New("server: the generated private and public keys have different algorithms")
	}
	switch {
	case version == 1 && seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific()):
		return privateKey, nil
	case version != 0 || !seq.Empty():
		return nil, malformed
	}

	var spkiSeq, bits cryptobyte.String
	in := cryptobyte.String(spki)
	if !in.ReadASN1(&spkiSeq, cbasn1.SEQUENCE) || !spkiSeq.SkipASN1(cbasn1.SEQUENCE) ||
		!spkiSeq.ReadASN1(&bits, cbasn1.BIT_STRING) {
		return nil, malformed
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddBytes(alg)
		b.AddBytes(key)
		if hasAttrs {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
		}
		// publicKey [1] IMPLICIT BIT STRING keeps the content octets, unused-bits count first.
		b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(bits) })
	})
	return b.Bytes()
}
