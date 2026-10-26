package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/internal/certpath"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// GeneratedKey is a private key the CA generated for the client (RFC 9483 §4.1.6).
type GeneratedKey struct {
	// PrivateKey is the parsed private key, such as *rsa.PrivateKey,
	// *ecdsa.PrivateKey, ed25519.PrivateKey, *mldsa.PrivateKey or a composite
	// ML-DSA key. It is nil for a key type the client cannot parse, such as
	// ML-KEM. PKCS8 then holds the key.
	PrivateKey crypto.PrivateKey
	// PKCS8 is the DER PKCS #8 private key. A OneAsymmetricKey (RFC 5958) from
	// the CA keeps its version 2 encoding with the public key.
	PKCS8 []byte
	// Signer is the certificate of the key generation authority that signed the key.
	Signer *x509.Certificate
}

// SendIRWithCentralKeyGeneration performs an Initialization Request (RFC 9810
// §5.3.1) that asks the CA to generate the key pair (RFC 9483 §4.1.6). See
// [Client.SendCRWithCentralKeyGeneration].
func (c *Client) SendIRWithCentralKeyGeneration(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCentralKeyGeneration(ctx, algorithm, creds, pkicmp.BodyTypeIP, opts)
}

// SendCRWithCentralKeyGeneration performs a Certification Request (RFC 9810
// §5.3.3) that asks the CA to generate the key pair (RFC 9483 §4.1.6).
//
// algorithm is the key algorithm to ask for, such as id-ecPublicKey with the
// named curve as its parameters. nil leaves the choice to the CA. The
// certificate template carries the algorithm with an empty public key. The
// request carries no proof of possession. It is sent with protocol version 3.
//
// The CA returns the private key signed by a key generation authority and
// encrypted for the client: to the shared secret of [pkicmp.MACCredentials],
// or to the key of [pkicmp.SignatureCredentials], which must then be an RSA
// key or an ECDSA key on P-256, P-384 or P-521. Other credentials cannot
// receive a key. [EnrollResult.GeneratedKey] holds the key, which must
// certify the issued certificate's public key.
//
// When the client has trusted CAs, see [WithTrustedCAs], the signer
// certificate must chain to them and assert id-kp-cmKGA, be a CA certificate or
// be the certificate that protected the response. A client without trusted
// CAs relies on the MAC that protected the response, as RFC 9483 §4.1.6 allows.
func (c *Client) SendCRWithCentralKeyGeneration(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCentralKeyGeneration(ctx, algorithm, creds, pkicmp.BodyTypeCP, opts)
}

// SendKURWithCentralKeyGeneration performs a Key Update Request (RFC 9810
// §5.3.5) that asks the CA to generate the new key pair (RFC 9483 §4.1.6). See
// [Client.SendCRWithCentralKeyGeneration].
func (c *Client) SendKURWithCentralKeyGeneration(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCentralKeyGeneration(ctx, algorithm, creds, pkicmp.BodyTypeKUP, opts)
}

// sendCentralKeyGeneration requests a certificate for a key pair the CA generates.
func (c *Client) sendCentralKeyGeneration(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	if _, err := keyDecryptionKey(creds); err != nil {
		return nil, &Error{Op: "central key generation", Err: err}
	}
	central := func(o *requestOptions) {
		o.centralKeyGeneration = true
		o.centralKeyAlgorithm = algorithm
	}
	// RFC 9483 §4.1.6: the request carries no proof of possession.
	noPOP := func(*pkicmp.CertReqMsg, *requestOptions) error { return nil }
	return c.sendCertRequest(ctx, nil, noPOP, nil, creds, expectedRepType, append(slices.Clone(opts), central))
}

// keyDecryptionKey returns what decrypts a private key the CA encrypted for the holder of creds.
func keyDecryptionKey(creds pkicmp.Credentials) (any, error) {
	switch cr := creds.(type) {
	case *pkicmp.MACCredentials:
		return cms.Password(cr.SharedSecret()), nil
	case *pkicmp.SignatureCredentials:
		if _, _, err := decryptionPublicKey(cr.Key()); err != nil {
			return nil, errors.New("the protection key cannot receive an encrypted private key: " + err.Error())
		}
		return cr.Key(), nil
	default:
		return nil, errors.New("only MAC or signature credentials can receive an encrypted private key")
	}
}

// openGeneratedKey decrypts and checks the private key of a central key
// generation response, which must match the public key of cert. roots and
// candidates validate the signer of the key package when roots is not nil, and
// responder is the certificate that protected the response.
func (c *Client) openGeneratedKey(certResp *pkicmp.CertResponse, cert *x509.Certificate, creds pkicmp.Credentials, roots *x509.CertPool, candidates []*x509.Certificate, responder *x509.Certificate) (*GeneratedKey, error) {
	envelope := certResp.CertifiedKeyPair.EncryptedPrivateKey()
	if envelope == nil {
		if certResp.CertifiedKeyPair.PrivateKey != nil {
			return nil, &Error{Op: "the CA returned the private key as EncryptedValue, which is not supported"}
		}
		return nil, &Error{Op: "the CA returned no private key"}
	}
	kdk, err := keyDecryptionKey(creds)
	if err != nil {
		return nil, &Error{Op: "decrypt private key", Err: err}
	}
	signedData, err := cms.Decrypt(envelope, kdk)
	if err != nil {
		return nil, &Error{Op: "decrypt private key", Err: err}
	}
	pkg, err := pkicmp.ParseKeyPackage(signedData, pkicmp.KeyPackageOptions{AllowSHA1Signatures: c.allowSHA1Signatures})
	if err != nil {
		return nil, &Error{Op: "verify private key signature", Err: err}
	}
	if roots != nil {
		if err := certpath.Verify(pkg.Signer, roots, slices.Concat(pkg.Certificates, candidates), time.Now()); err != nil {
			return nil, &Error{Op: "verify key generation authority", Err: err}
		}
		if !pkicmp.IsKeyGenerationAuthority(pkg.Signer) && (responder == nil || !responder.Equal(pkg.Signer)) {
			return nil, &Error{Op: "the private key signer is not a key generation authority"}
		}
	}
	key, pkcs8, err := parseGeneratedKey(pkg.PrivateKey)
	if err != nil {
		return nil, &Error{Op: "parse private key", Err: err}
	}
	if err := checkGeneratedKey(key, pkcs8, cert); err != nil {
		return nil, err
	}
	return &GeneratedKey{PrivateKey: key, PKCS8: pkcs8, Signer: pkg.Signer}, nil
}

// parseGeneratedKey parses the private key of a key package: a PKCS #8 or
// OneAsymmetricKey or the PKCS #1 or SEC 1 key that OpenSSL sends as id-data.
// It returns the parsed key and the key as PKCS #8. The parsed key is nil for
// an unknown PKCS #8 key type.
func parseGeneratedKey(der []byte) (crypto.PrivateKey, []byte, error) {
	if isPKCS8(der) {
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return key, der, nil
		}
		if key, err := compositex509.ParsePKCS8PrivateKey(der); err == nil {
			return key, der, nil
		}
		return nil, der, nil
	}
	var key crypto.PrivateKey
	var err error
	if key, err = x509.ParseECPrivateKey(der); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(der); err != nil {
			return nil, nil, errors.New("unsupported private key encoding")
		}
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pkcs8, nil
}

// isPKCS8 reports whether der has the outline of a PKCS #8 PrivateKeyInfo or
// OneAsymmetricKey: a version, an AlgorithmIdentifier and an OCTET STRING.
func isPKCS8(der []byte) bool {
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	var version int64
	return s.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1Integer(&version) &&
		seq.SkipASN1(cbasn1.SEQUENCE) && seq.PeekASN1Tag(cbasn1.OCTET_STRING)
}

// checkGeneratedKey checks that the generated key belongs to the public key
// of cert. An unparsed key is checked through the public key that a
// OneAsymmetricKey version 2 carries.
func checkGeneratedKey(key crypto.PrivateKey, pkcs8 []byte, cert *x509.Certificate) error {
	certKey, err := pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return &Error{Op: "cannot parse the public key of the issued certificate"}
	}
	if signer, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		if !pkicmp.PublicKeysEqual(signer.Public(), certKey) {
			return &Error{Op: "the generated private key does not match the issued certificate"}
		}
		return nil
	}
	alg, publicKey, ok := oneAsymmetricKeyPublicKey(pkcs8)
	if !ok {
		return &Error{Op: "the generated private key carries no public key to check against the certificate"}
	}
	certAlg, certPublicKey, ok := spkiParts(cert.RawSubjectPublicKeyInfo)
	if !ok || !bytes.Equal(alg, certAlg) || !bytes.Equal(publicKey, certPublicKey) {
		return &Error{Op: "the generated private key does not match the issued certificate"}
	}
	return nil
}

// oneAsymmetricKeyPublicKey returns the DER algorithm and the publicKey
// content octets of a OneAsymmetricKey version 2.
func oneAsymmetricKeyPublicKey(der []byte) ([]byte, []byte, bool) {
	s := cryptobyte.String(der)
	var seq, alg, publicKey cryptobyte.String
	var version int64
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&version) || version != 1 ||
		!seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) || !seq.SkipASN1(cbasn1.OCTET_STRING) ||
		!seq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed()) ||
		!seq.ReadASN1(&publicKey, cbasn1.Tag(1).ContextSpecific()) {
		return nil, nil, false
	}
	return alg, publicKey, true
}

// spkiParts returns the DER algorithm and the subjectPublicKey content octets of a SubjectPublicKeyInfo.
func spkiParts(der []byte) ([]byte, []byte, bool) {
	s := cryptobyte.String(der)
	var seq, alg, publicKey cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) ||
		!seq.ReadASN1(&publicKey, cbasn1.BIT_STRING) {
		return nil, nil, false
	}
	return alg, publicKey, true
}
