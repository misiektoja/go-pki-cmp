package mockserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// namedCurves maps the DER namedCurve parameter of an EC key to its curve.
	namedCurves = map[string]elliptic.Curve{
		string(mustMarshalOID(oidNamedCurveP256)):                       elliptic.P256(),
		string(mustMarshalOID(asn1.ObjectIdentifier{1, 3, 132, 0, 34})): elliptic.P384(),
		string(mustMarshalOID(asn1.ObjectIdentifier{1, 3, 132, 0, 35})): elliptic.P521(),
	}
)

// mustMarshalOID returns the DER encoding of oid.
func mustMarshalOID(oid asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return der
}

// KGAKey returns the private key of the key generation authority, which signs centrally generated keys.
func (c *MockCA) KGAKey() *ecdsa.PrivateKey { return c.kgaKey }

// KGACert returns the key generation authority certificate. The CA issued it
// with the id-kp-cmKGA extended key usage that RFC 9483 §4.1.6 requires and
// that OpenSSL checks.
func (c *MockCA) KGACert() *x509.Certificate { return c.kgaCert }

// CentralKeyGeneration returns the server option that answers requests for
// central key generation with keys from [MockCA.GenerateKey], signed by the
// key generation authority.
func (c *MockCA) CentralKeyGeneration() server.Option {
	return server.WithCentralKeyGeneration(c, c.kgaKey, c.kgaCert)
}

// GenerateKey implements server.KeyGenerator. It generates an ECDSA key on
// P-256, P-384 or P-521 or an RSA 2048-bit, Ed25519 or ML-DSA key. A request
// that leaves the algorithm open gets an ECDSA P-256 key.
func (c *MockCA) GenerateKey(_ context.Context, algorithm *pkicmp.AlgorithmIdentifier, _ *server.SenderIdentity) (*server.GeneratedKey, error) {
	var key crypto.Signer
	var err error
	switch {
	case algorithm == nil:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case algorithm.Algorithm.Equal(oidECPublicKey):
		curve := elliptic.P256()
		if len(algorithm.Parameters) > 0 {
			var ok bool
			if curve, ok = namedCurves[string(algorithm.Parameters)]; !ok {
				return nil, badAlg("unsupported curve")
			}
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	case algorithm.Algorithm.Equal(oidRSAEncryption):
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case algorithm.Algorithm.Equal(oidEd25519):
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case algorithm.Algorithm.Equal(oidMLDSA44):
		key, err = mldsa.GenerateKey(mldsa.MLDSA44())
	case algorithm.Algorithm.Equal(oidMLDSA65):
		key, err = mldsa.GenerateKey(mldsa.MLDSA65())
	case algorithm.Algorithm.Equal(oidMLDSA87):
		key, err = mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, badAlg("unsupported key algorithm")
	}
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	c.Log.Info("generated key pair", "algorithm", algorithmName(algorithm))
	return &server.GeneratedKey{PrivateKey: der, PublicKey: key.Public()}, nil
}

// badAlg returns the rejection of a key algorithm the mock CA does not generate.
func badAlg(text string) error {
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg, StatusText: text}
}

// algorithmName names a requested key algorithm for the log.
func algorithmName(algorithm *pkicmp.AlgorithmIdentifier) string {
	if algorithm == nil {
		return "CA choice"
	}
	return algorithm.Algorithm.String()
}

// generateKGA creates the key generation authority key and a certificate the CA issues for it.
func generateKGA(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(pubDER)
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "Test KGA"},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           caCert.NotAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{pkicmp.OIDExtKeyUsageCMKGA},
		SubjectKeyId:       bytes.Clone(h[:20]),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
