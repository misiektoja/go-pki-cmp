// Package kemcert creates test certificates for keys that crypto/x509 cannot
// certify, such as ML-KEM keys (RFC 9935).
package kemcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CreateCertificate works like x509.CreateCertificate but certifies the DER
// SubjectPublicKeyInfo spki. It lays the certificate out with a placeholder key,
// puts spki in its place and signs the result with priv. The signature
// algorithm must be an ECDSA, RSA PKCS #1 v1.5, RSA-PSS or Ed25519 one.
func CreateCertificate(template, parent *x509.Certificate, spki []byte, priv crypto.Signer) ([]byte, error) {
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &placeholder.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	laid, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tbs, err := replaceSPKI(laid.RawTBSCertificate, spki)
	if err != nil {
		return nil, err
	}
	opts, err := signerOpts(laid.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	digest := tbs
	if h := opts.HashFunc(); h != 0 {
		d := h.New()
		d.Write(tbs)
		digest = d.Sum(nil)
	}
	signature, err := priv.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}

	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	outer := cryptobyte.String(der)
	var cert, sigAlg cryptobyte.String
	if !outer.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.SkipASN1(cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errors.New("kemcert: cannot read the laid-out certificate")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(signature)
	})
	return b.Bytes()
}

// replaceSPKI returns tbs with its subjectPublicKeyInfo, the seventh field, replaced by spki.
func replaceSPKI(tbs, spki []byte) ([]byte, error) {
	s := cryptobyte.String(tbs)
	var fields cryptobyte.String
	if !s.ReadASN1(&fields, cbasn1.SEQUENCE) {
		return nil, errors.New("kemcert: invalid TBSCertificate")
	}
	var b cryptobyte.Builder
	var err error
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version [0], serialNumber, signature, issuer, validity, subject
		for range 6 {
			var field cryptobyte.String
			var tag cbasn1.Tag
			if !fields.ReadAnyASN1Element(&field, &tag) {
				err = errors.New("kemcert: truncated TBSCertificate")
				return
			}
			b.AddBytes(field)
		}
		if !fields.SkipASN1(cbasn1.SEQUENCE) {
			err = errors.New("kemcert: missing subjectPublicKeyInfo")
			return
		}
		b.AddBytes(spki)
		b.AddBytes(fields)
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes()
}

// signerOpts returns the options that make a crypto.Signer produce a signature of algorithm alg.
func signerOpts(alg x509.SignatureAlgorithm) (crypto.SignerOpts, error) {
	switch alg {
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA:
		return crypto.SHA512, nil
	case x509.SHA256WithRSAPSS:
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, nil
	case x509.SHA384WithRSAPSS:
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}, nil
	case x509.SHA512WithRSAPSS:
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}, nil
	case x509.PureEd25519:
		return &ed25519.Options{}, nil
	default:
		return nil, errors.New("kemcert: unsupported signature algorithm " + alg.String())
	}
}
