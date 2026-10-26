// Package kemcert creates certificates for keys that crypto/x509 cannot
// certify, such as ML-KEM keys (RFC 9935), for the tests and the example mock
// CA, and test certificates and requests signed with keys it cannot sign with,
// such as SLH-DSA keys (RFC 9909).
package kemcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CreateCertificate works like x509.CreateCertificate but certifies the DER
// SubjectPublicKeyInfo spki. It lays the certificate out with a placeholder key,
// puts spki in its place and signs the result with priv. The signature
// algorithm must be an ECDSA, RSA PKCS #1 v1.5, RSA-PSS, Ed25519 or ML-DSA one.
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
	// version [0], serialNumber, signature, issuer, validity and subject come first.
	tbs, err := replaceSPKI(laid.RawTBSCertificate, 6, spki)
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

// CreateSLHDSACertificate works like CreateCertificate for a parent with an
// SLH-DSA key, which crypto/x509 cannot sign with. sigAlg is the parent's RFC
// 9909 identifier, written with absent parameters. A CA template needs its
// SubjectKeyId set, because the placeholder key would otherwise determine it.
func CreateSLHDSACertificate(template, parent *x509.Certificate, spki []byte, sigAlg asn1.ObjectIdentifier, priv crypto.Signer) ([]byte, error) {
	if template.IsCA && len(template.SubjectKeyId) == 0 {
		return nil, errors.New("kemcert: a CA template needs a SubjectKeyId")
	}
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// crypto/x509 checks a parent key against the signer, which is the placeholder here.
	layoutParent := *parent
	layoutParent.PublicKey = nil
	der, err := x509.CreateCertificate(rand.Reader, template, &layoutParent, &placeholder.PublicKey, placeholder)
	if err != nil {
		return nil, err
	}
	laid, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	var alg cryptobyte.Builder
	alg.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(sigAlg) })
	algorithm, err := alg.Bytes()
	if err != nil {
		return nil, err
	}
	// version [0] and serialNumber precede the signature field.
	tbs, err := replaceField(laid.RawTBSCertificate, 2, algorithm)
	if err != nil {
		return nil, err
	}
	if tbs, err = replaceSPKI(tbs, 6, spki); err != nil {
		return nil, err
	}
	signature, err := priv.Sign(rand.Reader, tbs, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(algorithm)
		b.AddASN1BitString(signature)
	})
	return b.Bytes()
}

// replaceField returns a DER SEQUENCE with its field at index replaced by value.
func replaceField(sequence []byte, index int, value []byte) ([]byte, error) {
	s := cryptobyte.String(sequence)
	var fields cryptobyte.String
	if !s.ReadASN1(&fields, cbasn1.SEQUENCE) {
		return nil, errors.New("kemcert: invalid signed structure")
	}
	var b cryptobyte.Builder
	var err error
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := 0; !fields.Empty(); i++ {
			var field cryptobyte.String
			var tag cbasn1.Tag
			if !fields.ReadAnyASN1Element(&field, &tag) {
				err = errors.New("kemcert: truncated signed structure")
				return
			}
			if i == index {
				field = value
			}
			b.AddBytes(field)
		}
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes()
}

// CreateCertificateRequest works like x509.CreateCertificateRequest for a key
// that crypto/x509 cannot sign with. It lays the request out with a placeholder
// key, puts spki in its place and signs the whole CertificationRequestInfo with
// priv. The signature algorithm is sigAlg with absent parameters, as pure
// schemes such as SLH-DSA (RFC 9909 §3) require.
func CreateCertificateRequest(template *x509.CertificateRequest, spki []byte, sigAlg asn1.ObjectIdentifier, priv crypto.Signer) ([]byte, error) {
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, placeholder)
	if err != nil {
		return nil, err
	}
	laid, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	// version and subject come before subjectPKInfo.
	info, err := replaceSPKI(laid.RawTBSCertificateRequest, 2, spki)
	if err != nil {
		return nil, err
	}
	signature, err := priv.Sign(rand.Reader, info, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(info)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sigAlg)
		})
		b.AddASN1BitString(signature)
	})
	return b.Bytes()
}

// replaceSPKI returns tbs with the subjectPublicKeyInfo that follows its first
// before fields replaced by spki.
func replaceSPKI(tbs []byte, before int, spki []byte) ([]byte, error) {
	s := cryptobyte.String(tbs)
	var fields cryptobyte.String
	if !s.ReadASN1(&fields, cbasn1.SEQUENCE) {
		return nil, errors.New("kemcert: invalid signed structure")
	}
	var b cryptobyte.Builder
	var err error
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for range before {
			var field cryptobyte.String
			var tag cbasn1.Tag
			if !fields.ReadAnyASN1Element(&field, &tag) {
				err = errors.New("kemcert: truncated signed structure")
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
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return crypto.Hash(0), nil
	default:
		return nil, errors.New("kemcert: unsupported signature algorithm " + alg.String())
	}
}
