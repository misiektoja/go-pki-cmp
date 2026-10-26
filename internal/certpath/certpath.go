// Package certpath verifies certification paths that contain composite ML-DSA
// or SLH-DSA signatures, which crypto/x509 cannot check.
package certpath

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"time"

	"github.com/misiektoja/go-pki-cmp/internal/keylimit"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
)

// maxDepth bounds the number of composite or SLH-DSA links followed below a trusted path.
const maxDepth = 8

// maxSignatureChecks bounds the composite and SLH-DSA signature checks of one verification,
// as crypto/x509 bounds its own, so that crafted candidates sharing a name and
// key cannot force an exponential search.
const maxSignatureChecks = 100

// oidNameConstraints identifies the name constraints extension (RFC 5280 §4.2.1.10).
var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// errUntrusted reports that no path reached a trust anchor.
var errUntrusted = errors.New("certificate does not chain to a trusted certificate")

// Verify checks that cert chains to a certificate in roots, taking issuers from
// candidates. Paths without composite or SLH-DSA signatures are checked by
// crypto/x509 alone. Such a link is followed only when its issuer is in candidates,
// because a CertPool cannot return the anchor it holds. Such paths are refused
// when a certificate in them carries name constraints, which this check cannot
// enforce. A candidate whose RSA key exceeds keylimit.MaxRSAModulusBits is
// ignored, because crypto/x509 would otherwise verify signatures with it.
func Verify(cert *x509.Certificate, roots *x509.CertPool, candidates []*x509.Certificate, now time.Time) error {
	candidates = slices.DeleteFunc(slices.Clone(candidates), func(c *x509.Certificate) bool {
		return keylimit.Check(c.PublicKey) != nil
	})
	intermediates := x509.NewCertPool()
	for _, candidate := range candidates {
		intermediates.AddCert(candidate)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	}
	_, err := cert.Verify(opts)
	if err == nil {
		return nil
	}
	s := &search{
		candidates: candidates,
		opts:       opts,
		checksLeft: maxSignatureChecks,
		upper:      make(map[string][][]*x509.Certificate),
		onPath:     make(map[string]bool),
	}
	if s.trusted(cert, 0) {
		return nil
	}
	return errors.Join(errUntrusted, err)
}

// search holds the state of one path search below the trust anchors.
type search struct {
	candidates []*x509.Certificate
	opts       x509.VerifyOptions
	checksLeft int
	// upper caches the chains crypto/x509 builds above a certificate, keyed by its DER.
	upper map[string][][]*x509.Certificate
	// onPath holds the DER of the certificates on the current path, so that
	// no certificate is used twice in one path.
	onPath map[string]bool
}

// trusted searches for a path from cert, which has depth certificates below it
// in the path, to a trust anchor.
func (s *search) trusted(cert *x509.Certificate, depth int) bool {
	if depth > 0 && acceptsLowerPath(s.upperChains(cert), depth) {
		return true
	}
	if depth >= maxDepth || !validAt(cert, s.opts.CurrentTime) {
		return false
	}
	s.onPath[string(cert.Raw)] = true
	defer delete(s.onPath, string(cert.Raw))
	for _, parent := range s.candidates {
		if s.onPath[string(parent.Raw)] || !bytes.Equal(parent.RawSubject, cert.RawIssuer) {
			continue
		}
		if hasNameConstraints(parent) || !allowsFollowing(parent, depth) {
			continue
		}
		if s.checksLeft == 0 {
			return false
		}
		s.checksLeft--
		if slhdsasig.CheckSignatureFrom(cert, parent) != nil {
			continue
		}
		if s.trusted(parent, depth+1) {
			return true
		}
	}
	return false
}

// upperChains returns the chains crypto/x509 builds from cert to a trust
// anchor, computing them once per certificate.
func (s *search) upperChains(cert *x509.Certificate) [][]*x509.Certificate {
	chains, ok := s.upper[string(cert.Raw)]
	if !ok {
		chains, _ = cert.Verify(s.opts)
		s.upper[string(cert.Raw)] = chains
	}
	return chains
}

// acceptsLowerPath reports whether one of the chains crypto/x509 built above a
// certificate with depth certificates below it also permits those certificates.
func acceptsLowerPath(chains [][]*x509.Certificate, depth int) bool {
	for _, chain := range chains {
		ok := true
		for i, ancestor := range chain {
			if hasNameConstraints(ancestor) || i > 0 && !allowsFollowing(ancestor, depth+i-1) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// allowsFollowing applies the path length constraint of issuer to the number of
// intermediate certificates below it (RFC 5280 §4.2.1.9).
func allowsFollowing(issuer *x509.Certificate, intermediates int) bool {
	if !issuer.BasicConstraintsValid || issuer.MaxPathLen < 0 || issuer.MaxPathLen == 0 && !issuer.MaxPathLenZero {
		return true
	}
	return intermediates <= issuer.MaxPathLen
}

// validAt reports whether cert is within its validity period and has no
// critical extension crypto/x509 leaves unhandled.
func validAt(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter) && len(cert.UnhandledCriticalExtensions) == 0
}

// hasNameConstraints reports whether cert carries the name constraints extension.
func hasNameConstraints(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			return true
		}
	}
	return false
}
