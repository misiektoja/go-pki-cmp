package mockserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// revocation records when and why a certificate was revoked.
type revocation struct {
	serial *big.Int
	reason pkicmp.CRLReason
	at     time.Time
	// invalidityDate is the time the requester gave for the compromise, zero when it gave none.
	invalidityDate time.Time
}

// Algorithm OIDs for the key specification of the certificate request template.
var (
	oidRegCtrlAlgID   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 11} // RFC 9480 §2.16 id-regCtrl-algId
	oidECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCommonName     = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// CACertificates implements [server.CACertificatesProvider]. The mock CA
// issues end-entity certificates itself, so it is the only CA certificate a
// client needs.
func (c *MockCA) CACertificates(context.Context, *server.SenderIdentity) ([]*x509.Certificate, error) {
	return []*x509.Certificate{c.cert}, nil
}

// RootCAUpdate implements [server.RootCAUpdateProvider]. The mock CA never
// replaces its key, so no update is available. A CA that rolls over its root
// returns the new self-signed root and the link certificate signed with the
// old key, as RFC 4210 §4.4 describes.
func (c *MockCA) RootCAUpdate(context.Context, *x509.Certificate, *server.SenderIdentity) (*pkicmp.RootCAKeyUpdate, error) {
	return nil, nil
}

// CertReqTemplate implements [server.CertReqTemplateProvider]. Whatever the
// profile, it asks for a subject with a common name the client fills in and
// for a P-256 key (RFC 9483 §4.3.3).
func (c *MockCA) CertReqTemplate(_ context.Context, profile string, _ *server.SenderIdentity) (*pkicmp.CertReqTemplate, error) {
	c.Log.Info("certificate request template requested", "profile", profile)
	curve, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		return nil, err
	}
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidECPublicKey,
		Parameters: asn1.RawValue{FullBytes: curve},
	})
	if err != nil {
		return nil, err
	}
	// An attribute with an empty value asks the client to fill it in.
	subject := pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidCommonName, Value: ""}}}
	return &pkicmp.CertReqTemplate{
		Template: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(subject)},
		KeySpec:  []pkicmp.AttributeTypeAndValue{{Type: oidRegCtrlAlgID, Value: algID}},
	}, nil
}

// LatestCRL implements [server.CRLProvider]. It answers a zero source and any
// source that names the mock CA, with a CRL signed on demand from the
// revocations so far. A real CA would publish the CRL it already signed.
func (c *MockCA) LatestCRL(_ context.Context, source pkicmp.CRLSource, _ *server.SenderIdentity) (*x509.RevocationList, error) {
	if !source.IsZero() && !slices.ContainsFunc(source.DirectoryNames(), c.isOwnName) {
		c.Log.Info("CRL requested for another issuer")
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(c.crlNumber),
		ThisUpdate: c.crlUpdated,
		NextUpdate: c.crlUpdated.Add(24 * time.Hour),
	}
	for _, r := range c.revoked {
		entry := x509.RevocationListEntry{
			SerialNumber:   r.serial,
			RevocationTime: r.at,
			ReasonCode:     int(r.reason),
		}
		// The requested invalidityDate is published in the CRL entry (RFC 5280 §5.3.2).
		if !r.invalidityDate.IsZero() {
			ext, err := pkicmp.NewInvalidityDateExtension(r.invalidityDate)
			if err != nil {
				return nil, err
			}
			entry.ExtraExtensions = []pkix.Extension{ext}
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, entry)
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}

// crlChanged starts a new CRL with a higher number and a later thisUpdate.
// Callers hold c.mu. Each CRL needs a distinct thisUpdate, because RFC 9483
// §4.3.4 tells a client whether its CRL is current by that time alone, and
// the encoding has a resolution of one second.
func (c *MockCA) crlChanged() {
	c.crlNumber++
	next := time.Now().UTC().Truncate(time.Second)
	if !next.After(c.crlUpdated) {
		next = c.crlUpdated.Add(time.Second)
	}
	c.crlUpdated = next
}

// isOwnName reports whether the DER name is the subject of the mock CA, however its strings are encoded.
func (c *MockCA) isOwnName(name []byte) bool {
	if bytes.Equal(name, c.cert.RawSubject) {
		return true
	}
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(name, &rdns); err != nil || len(rest) > 0 {
		return false
	}
	var parsed pkix.Name
	parsed.FillFromRDNSequence(&rdns)
	return parsed.String() == c.cert.Subject.String()
}
