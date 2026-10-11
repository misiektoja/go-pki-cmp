// Package mockclient provides reusable enrollment and revocation helpers built on top of the
// [client] and [pkicmp] packages. See cmd/ for a step-by-step tutorial that
// calls the APIs directly.
package mockclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Enroll performs an Initialization Request (IR) using Password-Based MAC
// protection. reference is sent as PKIHeader senderKID to identify the
// shared secret on the server, and iak is the Initial Authentication Key.
//
// A fresh ECDSA P-256 key is generated for the new certificate. Pass the
// returned result and key to [Renew] for subsequent key updates.
func Enroll(ctx context.Context, endpoint string, reference, iak []byte, subject pkix.Name) (*client.EnrollResult, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	creds, err := pkicmp.NewMACCredentials(iak)
	if err != nil {
		return nil, nil, fmt.Errorf("creating MAC credentials: %w", err)
	}

	c := client.NewClient(endpoint)

	result, err := c.SendIR(ctx, key, creds,
		client.WithSenderKID(reference),
		client.WithSender(subject),
		client.WithTemplateSubject(subject),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("IR: %w", err)
	}

	return result, key, nil
}

// Renew performs a Key Update Request (KUR) using signature-based protection.
// oldKey signs the request proving ownership, oldCert identifies the sender,
// trustedCAs verify the server's response, and caCerts are included in
// extraCerts for the server to verify the sender's certificate chain.
//
// A fresh ECDSA P-256 key is generated for the renewed certificate. The
// returned certificate and key replace the old ones.
func Renew(ctx context.Context, endpoint string, oldKey crypto.Signer, oldCert *x509.Certificate, trustedCAs *x509.CertPool, caCerts []*x509.Certificate, subject pkix.Name) (*client.EnrollResult, crypto.Signer, error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	creds, err := pkicmp.NewSignatureCredentials(oldKey, oldCert, caCerts...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating signature credentials: %w", err)
	}

	c := client.NewClient(endpoint, client.WithTrustedCAs(trustedCAs))

	result, err := c.SendKUR(ctx, newKey, creds,
		client.WithSender(subject),
		client.WithTemplateSubject(subject),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("KUR: %w", err)
	}

	return result, newKey, nil
}

// Revoke performs a Revocation Request (RR) signed with the certificate being
// revoked, as RFC 9483 §4.2 expects. key is the private key of cert,
// trustedCAs verify the server's response, and caCerts are included in
// extraCerts.
func Revoke(ctx context.Context, endpoint string, key crypto.Signer, cert *x509.Certificate, reason pkicmp.CRLReason, trustedCAs *x509.CertPool, caCerts []*x509.Certificate) error {
	creds, err := pkicmp.NewSignatureCredentials(key, cert, caCerts...)
	if err != nil {
		return fmt.Errorf("creating signature credentials: %w", err)
	}

	c := client.NewClient(endpoint, client.WithTrustedCAs(trustedCAs))
	if err := c.SendRR(ctx, cert, reason, creds); err != nil {
		return fmt.Errorf("RR: %w", err)
	}
	return nil
}
