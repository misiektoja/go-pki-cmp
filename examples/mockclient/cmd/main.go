// Command mockclient is a minimal CMP client for testing.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func printCert(log *slog.Logger, label string, cert *x509.Certificate) {
	log.Info(label,
		"subject", cert.Subject.String(),
		"issuer", cert.Issuer.String(),
		"serial", cert.SerialNumber.String(),
	)
}

func verifyCert(log *slog.Logger, cert *x509.Certificate, trustedCAs *x509.CertPool) {
	if _, err := cert.Verify(x509.VerifyOptions{Roots: trustedCAs}); err != nil {
		log.Error("certificate verification failed", "error", err)
		return
	}
	log.Info("certificate verified")
}

func main() {
	log := slog.Default()

	endpoint := "http://localhost:8080/cmp"
	subject := pkix.Name{CommonName: "my-device"}

	// --- Step 1: Initial enrollment (IR) with MAC protection ---
	//
	// A new device has no certificate yet. It authenticates using a pre-shared
	// secret (Initial Authentication Key) and a reference number (senderKID)
	// that tells the server which secret to look up.

	// Generate a key pair for the certificate we're requesting.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error("generating key", "error", err)
		return
	}

	// Create MAC credentials from the shared secret.
	creds, err := pkicmp.NewMACCredentials([]byte("test-shared-secret"))
	if err != nil {
		log.Error("creating credentials", "error", err)
		return
	}

	// Send the IR request.
	c := client.NewClient(endpoint)

	log.Info("sending IR with MAC protection")
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithSenderKID([]byte("my-device")), // reference number for the shared secret
		client.WithSender(subject),                // sender DN in PKIHeader
		client.WithTemplateSubject(subject),       // requested certificate subject
	)
	if err != nil {
		log.Error("IR failed", "error", err)
		return
	}

	printCert(log, "enrolled", result.Certificate)

	// The IR response includes CA certificates in caPubs for trust bootstrap.
	// We use them to verify the enrolled certificate and as trust anchors for
	// the server's signature-protected KUR response later.
	trustedCAs := x509.NewCertPool()
	for _, ca := range result.CAPubs {
		printCert(log, "received CA", ca)
		trustedCAs.AddCert(ca)
	}
	verifyCert(log, result.Certificate, trustedCAs)

	// --- Step 2: Key update (KUR) with signature protection ---
	//
	// The device now has a certificate. It proves its identity by signing the
	// request with the existing key, and sends the CA chain in extraCerts so
	// the server can verify the sender's certificate.

	// Generate a new key for the renewed certificate.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error("generating new key", "error", err)
		return
	}

	// Create signature credentials: the old key signs the request, the old
	// certificate identifies the sender, and the CA chain enables the server
	// to verify the sender's certificate.
	sigCreds, err := pkicmp.NewSignatureCredentials(key, result.Certificate, result.CAPubs...)
	if err != nil {
		log.Error("creating signature credentials", "error", err)
		return
	}

	// For KUR, configure trust anchors so the client can verify the server's
	// signature-protected response.
	c = client.NewClient(endpoint, client.WithTrustedCAs(trustedCAs))

	log.Info("sending KUR with signature protection")
	renewal, err := c.SendKUR(context.Background(), newKey, sigCreds,
		client.WithSender(subject),
		client.WithTemplateSubject(subject),
	)
	if err != nil {
		log.Error("KUR failed", "error", err)
		return
	}

	printCert(log, "renewed", renewal.Certificate)
	verifyCert(log, renewal.Certificate, trustedCAs)

	// --- Step 3: Revocation (RR) with signature protection ---
	//
	// The device retires the renewed certificate. RFC 9483 §4.2 expects the
	// request to be signed with the certificate being revoked, which proves
	// the device is entitled to revoke it.
	revCreds, err := pkicmp.NewSignatureCredentials(newKey, renewal.Certificate, result.CAPubs...)
	if err != nil {
		log.Error("creating revocation credentials", "error", err)
		return
	}

	log.Info("sending RR with signature protection")
	err = c.SendRR(context.Background(), renewal.Certificate, pkicmp.CRLReasonCessationOfOperation, revCreds)
	if err != nil {
		log.Error("RR failed", "error", err)
		return
	}
	log.Info("certificate revoked", "serial", renewal.Certificate.SerialNumber.String())
}
