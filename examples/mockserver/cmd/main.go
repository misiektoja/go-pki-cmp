// Command mockserver is a minimal CMP server for testing.
package main

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/server"
)

func main() {
	// Create a logger for the server.
	log := slog.Default()

	// Create a CA with shared secrets for MAC-based enrollment.
	// Each entry maps a senderKID (reference number) to an Initial Authentication
	// Key (IAK). In production these would be loaded from a database or a
	// secrets manager.
	ca, err := mockserver.New(map[string][]byte{
		"my-device": []byte("test-shared-secret"),
	}, log)
	if err != nil {
		log.Error("creating CA", "error", err)
		return
	}
	log.Info("CA ready", "subject", ca.Cert().Subject.String(), "serial", ca.Cert().SerialNumber)

	// Connect the CA into a CMP server.
	//
	//   - LightweightPolicy: enforces the mandatory checks from RFC 9483.
	//   - WithSigner: signs every outgoing response with the CA key; a crypto.Signer
	//     so an HSM-backed signer can be used in production.
	//   - WithExtraCerts: appends the CA cert to outgoing response extraCerts.
	//   - WithSecretLookup: enables MAC (shared-secret) protection for IR/CR.
	//   - WithCertificateLookup: enables signature protection for KUR/certConf/RR.
	//   - CentralKeyGeneration: lets a client ask the CA to generate its key pair.
	//   - WithRAAuthorizer: accepts requests that a registration authority with
	//     an id-kp-cmcRA certificate from this CA forwards in nested messages.
	srv := server.NewCAServer(ca,
		server.LightweightPolicy(),
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithExtraCerts([]*x509.Certificate{ca.Cert()}),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
		ca.CentralKeyGeneration(),
		server.WithRAAuthorizer(ca),
	)
	if err := srv.Err(); err != nil {
		log.Error("server misconfigured", "err", err)
		os.Exit(1)
	}

	// Periodically remove stale transactions from clients that never send certConf.
	// A transaction is stale once the confirm wait time has passed, 10 seconds
	// unless the server is built with WithConfirmWaitTime.
	go func() {
		for range time.Tick(30 * time.Second) {
			srv.CleanupExpired()
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	log.Info("mockserver listening", "addr", "localhost:8080", "path", "/cmp")
	httpSrv := &http.Server{
		Addr:         "localhost:8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Error("server error", "error", err)
	}
}
