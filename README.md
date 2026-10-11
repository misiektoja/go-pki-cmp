# go-pkicmp-ng

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pkicmp-ng?style=flat-square&color=blue)](https://github.com/misiektoja/go-pkicmp-ng/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pkicmp-ng.svg)](https://pkg.go.dev/github.com/misiektoja/go-pkicmp-ng)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/test.yml)
[![Integration](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/integration.yml)
[![Supply chain](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pkicmp-ng&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pkicmp-ng)

Go library for the **Certificate Management Protocol (CMP)**. Its core encodes, parses, protects and
verifies CMP and CRMF messages. On top of it, the `client` package enrolls, updates and revokes
certificates and the `server` package serves the same operations to CMP clients as an `http.Handler`
in front of a CA. [cmp-issuer](https://github.com/misiektoja/cmp-issuer), a cert-manager external
issuer, is built on this library. The library implements:

- **RFC 9810** (obsoletes RFC 4210 and RFC 9480): Certificate Management Protocol (CMP), CMPv2 and CMPv3
- **RFC 9483**: Lightweight CMP Profile
- **RFC 4211**: Certificate Request Message Format (CRMF)
- **RFC 9811** (obsoletes RFC 6712): HTTP Transfer for the Certificate Management Protocol (CMP)

Supported messages are `ir`, `cr`, `kur`, `p10cr`, `rr`, `certConf`, `pollReq` and `nested` with
their responses. Key recovery, cross-certification, proof-of-possession challenges, announcements and
general messages (`genm`) are not implemented.

## Interoperability and testing

CI runs the library against independent CMP implementations:

* **[EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp)**: the client enrolls and updates certificates.
* **[OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html)**: the client enrolls,
  updates and revokes against the mock server. OpenSSL as a client revokes at the server.
* **[Nokia NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)**:
  the client enrolls, re-enrolls, updates and revokes certificates against a hosted instance on every push to
  `dev` and `main` and once a week.
* **[Siemens CMP test suite](https://github.com/siemens/cmp-test-suite)**: runs its conformance tests
  against the server.

Local tests also run the Insta Certifier 10 cmpclient and the Nokia ssh-cmpclient against the server.
Both clients are proprietary, so CI does not run them. See
[test/integration/certifier](test/integration/certifier/README.md).

## Install

```bash
go get github.com/misiektoja/go-pkicmp-ng
```

Requires Go 1.27.2 or newer.

* **ML-DSA-44, ML-DSA-65 and ML-DSA-87** cover certificate keys, CRMF proof of possession and message
  signatures. Under CMPv3 the client confirms an ML-DSA-signed certificate with an explicit SHA-512
  hash. Build a manual confirmation with `pkicmp.NewCertStatus`, because `pkicmp.CertHash` cannot carry
  that hash identifier. Older Dilithium encodings are not supported.
* **Composite ML-DSA keys** from [go-composite-mldsa](https://github.com/misiektoja/go-composite-mldsa)
  sign CMP messages and issued certificates and can be the key a device enrolls. `ir`, `cr`, `kur` and
  `p10cr` carry a composite key with a composite proof of possession, and `rr` revokes its certificate.
  The client confirms a certificate signed by a composite CA with the hash the composite algorithm uses
  and an explicit hash identifier. A composite issuer is trusted only when its certificate arrives in
  extraCerts or caPubs and no certificate in the path has name constraints.
* **RFC 4210 peers** are supported. The server accepts their requests without a transactionID or with
  a short senderNonce. `server.WithStrictProfileValidation` rejects them as RFC 9483 requires. SHA-1 is
  off by default. `pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1)` selects the RFC 4210
  PasswordBasedMac profile and `WithSHA1Signatures` in `client` and `server` accepts SHA-1 signatures.
* **Device compatibility options** in `server`: `WithRawSubject` issues the subject exactly as
  requested, `WithOptionalCertConfRecipNonce` accepts a certConf without recipNonce and
  `WithMACIterationLimits` sets the accepted MAC iteration counts. `client.WithMACIterationLimits`
  sets the range for responses.
* **Request rule options** in `server` accept requests that break an RFC 9483 rule:
  `WithPoposkInputVariants` for the proof of possession of the Insta Certifier 10 cmpclient,
  `WithOptionalSubject` for a template without a subject field that names its identity in subjectAltName and
  `WithSignatureProtectionPOP` for a key update that keeps its key and is signed with it.
  `WithOptionalRevocationReason`, `WithOptionalRevocationIssuer` and `WithMACRevocation` accept
  revocation requests without a reason code, without an issuer or protected with a shared secret.
  `WithStrictProfileValidation` turns all of these off, as well as `WithOptionalCertConfRecipNonce`.

## Package structure

* **[`pkicmp`](./pkicmp/)**: CMP and CRMF ASN.1 types with parsing, serialization and MAC or signature
  protection.
* **[`client`](./client/)**: IR, CR, KUR, P10CR and RR flows with polling, response verification and
  certificate confirmation.
* **[`server`](./server/)**: an `http.Handler` that authenticates clients, tracks transactions,
  supports deferred issuance and revocation, accepts requests a registration authority forwards in
  nested messages and applies policy middleware such as the lightweight profile.

## Usage

### Client

Initialization Request (IR) with a shared secret:

```go
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

// A bootstrapping device has no trust anchor yet. Add client.WithTrustedCAs when
// one is available, so that a signed rejection can be verified.
c := client.NewClient("http://localhost:8080/cmp")
result, err := c.SendIR(context.Background(), key, creds,
	client.WithSenderKID([]byte("my-device")),
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
)
```

Key Update Request (KUR) with signature protection:

```go
creds, _ := pkicmp.NewSignatureCredentials(existingKey, existingCert)
c := client.NewClient("http://localhost:8080/cmp", client.WithTrustedCAs(trustedCAs))

// SignatureCredentials lets SendKUR name existingCert in the CRMF oldCertID control.
// The sender and template subject repeat existingCert's subject with its original encoding.
result, err := c.SendKUR(context.Background(), newKey, creds)
```

Revocation Request (RR):

```go
// RFC 9483 expects the request to be signed with the certificate being revoked.
creds, _ := pkicmp.NewSignatureCredentials(certKey, cert)

// Some CAs sign the response without attaching their certificate. WithServerCerts
// supplies it, and it must still chain to trustedCAs and match the response sender.
c := client.NewClient("http://localhost:8080/cmp",
	client.WithTrustedCAs(trustedCAs),
	client.WithServerCerts([]*x509.Certificate{issuingCA}),
)

// A nil error means the CA revoked the certificate. A rejection such as
// certRevoked is returned as *pkicmp.PKIStatusError.
err := c.SendRR(context.Background(), cert, pkicmp.CRLReasonKeyCompromise, creds)
```

### Server

Implement the `server.CA` interface and the credential lookups:

```go
type MyCA struct{}

func (ca *MyCA) IssueCertificate(ctx, reqType, template, sender) {
	// Called on enrollment requests (IR/CR/KUR). Signs template with CA private key.
}
func (ca *MyCA) LookupSecret(sender, senderKID) {
	// Called to verify MAC-protected requests. Finds pre-shared secret by DN or key ID.
}
func (ca *MyCA) LookupCertificate(issuer, subject, senderKID) {
	// Called to verify signature-protected requests. Finds existing cert by DN or Subject Key ID.
}
func (ca *MyCA) RevokeCertificate(ctx, req, sender) {
	// Optional. Called on revocation requests (RR) signed with the certificate being revoked.
	// Implement server.RevocationAuthorizer to also accept requests from other signers.
}
```

Then serve it:

```go
myCA := &MyCA{}
srv := server.NewCAServer(myCA,
	server.LightweightPolicy(),
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(myCA),
	server.WithCertificateLookup(myCA),
	// A present messageTime outside this local tolerance is rejected as badTime.
	server.WithMessageTimeTolerance(5*time.Minute),
)
// Reports a misconfiguration such as a signer key that does not match its cert.
if err := srv.Err(); err != nil {
	log.Fatal(err)
}

http.Handle("/cmp", srv)
http.ListenAndServe(":8080", nil)
```

## Runnable examples

[examples](./examples/) holds a [mock CA server](./examples/mockserver/) and a
[client](./examples/mockclient/) that runs a MAC-protected IR, a signature-protected KUR and an RR
against it. Run them in two terminals:

```bash
go run ./examples/mockserver/cmd
go run ./examples/mockclient/cmd
```

## Credits and relationship to go-pkicmp

This project began as a fork of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by
[@tsaarni](https://github.com/tsaarni). Its package layout, ASN.1 types and client and server design
are still the base of this library and made everything here possible. The credit for that
foundation belongs to its author.

Development continued here because the changes are security relevant and needed a faster cycle than
upstream review allowed. The early hardening work is offered upstream in
[tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3), which is still open. This fork
adds:

* **Stricter verification.** Signatures are bound to the sender they claim. Issued certificates must
  certify the requested key and carry the request's certReqId. PBKDF2 parameters and poll intervals
  from peers are bounded.
* **Post-quantum signatures**: ML-DSA with SHA-512 certificate confirmation plus composite ML-DSA
  keys for both CAs and enrolling devices.
* **Revocation** in the client and the server, plus nested requests from a registration authority.
* **Certificate confirmation checks** on both sides, with `SnapshotTransactions` and
  `RestoreTransactions` to keep server transactions across a restart.
* **Support for RFC 4210 peers**, with the SHA-1 options off by default.
* **Server hardening**: required proof of possession, an optional `messageTime` tolerance, no handler
  error text on the wire, MAC-protected errors for shared-secret clients and `Server.Err` for a
  misconfigured signer.
* **Interoperability fixes** for EJBCA, OpenSSL, Nokia NCM and vendor CMP clients. Key update names
  the replaced certificate in `oldCertID`, enrollment works with Ed25519-signing CAs and
  `client.WithServerCerts` verifies responses from CAs that do not attach their certificate.

The [release notes](RELEASE_NOTES.md) list every change.

## Contributing and support

The [Contributing Guide](CONTRIBUTING.md) describes the development checks, the integration tests and the release process. [SUPPORT.md](SUPPORT.md) says where to ask a question or report a bug. Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). [DEPENDENCIES.md](DEPENDENCIES.md) lists third-party dependencies and their licenses.
