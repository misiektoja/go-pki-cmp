# go-pki-cmp

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pki-cmp?style=flat-square&color=blue)](https://github.com/misiektoja/go-pki-cmp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-cmp.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-cmp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/test.yml)
[![Integration](https://github.com/misiektoja/go-pki-cmp/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/integration.yml)
[![Supply chain](https://github.com/misiektoja/go-pki-cmp/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pki-cmp&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pki-cmp)

Go library for the **Certificate Management Protocol (CMP)**. Its core encodes, parses, protects and
verifies CMP and CRMF messages. On top of it, the `client` package enrolls, updates and revokes
certificates and the `server` package serves the same operations to CMP clients as an `http.Handler`
in front of a CA. [cmp-issuer](https://github.com/misiektoja/cmp-issuer), a cert-manager external
issuer, is built on this library. The library implements:

- **RFC 9810** (obsoletes RFC 4210 and RFC 9480): Certificate Management Protocol (CMP), CMPv2 and CMPv3
- **RFC 9483**: Lightweight CMP Profile
- **RFC 4211**: Certificate Request Message Format (CRMF)
- **RFC 9811** (obsoletes RFC 6712): HTTP Transfer for the Certificate Management Protocol (CMP)

Supported messages are `ir`, `cr`, `kur`, `p10cr`, `rr`, `certConf`, `pollReq`, `genm` and `nested`
with their responses. General messages carry the RFC 9483 support requests for CA certificates, a root
CA update, a certificate request template and CRL updates. Key recovery, cross-certification,
proof-of-possession challenges and announcements are not implemented.

## Interoperability and testing

CI runs the library against independent CMP implementations:

* **[EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp)**: the client enrolls and updates certificates.
* **[OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html)**: the client enrolls,
  updates, revokes and sends support messages against the mock server. OpenSSL as a client revokes at
  the server and sends support messages to it.
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
go get github.com/misiektoja/go-pki-cmp
```

Requires Go 1.27.2 or newer. Releases up to v0.3.2 use the module path
`github.com/misiektoja/go-pkicmp-ng`.

## Package structure

* **[`pkicmp`](./pkicmp/)**: CMP and CRMF ASN.1 types with parsing, serialization and MAC or signature
  protection.
* **[`client`](./client/)**: IR, CR, KUR, P10CR, RR and support message flows with polling, response
  verification and certificate confirmation.
* **[`server`](./server/)**: an `http.Handler` that authenticates clients, tracks transactions,
  supports deferred issuance, revocation and support messages, accepts requests a registration
  authority forwards in nested messages and applies policy middleware such as the lightweight profile.

## Compatibility

* **Post-quantum keys:** ML-DSA-44, ML-DSA-65, ML-DSA-87 and
  [composite ML-DSA](https://github.com/misiektoja/go-composite-mldsa) support enrollment and CMP
  signatures. Older Dilithium encodings are not supported.
* **RFC 4210 peers** are supported by default. SHA-1 signatures and additional device compatibility
  options are opt-in. [Server options](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#Option)
  describe these exceptions and the stricter `WithStrictProfileValidation` checks.

For manual certificate confirmation, use
[`pkicmp.NewCertStatus`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/pkicmp#NewCertStatus).
Composite certificate chains have additional
[verification limits](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/pkicmp#VerifyOptions) and
[client trust requirements](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithTrustedCAs).

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

Root CA update (RFC 9483 §4.3.2):

```go
update, err := c.GetRootCAUpdate(context.Background(), currentRoot, creds)
switch {
case errors.Is(err, client.ErrInfoTypeNotSupported):
	// The CA does not offer root updates. RFC 4210 CAs often ignore the request.
case err != nil:
	return err
case update != nil:
	// update.NewWithNew is the new root. The client has checked that currentRoot
	// signed update.NewWithOld.
}
```

`GetCACertificates`, `GetCertReqTemplate`, `GetCRLUpdate` and `GetCurrentCRL` follow the same pattern.

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

Support messages are answered by optional interfaces: `server.CACertificatesProvider`,
`server.RootCAUpdateProvider`, `server.CertReqTemplateProvider` and `server.CRLProvider`. The server
lists a requested type without a provider as unsupported.

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
[Tero Saarni (@tsaarni)](https://github.com/tsaarni). Its package layout, ASN.1 types and client and
server design come from that project.

Early hardening changes were submitted in
[tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3). This fork is maintained separately.
See the [release notes](RELEASE_NOTES.md) for changes and [NOTICE](NOTICE) for attribution.

## Contributing and support

The [Contributing Guide](CONTRIBUTING.md) describes the development checks, the integration tests and the release process. [SUPPORT.md](SUPPORT.md) says where to ask a question or report a bug. Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). [DEPENDENCIES.md](DEPENDENCIES.md) lists third-party dependencies and their licenses.
