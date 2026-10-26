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
issuer, is built on this library.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Interoperability](#interoperability)
* [Documentation](#documentation)
* [Credits](#credits)
* [Support and contributing](#support-and-contributing)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-pki-cmp
```

Requires Go 1.27.3 or newer. Releases up to v0.3.2 use the module path
`github.com/misiektoja/go-pkicmp-ng`.

| Package | Content |
| --- | --- |
| [`pkicmp`](./pkicmp/) | CMP and CRMF types with parsing, serialization and MAC or signature protection |
| [`client`](./client/) | Enrollment, key update, revocation and support messages with response verification, certificate confirmation and polling that can resume in a later process |
| [`server`](./server/) | An `http.Handler` that authenticates clients, tracks transactions and applies policy in front of your CA |
| [`cms`](./cms/) | EnvelopedData and EncryptedValue for proof of possession by decryption and centrally generated keys |

## Scope

| Standard | Coverage |
| --- | --- |
| RFC 9810 (obsoletes RFC 4210 and RFC 9480) | CMP version 2 and version 3 |
| RFC 9483 | Lightweight CMP Profile |
| RFC 4211 | Certificate Request Message Format (CRMF) |
| RFC 9811 (obsoletes RFC 6712) | HTTP transfer for CMP |

Supported messages are `ir`, `cr`, `kur`, `p10cr`, `rr`, `certConf`, `pollReq`, `genm` and `nested`
with their responses. General messages carry the RFC 9483 support requests for CA certificates, a
root CA update, a certificate request template and CRL updates.

**Post-quantum keys:** ML-DSA-44, ML-DSA-65, ML-DSA-87, the twelve SLH-DSA parameter sets and
[composite ML-DSA](https://github.com/misiektoja/go-composite-mldsa) keys can enroll and sign CMP
messages. ML-KEM-768 and ML-KEM-1024 keys, which cannot sign, prove possession by decryption.

**Central key generation:** a client can ask the CA to generate its key pair and receive the private
key signed and encrypted for it (RFC 9483 section 4.1.6).

**RFC 4210 peers** work with the defaults. Options accept deployed clients that break RFC 9483 rules.

Key recovery, cross-certification and announcements are not implemented.

The [support matrix](https://misiektoja.github.io/go-pki-cmp/support-matrix/) and
[known limitations](https://misiektoja.github.io/go-pki-cmp/known-limitations/) give the details.

## Getting started

Enroll a certificate with a shared secret:

```go
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

c := client.NewClient("http://localhost:8080/cmp")
result, err := c.SendIR(context.Background(), key, creds,
	client.WithSenderKID([]byte("my-device")),
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
)
```

Serve CMP in front of your CA, which implements `server.CA` and the credential lookups:

```go
srv := server.NewCAServer(myCA,
	server.LightweightPolicy(),
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(myCA),
	server.WithCertificateLookup(myCA),
)
if err := srv.Err(); err != nil {
	log.Fatal(err)
}
http.Handle("/cmp", srv)
```

[examples](./examples/) holds a mock CA and a client that enrolls, updates and revokes a certificate
against it. Run them in two terminals:

```bash
go run ./examples/mockserver/cmd
go run ./examples/mockclient/cmd
```

[Getting started](https://misiektoja.github.io/go-pki-cmp/getting-started/) walks through both
programs and names what to replace before production.

## Interoperability

CI runs the library against [EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp),
[OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html) 3.5 and 4.0 in both
directions, a hosted [Nokia NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)
instance and the [Siemens CMP test suite](https://github.com/siemens/cmp-test-suite). Local tests
also run the Insta Certifier 10 cmpclient and the Insta Certifier 7 ssh-cmpclient against the server.
Both clients are proprietary, so CI does not run them.

[Tested implementations](https://misiektoja.github.io/go-pki-cmp/interoperability/tested-implementations/)
lists the scenarios and the server options each client needs.

## Documentation

Full documentation is at [misiektoja.github.io/go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/).

* [Getting started](https://misiektoja.github.io/go-pki-cmp/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-pki-cmp/support-matrix/)
* [Architecture](https://misiektoja.github.io/go-pki-cmp/architecture/)
* Client: [Enrollment](https://misiektoja.github.io/go-pki-cmp/client/enrollment/), [Response verification](https://misiektoja.github.io/go-pki-cmp/client/response-verification/), [Revocation](https://misiektoja.github.io/go-pki-cmp/client/revocation/), [Keys that cannot sign](https://misiektoja.github.io/go-pki-cmp/client/indirect-pop/) and [Keys the CA generates](https://misiektoja.github.io/go-pki-cmp/client/central-key-generation/)
* Server: [Implementing a CA](https://misiektoja.github.io/go-pki-cmp/server/ca/), [Authentication](https://misiektoja.github.io/go-pki-cmp/server/authentication/), [Policy and client compatibility](https://misiektoja.github.io/go-pki-cmp/server/policy/) and [Transactions and recovery](https://misiektoja.github.io/go-pki-cmp/server/transactions/)
* [Client options](https://misiektoja.github.io/go-pki-cmp/reference/client-options/) and [Server options](https://misiektoja.github.io/go-pki-cmp/reference/server-options/)
* [Troubleshooting](https://misiektoja.github.io/go-pki-cmp/operations/troubleshooting/)
* [Security model](https://misiektoja.github.io/go-pki-cmp/security/security-model/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp)
describes every exported type and option. [RELEASE_NOTES.md](RELEASE_NOTES.md) records the changes in
each release.

## Credits

This project began as a fork of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by
[Tero Saarni (@tsaarni)](https://github.com/tsaarni). Its package layout, ASN.1 types and client and
server design come from that project. Early hardening changes were submitted in
[tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3). This fork is maintained
separately. [NOTICE](NOTICE) records the attribution.

## Support and contributing

[SUPPORT.md](SUPPORT.md) says where to ask a question or report a bug. Report vulnerabilities
privately as [SECURITY.md](SECURITY.md) describes. The [Contributing Guide](CONTRIBUTING.md) lists
the development checks.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). [DEPENDENCIES.md](DEPENDENCIES.md)
lists third-party dependencies and their licenses.
