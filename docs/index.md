# go-pki-cmp

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pki-cmp?style=flat-square&color=blue)](https://github.com/misiektoja/go-pki-cmp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-cmp.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/misiektoja/go-pki-cmp/blob/main/LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-cmp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/test.yml)
[![Integration](https://github.com/misiektoja/go-pki-cmp/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/integration.yml)
[![Supply chain](https://github.com/misiektoja/go-pki-cmp/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-cmp/actions/workflows/supply-chain.yml)

go-pki-cmp is a Go library for the **Certificate Management Protocol (CMP)**. It has four packages:

* **`pkicmp`** encodes, parses, protects and verifies CMP and CRMF messages
* **`client`** enrolls, updates and revokes certificates and asks a CA for information
* **`server`** serves the same operations to CMP clients as an `http.Handler` in front of your CA
* **`cms`** encrypts and decrypts the CMS EnvelopedData and EncryptedValue that proof of possession by decryption needs

The server handles the protocol: transport, message protection, transactions, polling and
certificate confirmation. Your application supplies issuance, credential lookup and authorization
policy through Go interfaces. [cmp-issuer](https://github.com/misiektoja/cmp-issuer), a cert-manager
external issuer, is built on this library.

Certificates can carry **post-quantum ML-DSA**, **SLH-DSA** or **composite ML-DSA** keys and all of
them can sign CMP messages. **ML-KEM** keys are certified through proof of possession by decryption. The
[support matrix](support-matrix.md) lists what is covered.

## Install

```bash
go get github.com/misiektoja/go-pki-cmp
```

The module needs Go 1.27.3 or newer. Releases up to v0.3.2 use the module path
`github.com/misiektoja/go-pkicmp-ng`.

## Start here

**[Getting started](getting-started.md)** runs the example CA and client from the repository. The
client enrolls with a shared secret, updates its key and revokes the result. The page then names
each piece you replace in your own client or server.

## Where to go next

| I want to | Page |
| --- | --- |
| Know which RFCs, messages, algorithms and keys are covered | [Support matrix](support-matrix.md) |
| Understand how the packages and my code fit together | [Architecture](architecture.md) |
| Request certificates from a CA | [Enrollment](client/enrollment.md) |
| Decide which CA certificates and responses the client trusts | [Response verification](client/response-verification.md) |
| Revoke a certificate | [Revocation (client)](client/revocation.md) |
| Fetch CA certificates, root updates, templates or CRLs | [Support messages (client)](client/support-messages.md) |
| Certify an ML-KEM or encryption-only key | [Keys that cannot sign (client)](client/indirect-pop.md) |
| Have the CA generate my key pair | [Keys the CA generates](client/central-key-generation.md) |
| Put a CMP front end on my CA | [Implementing a CA](server/ca.md) |
| Authenticate devices by shared secret or certificate | [Authentication](server/authentication.md) |
| Accept clients that break RFC 9483 rules | [Policy and client compatibility](server/policy.md) |
| Hold requests for an operator's approval | [Delayed issuance and confirmation](server/delayed-issuance.md) |
| Generate key pairs for devices that cannot | [Keys the server generates](server/central-key-generation.md) |
| Accept requests forwarded by a registration authority | [Registration authorities](server/registration-authorities.md) |
| Run several replicas or survive a restart | [Transactions and recovery](server/transactions.md) |
| Build or verify CMP messages myself | [Messages and protection](pkicmp/messages-and-protection.md) |
| Look up an option and its default | [Client options](reference/client-options.md) and [Server options](reference/server-options.md) |
| See which CMP implementations were tested | [Tested implementations](interoperability/tested-implementations.md) |
| Fix a refused request | [Troubleshooting](operations/troubleshooting.md) |
| Understand what is not implemented | [Known limitations](known-limitations.md) |

## Design and security

* [Security model](security/security-model.md) - what the library checks and what remains with your application
* [Compatibility policy](reference/compatibility.md) - what may change before v1.0.0 and how
* [Package documentation](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp) - every exported type and option

## Contributing

* [Development](development/development.md), [Testing](development/testing.md) and [Release process](development/release-process.md)
* Source and issues: [github.com/misiektoja/go-pki-cmp](https://github.com/misiektoja/go-pki-cmp)

## Credits

go-pki-cmp began as a fork of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by Tero
Saarni. Its package layout, ASN.1 types and client and server design come from that project. The
[NOTICE](https://github.com/misiektoja/go-pki-cmp/blob/main/NOTICE) file records the attribution.

## Support

[SUPPORT.md](https://github.com/misiektoja/go-pki-cmp/blob/main/SUPPORT.md) routes usage questions,
bug reports, feature requests and private security reports. Check
[Troubleshooting](operations/troubleshooting.md) and collect sanitized diagnostics before posting.
