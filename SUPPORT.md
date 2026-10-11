# Getting help

Start with the [README](README.md), which shows client and server usage and lists the supported RFCs. The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pkicmp-ng) describes every exported type and option. The [examples](examples/) directory holds a runnable mock CA and a client that enrolls, updates and revokes a certificate against it.

## Check your integration first

Most problems come from configuration that differs between CMP peers. Before asking, confirm that:

* The client has a trust anchor through `client.WithTrustedCAs` wherever one is available. Signed responses, including error messages to a MAC-protected request, are verified against it.
* The MAC secret and the reference sent as `senderKID` match what the CA expects. A peer that implements only RFC 4210 may need `pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1)`.
* A request refused with "MAC protection parameters not accepted" uses an iteration count outside `server.WithMACIterationLimits`, which accepts 1 to 500000 by default. `client.WithMACIterationLimits` sets the range for responses.
* A certConf refused with "missing recipNonce" comes from a client that leaves the field out. `server.WithOptionalCertConfRecipNonce` accepts it.
* SHA-1 signatures are enabled with `WithSHA1Signatures` in the `client` or `server` package when the peer still uses them. They are off by default.
* `Err` on a server built with `server.New` or `server.NewCAServer` returns nil. It reports a signer key that does not match its certificate.
* `server.WithStrictProfileValidation` is set only when every client follows RFC 9483 exactly. It rejects requests that many deployed clients send.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question | [Question](https://github.com/misiektoja/go-pkicmp-ng/issues/new?template=question.yml) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-pkicmp-ng/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-pkicmp-ng/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-pkicmp-ng/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-pkicmp-ng version, the Go version, the CMP peer and its version, the request type (`ir`, `cr`, `kur`, `p10cr` or `rr`) and the message protection in use. Attach the error the library returned, the PKIStatusInfo the peer sent and the peer's log lines around it.

Never post shared secrets, private keys, full CSRs, CMP messages captured from a production system or production endpoint details. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so reproduce the problem on the current version before reporting it.
