# Response verification

The client verifies every response before it acts on it. This page explains what it checks, which
trust material it needs and the options for CAs that deviate from RFC 9483.

## Protection

* A **MAC-protected** response is verified with the shared secret of the request credentials.
* A **signature-protected** response is verified against the anchors in `client.WithTrustedCAs`.
  The signer certificate must chain to them and its subject must match the sender in the response
  header.

Either mechanism is accepted by default, because many CAs authenticate a device by shared secret
and sign every response. `client.WithResponseProtection` pins one mechanism, as RFC 9483 section 3.1
asks.

## Trust anchors

Set `WithTrustedCAs` wherever an anchor is available:

```go
c := client.NewClient("https://ca.example.com/.well-known/cmp/p/devices",
	client.WithTrustedCAs(trustedCAs),
	client.WithRecipient(pkix.Name{CommonName: "Device Issuing CA"}),
)
```

A shared-secret enrollment can complete without a pool, which is how a device gets its first anchor
from `caPubs`. Errors are signed however the request was protected (RFC 9810 section 5.3.21), so
without a pool a rejection such as transactionIdInUse arrives as an `UnverifiedStatusError`: safe to
log, not to act on. A CA that signs every response cannot be used without a pool at all.

The pool also validates the issued certificate. A CA with a composite ML-DSA key is trusted as an
issuer only when the response also carries its certificate in `extraCerts` or `caPubs`. The pool
entry still decides whether that certificate is trusted.

## Signer certificate

The signer certificate comes from `extraCerts`. A server may send `extraCerts` only on its first
response, so the client keeps the certificate it authenticated earlier in the operation and tries it
for later messages under the same checks.

Some CAs need extra options:

| CA behavior | Symptom | Option |
| --- | --- | --- |
| Signs a response, such as the answer to a revocation request, without attaching its certificate | `pkicmp.ReasonNoCandidateSigner` | `WithServerCerts` with the certificate the CA signs with, often the issuing CA |
| Copies the request's `senderKID` into the response | `pkicmp.ReasonSenderKIDMismatch` | `WithSenderKIDMismatch` |
| Signs with SHA-1 | `pkicmp.ReasonUnsupportedAlgorithm` | `WithSHA1Signatures` |
| Uses a MAC iteration count outside 1 to 500000 | The MAC parameters are refused | `WithMACIterationLimits` |

`WithServerCerts` does not trust a certificate directly. Like every candidate, it must chain to the
anchors, match the sender name and verify the signature. `WithSHA1Signatures` covers only the message
signature. Certificates signed with SHA-1 are still refused by crypto/x509.

## Certificate responses

A certificate response must hold exactly one `CertResponse` with the `certReqId` of the request. A
`p10cr` has none, so both -1 and 0 are accepted. The issued certificate must certify the requested
public key and validate against the anchors, with the response `extraCerts` completing the path.

The subject is not compared with the request, because a CA may change it and answer
grantedWithMods. A certificate that fails these checks is rejected in `certConf` before the error is
returned, so the CA learns about it at once.

## HTTP

The client posts to the endpoint with `Content-Type: application/pkixcmp`. A CMP message in an HTTP
4xx or 5xx response is parsed and verified before its status is returned and the error keeps the
HTTP status. Response bodies are limited to 10 MiB by default, set with `WithMaxResponseBytes`.

`WithHTTPClient` supplies the HTTP client, for example with a TLS configuration or a timeout.
