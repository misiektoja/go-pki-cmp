# Client options

Options of `client.NewClient` apply to every call of that client. Request options apply to one call.
The [package documentation](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client) describes each
in full.

## Client options

| Option | Default | Effect |
| --- | --- | --- |
| [`WithTrustedCAs`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithTrustedCAs) | None | Anchors for signed responses and issued certificates |
| [`WithRecipient`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithRecipient) | NULL-DN | CA name in the request header. Many CAs route on it |
| [`WithResponseProtection`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithResponseProtection) | `pkicmp.ProtectionAny` | Requires MAC or signature protection on every response |
| [`WithExtraCerts`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithExtraCerts) | None | Certificates added to `extraCerts` of every request |
| [`WithServerCerts`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithServerCerts) | None | CA protection certificates known out of band, for responses that do not carry them |
| [`WithoutCAPubsTrust`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithoutCAPubsTrust) | Off | Keeps the CA certificates in `caPubs` of a MAC-protected response from becoming anchors |
| [`WithSenderKIDMismatch`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithSenderKIDMismatch) | Off | Accepts a signed response whose senderKID names none of the candidate certificates |
| [`WithSHA1Signatures`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithSHA1Signatures) | Off | Accepts responses signed with SHA-1 |
| [`WithMACIterationLimits`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithMACIterationLimits) | 1 to 500000 | Accepted MAC iteration counts in responses |
| [`WithMaxPolls`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithMaxPolls) | 60 | Poll attempts before the call gives up |
| [`WithCheckAfterLimits`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithCheckAfterLimits) | 1 second to 1 hour | Clamps each wait the CA asks for |
| [`WithMaxResponseBytes`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithMaxResponseBytes) | 10 MiB | Largest accepted response body. Zero or less disables the limit |
| [`WithHTTPClient`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithHTTPClient) | `http.DefaultClient` | The HTTP client, for TLS settings or timeouts |

To send a MAC iteration count outside the default range, set it on the credentials with
`pkicmp.WithMACIterationCount` and widen `pkicmp.WithMACIterationLimits` to match.

## Request options

| Option | Effect |
| --- | --- |
| [`WithSender`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithSender) | Sender name in the header. A signed request otherwise names the subject of its protection certificate |
| [`WithSenderKID`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithSenderKID) | `senderKID` in every message, the reference of a shared secret |
| [`WithTemplateSubject`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithTemplateSubject) | Subject in the certificate template |
| [`WithTemplateExtension`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithTemplateExtension) | Adds an extension to the certificate template |
| [`WithCertProfile`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithCertProfile) | Names a certificate profile in the header |
| [`WithOldCertificate`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithOldCertificate) | The certificate a key update replaces, for custom credential types |
| [`WithGeneralInfo`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithGeneralInfo) | Adds items to `generalInfo` of the request header, after the certProfile |
| [`WithCertReqID`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithCertReqID) | The `certReqId` of an ir, cr or kur, which the CA must repeat. Default 0 |
| [`WithPOPHash`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithPOPHash) | The digest of the signature proof of possession of an RSA or ECDSA key. Default by key type |
| [`WithImplicitConfirm`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithImplicitConfirm) | Asks for implicit confirmation. When the CA grants it, no `certConf` is sent and `EnrollResult.ImplicitConfirm` is true |
| [`WithInvalidityDate`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/client#WithInvalidityDate) | Adds the invalidityDate CRL entry extension to a revocation request, the time the certificate became invalid |

The digest of signature protection is chosen the same way on the credentials with
`pkicmp.SignatureCredentials.WithHash`.
