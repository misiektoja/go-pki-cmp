# Server options

Options of `server.New` and `server.NewCAServer`. The
[package documentation](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server) describes each in
full.

## Identity and credentials

| Option | Default | Effect |
| --- | --- | --- |
| [`WithSigner`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithSigner) | None | Key, certificate and chain that sign responses. `Err` reports a key that does not match |
| [`WithExtraCerts`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithExtraCerts) | None | Certificates added to `extraCerts` of every response |
| [`WithSender`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithSender) | Subject of the signer certificate | Server name in response headers. A request for another recipient is refused |
| [`WithSecretLookup`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithSecretLookup) | None | Finds shared secrets. Without it MAC-protected messages are refused |
| [`WithCertificateLookup`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithCertificateLookup) | None | Finds sender certificates. Without it signed messages are refused |
| [`WithRAAuthorizer`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithRAAuthorizer) | None | Accepts nested messages from registration authorities |
| [`WithMACIterationLimits`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithMACIterationLimits) | 1 to 500000 | Accepted MAC iteration counts |
| [`WithSHA1Signatures`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithSHA1Signatures) | Off | Accepts SHA-1 signatures in protection and proof of possession |

## Confirmation and waiting

| Option | Default | Effect |
| --- | --- | --- |
| [`WithConfirmWaitTime`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithConfirmWaitTime) | 10 seconds | How long an issued certificate or a challenge waits for its answer |
| [`WithImplicitConfirm`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithImplicitConfirm) | Off | Grants implicit confirmation to clients that ask for it |
| [`WithWaitingLifetime`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithWaitingLifetime) | 24 hours | How long a waiting request stays after its last poll |
| [`WithWaitingExpirer`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithWaitingExpirer) | The CA, if it implements `WaitingExpirer` | Hears about waiting requests that `CleanupExpired` removes |

## Proof of possession

| Option | Default | Effect |
| --- | --- | --- |
| [`WithEncryptedCertificatePOP`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithEncryptedCertificatePOP) | Off | Accepts the encrypted certificate method |
| [`WithChallengeResponsePOP`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithChallengeResponsePOP) | Off | Accepts the challenge-response method |
| [`WithEnvelopedDataForVersion2`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithEnvelopedDataForVersion2) | Off | Sends EnvelopedData instead of EncryptedValue to CMP version 2 RSA requests |
| [`WithSignatureProtectionPOP`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithSignatureProtectionPOP) | Off | Accepts a request without proof whose protection was signed with the requested key |
| [`WithPoposkInputVariants`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithPoposkInputVariants) | Off | Accepts the signature proof the Insta Certifier 10 cmpclient sends |

## Central key generation

| Option | Default | Effect |
| --- | --- | --- |
| [`WithCentralKeyGeneration`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithCentralKeyGeneration) | Off | Generates the key pair for requests without a public key and signs the private key with a key generation authority |
| [`WithCentralKeyGenerationAESKeyWrap`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithCentralKeyGenerationAESKeyWrap) | Off | Encrypts the key for a MAC-protected request with the AES key wrap instead of the RFC 3211 key wrap that OpenSSL reads |
| [`WithCentralKeyGenerationAsymmetricKeyPackage`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithCentralKeyGenerationAsymmetricKeyPackage) | Off | Signs the key as an RFC 9810 AsymmetricKeyPackage instead of the id-data that OpenSSL reads |

## Request rules

| Option | Default | Effect |
| --- | --- | --- |
| [`WithStrictProfileValidation`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithStrictProfileValidation) | Off | Enforces the RFC 9483 message construction rules and overrides the relaxing options |
| [`WithMessageTimeTolerance`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithMessageTimeTolerance) | Off | Refuses a messageTime further than the tolerance with badTime |
| [`WithOptionalCertConfRecipNonce`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithOptionalCertConfRecipNonce) | Off | Accepts `certConf` without recipNonce |
| [`WithOptionalPollReqRecipNonce`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithOptionalPollReqRecipNonce) | Off | Accepts `pollReq` without recipNonce |
| [`WithOptionalSubject`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithOptionalSubject) | Off | Accepts a template without the subject field when it requests a subjectAltName |
| [`WithAnyCertReqID`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithAnyCertReqID) | Off | Accepts an ir, cr or kur with a certReqId other than 0 and repeats it in the response |
| [`WithRawSubject`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithRawSubject) | Off | Passes the requested subject unchanged in `template.RawSubject` |
| [`WithOptionalRevocationReason`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithOptionalRevocationReason) | Off | Accepts a revocation request without reasonCode |
| [`WithOptionalRevocationIssuer`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithOptionalRevocationIssuer) | Off | Accepts a revocation request without an issuer |
| [`WithMACRevocation`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithMACRevocation) | Off | Passes MAC-protected revocation requests to `RevocationAuthorizer` |

## Limits

| Setting | Default | Effect |
| --- | --- | --- |
| [`WithMaxTransactions`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithMaxTransactions) | 10000 | Concurrent transactions in the server |
| [`WithMaxTransactionsPerCredential`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#WithMaxTransactionsPerCredential) | 100 | Concurrent transactions per client credential |
| [`MaxRequestBodySize`](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp/server#MaxRequestBodySize) | 1 MiB | Largest accepted request body, a package variable |
