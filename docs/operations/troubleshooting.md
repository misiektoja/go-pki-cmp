# Troubleshooting

Most problems come from configuration that differs between CMP peers. A refused request names the
rule it broke in its status text. Find the text below.

## Server refusals

| Status text or failure | Cause | Fix |
| --- | --- | --- |
| "malformed message" with badDataFormat | The message after its header cannot be decoded. A request without a readable header gets HTTP 400 instead | Fix the client encoding |
| "senderKID does not identify the protection certificate" | The senderKID names another key than the certificate that signed the request | Fix the client's senderKID or its protection certificate |
| "MAC protection parameters not accepted" | The MAC iteration count, for PBMAC1 multiplied by the PRF blocks of the key length, is outside `WithMACIterationLimits`, 1 to 500000 by default | Widen the limits for that fleet |
| "pkicmp: RSA modulus larger than 16384 bits" | The request, its proof of possession or its protection certificate carries an RSA key above `pkicmp.MaxRSAModulusBits` | Use a key of at most 16384 bits |
| "MAC protection not configured" | No `WithSecretLookup` | Configure the lookup |
| "signature protection not configured" | No `WithCertificateLookup` | Configure the lookup |
| "missing recipNonce" on a `certConf` | The client leaves the field out | `WithOptionalCertConfRecipNonce` |
| "missing recipNonce" on a `pollReq` | The client polls without recipNonce, as the Insta Certifier clients do | `WithOptionalPollReqRecipNonce` |
| "recipNonce mismatch" | The client repeats the wrong senderNonce | None. A recipNonce that is present must match |
| "poposkInput not allowed when the template contains the subject and public key" | A client such as the Insta Certifier 10 cmpclient | `WithPoposkInputVariants` |
| "proof of possession by signature required" on a key update | The request carries no proof of possession | `WithSignatureProtectionPOP`, when the request keeps the key of the certificate that signs it |
| badPOP or badAlg for an ML-KEM key | Proof by decryption is off | `WithEncryptedCertificatePOP` or `WithChallengeResponsePOP` |
| "subject required" | The template has no subject field | Send a NULL-DN subject with subjectAltName or `WithOptionalSubject` |
| "reasonCode required" | The revocation request carries no reason | `WithOptionalRevocationReason` |
| "issuer required" | The revocation request names only a serial number | `WithOptionalRevocationIssuer` |
| "revocation requires signature protection" | A MAC-protected revocation request | `WithMACRevocation` and a CA that implements `RevocationAuthorizer` |
| "revocation not supported" | The CA does not implement `Revoker` | Implement it |
| "message type not supported" | The request uses a CMP operation the library does not implement, such as key recovery | None |
| "unsupported pvno 0" | The client uses a protocol version the server does not support | None. Only versions 2 and 3 are supported |
| badAlg on a signed request | The client signs with SHA-1 | `WithSHA1Signatures` |
| badTime | The messageTime is outside `WithMessageTimeTolerance` | Fix the client clock or widen the tolerance |
| "recipient does not match server identity" | The request names another CA | Fix the client recipient or `WithSender` on the server |
| systemUnavail | A transaction limit is reached | Call `CleanupExpired` periodically and check `WithMaxTransactions` |
| systemFailure on every request | A signer key that does not match its certificate | Check `Server.Err` at startup |

`WithStrictProfileValidation` refuses many requests deployed clients send and overrides most of the
options above. Set it only when every client follows RFC 9483 exactly.

## Client errors

| Error | Cause | Fix |
| --- | --- | --- |
| `pkicmp.ReasonMissingTrustAnchors` or an `UnverifiedStatusError` | The response is signed and the client has no anchor | `client.WithTrustedCAs` |
| `pkicmp.ReasonUntrustedSigner` | The CA's protection certificate does not chain to the anchors | Add the right root to the pool |
| `pkicmp.ReasonNoCandidateSigner` | The CA signed without attaching its certificate | `client.WithServerCerts` |
| `pkicmp.ReasonSenderKIDMismatch` | The CA copied the request's senderKID into the response | `client.WithSenderKIDMismatch` |
| `pkicmp.ReasonSenderMismatch` | No candidate certificate has the sender name of the response | Check which certificate the CA signs with |
| `pkicmp.ReasonUnsupportedAlgorithm` | The CA signs with SHA-1 | `client.WithSHA1Signatures` |
| `pkicmp.ReasonBadMAC` | The shared secret differs from the CA's | Check the secret and the reference sent as `senderKID` |
| `client.ErrInfoTypeNotSupported` | The CA does not offer that support message | None, the CA decides |
| `*client.ConfirmationError` | The certificate was issued but `certConf` failed | Check the CA before retrying, a retry may issue a second certificate |

A peer that implements only RFC 4210 may need the SHA-1 MAC suite:
`pkicmp.NewMACCredentials(secret, pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1))`.

## Collecting diagnostics

Before asking for help, collect:

* the go-pki-cmp and Go versions
* the CMP peer and its version
* the request type and the message protection
* the error the library returned and the PKIStatusInfo the peer sent
* the peer's log lines around the failure

Never share shared secrets, private keys, full CSRs, CMP messages captured from a production system
or production endpoint details. [SUPPORT.md](https://github.com/misiektoja/go-pki-cmp/blob/main/SUPPORT.md)
says where to post.
