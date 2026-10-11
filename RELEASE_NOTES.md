# Release Notes

Notable changes to go-pkicmp-ng. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.4.0 - TBD

Servers can accept CMP devices that the default settings refuse. They can issue the subject exactly as a device requested it, accept a certConf without recipNonce and accept MAC iteration counts outside the default range. Further options accept the Insta Certifier 10 cmpclient, key updates that keep the key without a proof of possession, requests that name the device only in subjectAltName and revocation requests without a reason code, without an issuer or protected with a shared secret. `WithStrictProfileValidation` turns these options off. Key updates that keep the key now complete their confirmation.

### `pkicmp`

* **MAC iteration count limits are configurable.** **`VerifyOptions.MinMACIterationCount`** and **`MaxMACIterationCount`** bound the PasswordBasedMac or PBMAC1 iteration count the sender chose. The defaults are unchanged at 1 and 500000, exported as `DefaultMinMACIterationCount` and `DefaultMaxMACIterationCount`. **`WithMACIterationLimits`** applies a range when protecting, including when echoing a peer's parameters with `WithProtectionAlgorithm`. `VerifyResult.ProtectionParams` carries the range the message was verified against, so echoing it needs no extra option.
* **`CertTemplate.RawSubject`** holds the subject name exactly as received. Marshalling still encodes `Subject`.
* **poposkInput proofs of possession.** `VerifyPOPWithOptions` verifies a signature proof that carries poposkInput, which RFC 4211 §4.1 allows when the template has no subject. It checks the publicKeyMAC against **`POPOptions.SharedSecret`** within the MAC iteration limits or the sender against **`POPOptions.Sender`**. Such a proof previously failed verification. A malformed poposkInput is now a parse error. **`POPOptions.AllowPoposkInputVariants`** accepts the poposkInput that the Insta Certifier 10 cmpclient sends, which does not follow RFC 4211. Its signature does not cover the template.
* **`CertRequest.OldCertID`** returns the certificate that a key update names in its oldCertID control. **`CertID.Identifies`** reports whether a CertID names a given certificate.
* **A template subject from `NewDirectoryNameFromRawDER` is encoded.** `CertTemplate` previously dropped it, so the request carried no subject.

### `client`

* **`WithMACIterationLimits`** sets the accepted iteration counts in MAC-protected responses. To send a count outside the default range, set it with `pkicmp.WithMACIterationCount` and widen `pkicmp.WithMACIterationLimits` on the credentials.

### `server`

* **`WithMACIterationLimits`** sets the accepted iteration counts in MAC-protected requests, and responses echo the request's count. A request outside the range is rejected with `badMessageCheck` before any key derivation. A request whose MAC parameters are not accepted, for example an iteration count out of range or a PBMAC1 key length out of range, now gets the status text "MAC protection parameters not accepted" instead of "MAC verification failed".
* **`WithRawSubject`** sets `template.RawSubject` to the subject a CRMF or PKCS#10 request asked for, so the issued certificate keeps every attribute, such as domainComponent and emailAddress, with its order and string type. It is off by default. `x509.CreateCertificate` prefers `RawSubject` to `Subject`, so a CA that changes the subject must clear it and a CA that checks the subject must check every attribute in `Subject.Names`.
* **`WithOptionalCertConfRecipNonce`** accepts a certConf without recipNonce, which the server otherwise rejects with `badRecipientNonce`. A recipNonce that is present must still match. The certificate hash in each CertStatus still binds the confirmation to the issued certificate.
* **`WithPoposkInputVariants`** accepts the proof of possession that the Insta Certifier 10 cmpclient sends with `ir`, `cr` and `kur`. The server refuses it with `badPOP` by default. The signature and the publicKeyMAC are still verified, but the proof does not cover the template, so only the message protection binds the requested names to the key holder.
* **`WithSignatureProtectionPOP`** accepts a CRMF request without a proof of possession when its protection signature was made with a certificate for the requested key. Nokia ssh-cmpclient sends such a key update when it keeps the key. A MAC-protected request still needs a proof.
* **`WithOptionalSubject`** accepts a request without a subject when it requests a subjectAltName extension. The CA must mark that extension critical, as RFC 5280 §4.2.1.6 requires for an empty subject.
* **Revocation options.** **`WithOptionalRevocationReason`** accepts an `rr` without reasonCode, which reaches the CA as reason unspecified. **`WithOptionalRevocationIssuer`** accepts an `rr` without an issuer. When the request is signed with the certificate it names, the server takes the issuer from that certificate. Otherwise `RevocationRequest.RawIssuer` is empty and the CA must find the certificate by serial number. **`WithMACRevocation`** passes a MAC-protected `rr` to `RevocationAuthorizer`, which decides whether the shared secret may revoke the certificate.
* **`WithStrictProfileValidation` turns these options off**, including `WithOptionalCertConfRecipNonce`. It also refuses every poposkInput, as RFC 9483 §4.1.1 requires.
* **Status texts for two rejections.** A request with an unsupported protocol version gets "unsupported pvno" with the version. A message type the server does not handle, such as `genm`, gets "message type not supported". Both previously had no text.
* **Key updates that keep the key are confirmed.** The server refused the certConf of a `kur` or `cr` for the key of its signer certificate with `badMessageCheck` and "certConf signed with newly issued certificate", although the client signed it with the certificate of the request. A certConf signed with the newly issued certificate is still refused.
* **Responses to MAC-protected requests repeat the request's senderKID** when the server also has a signer. They carried the signer's key identifier, which clients that check it refuse.

## v0.3.2 - 9 Oct 2026

This version requires Go 1.27.2 and updates composite ML-DSA support to the published v0.2.0 library.

### Requirements

* **Go 1.27.2 or newer** is required. **go-composite-mldsa v0.2.0** validates composite key encodings more strictly. Valid keys retain the same encoding and algorithm support.

## v0.3.1 - 2 Oct 2026

The client can revoke certificates at CAs that sign the revocation response without attaching their certificate.

### `pkicmp`

* **`ReasonNoCandidateSigner`** reports a signature-protected message that carries no certificate to verify it, either none at all or none matching its senderKID. Such a message previously failed with `ReasonSignatureFailed`, so code that checks for that reason no longer sees it in this case.

### `client`

* **`WithServerCerts`** supplies the CMP server certificates the client knows out of band, like the `-srvcert` option of `openssl cmp`. The client tries them after the certificates in the response, so a response without extraCerts verifies. Unlike `-srvcert`, each must still chain to `WithTrustedCAs`, match the sender in the response and verify the signature. A CA certificate without the digitalSignature key usage is accepted, as it already is from extraCerts. Without the option such a response fails with `ReasonNoCandidateSigner` and the error names `WithServerCerts`.

## v0.3.0 - 30 Sep 2026

Devices can enroll **composite ML-DSA keys**, which pair an ML-DSA key with a classical key in one certificate, through `ir`, `cr`, `kur` and `p10cr`, and revoke those certificates with `rr`.

### `pkicmp`

* **Composite ML-DSA proof of possession.** `VerifyPOP` and `VerifyPOPWithOptions` check a composite signature over the certificate request. The algorithm must match the requested key exactly and its parameters must be absent. **`CertReqMsg.PublicKey`** returns a composite key as `*compositemldsa.PublicKey`.

### `client`

* **`SendIR`, `SendCR` and `SendKUR` accept a composite ML-DSA key** and sign the proof of possession with it. **`SendP10CR`** accepts a PKCS#10 request for a composite key made with `compositex509.CreateCertificateRequest`. The client checks that the issued certificate carries that key.

### `server`

* **Composite ML-DSA certificate requests** reach the CA after the server verifies their proof of possession. The template carries the key as `*compositemldsa.PublicKey`, which the CA certifies with `compositex509.CreateCertificate`. Confirmation, key update and revocation work for these certificates as for classical ones.

## v0.2.0 - 29 Sep 2026

A CA with a post-quantum composite ML-DSA key can sign CMP messages and the certificates it issues. Revoke certificates over CMP from the client and accept revocation requests in the server. Servers can also accept requests that a registration authority forwards in nested messages. The client tells the CA when it refuses an issued certificate. The server no longer passes requests without a verified proof of possession to the CA. Devices that implement only RFC 4210 can enroll with the default settings. SHA-1 can be enabled for the ones that need it.

### `pkicmp`

* **Composite ML-DSA signatures** (draft-ietf-lamps-pq-composite-sigs) protect and verify CMP messages when the key comes from [go-composite-mldsa](https://github.com/misiektoja/go-composite-mldsa). **`NewSignatureCredentials`** accepts composite keys and certificates. Algorithm parameters must be absent. **`NewCertStatus`** and **`CertHash`** hash a certificate signed by a composite key with the hash that composite algorithm uses. `NewCertStatus` names that hash explicitly. With **`VerifyOptions.TrustPool`**, a certificate signed by a composite key is accepted only when its issuer is also in `ExtraCerts` and no certificate in the path has name constraints. Composite keys in certificate requests and proof of possession are not supported yet.
* **`RevReqContent` and `RevRepContent`** encode and parse revocation request (`rr`) and response (`rp`) bodies. **`NewRevDetails`** names a certificate by issuer and serial number and adds a **`CRLReason`**.
* **`CertTemplate`** supports the `serialNumber` and `issuer` fields.
* **Nested message bodies use the encoding RFC 4210 and RFC 9810 define**, a sequence of one or more messages. They previously held a single message directly, which conforming peers could not parse. **`NewNestedBody`** takes one or more messages and **`Nested`** returns a slice. A protected message keeps the exact bytes its protection covers, so a received message can be forwarded without breaking its protection.
* **`WithPBMAlgorithms`** chooses the one-way function and HMAC of PasswordBasedMac. `WithPBMAlgorithms(crypto.SHA1, crypto.SHA1)` produces the SHA-1 profile that RFC 4210 requires. `WithPBM` still defaults to SHA-256.
* **SHA-1 signatures** (`sha1WithRSAEncryption` and `ecdsa-with-SHA1`) verify when **`VerifyOptions.AllowSHA1Signatures`** is set. **`VerifyPOPWithOptions`** does the same for proof of possession. By default they fail with `ReasonUnsupportedAlgorithm`, which is now also the reason for a PasswordBasedMac or PBMAC1 hash function the library does not implement.

### `client`

* **Certificates from a composite ML-DSA CA** are verified and confirmed. The CA certificate must arrive in extraCerts or caPubs, even when it is already in the pool passed to `WithTrustedCAs`.
* **`SendRR`** asks the CA to revoke a certificate. A rejection such as `certRevoked` is returned as `*pkicmp.PKIStatusError`. Sign the request with the certificate being revoked, or with registration authority credentials when the CA allows that. A delayed answer is polled like enrollment.
* **Refused certificates are reported to the CA.** When an issued certificate fails validation or certifies a different key, the client sends `certConf` with status rejection before returning the error. The CA previously learned of it only when its confirmation wait expired.
* **Certificate responses must match the request.** The client accepts a response only when it holds one `CertResponse` with the certReqId of the request. A p10cr response may carry `-1` or `0`. A certificate under another certReqId is rejected in `certConf`. The client previously read the first `CertResponse` without checking its certReqId and ignored any others.
* **`WithSHA1Signatures`** accepts responses signed with SHA-1 by RFC 4210 era CAs. Certificates signed with SHA-1 are still rejected, because crypto/x509 does not accept them.

### `server`

* **`WithSigner` accepts composite ML-DSA keys** and `WithStrictProfileValidation` checks composite signatures in the extraCerts chain. A CA issues with a composite key through `compositex509.CreateCertificate`, as the package documentation describes.
* **Revocation requests** reach CAs that implement the new **`Revoker`** interface. By default only the certificate being revoked may sign the request. Implement **`RevocationAuthorizer`** to accept other signers, such as a registration authority. Revocation is synchronous. A CA without `Revoker` rejects revocation requests with `badRequest`.
* **Requests forwarded by a registration authority** in a nested message are accepted when **`WithRAAuthorizer`** is set (RFC 9483 §5.2.2.1). The server verifies the protection of both the RA and the end entity, then answers the end entity as if it had sent the request directly. The authorizer decides which RAs may forward requests and whether a MAC-protected nested message is allowed, which RFC 4210 permits and RFC 9483 does not. **`SenderIdentity.RA`** names the approving RA. Without an authorizer nested messages are still rejected with `badRequest`. Batches of several messages are always rejected. `WithStrictProfileValidation` requires a signed nested message to carry `extraCerts`.
* **`LightweightPolicy`** requires revocation requests to use signature protection and to carry a reason code.
* **Proof of possession by signature is required** for every `ir`, `cr` and `kur`, with or without a policy. Requests for keys that cannot sign, such as X25519, are rejected with `badPOP` and requests without a public key with `badCertTemplate`. They previously reached the CA without any verified proof.
* **RFC 4210 clients are accepted without the RFC 9483 header rules.** A first request without a transactionID gets one from the server. A missing or short senderNonce is accepted. Such transactions also survive a snapshot and restore. `WithStrictProfileValidation` still rejects both.
* **MAC clients that send only a sender name no longer share transactions.** Transactions and the `WithMaxTransactionsPerCredential` limit are bound to the senderKID and the sender name together. Clients without a senderKID previously shared one transaction space, so one could confirm or reject another's certificate and all of them shared one limit. A MAC transaction in a snapshot taken by an earlier version cannot be continued after restore and expires.
* **Every `CertStatus` in a `certConf` is checked.** Each must carry the certHash and certReqId of the issued certificate and all of them must agree. The CA is then notified once. A p10cr confirmation may use certReqId `-1` or `0`. The server previously checked only the first entry and notified the CA once per entry, so an unchecked extra entry could reject a certificate the first one accepted. An **empty `certConf`** rejects the certificate, as RFC 9810 §5.3.18 defines, where the CA previously received nothing. `WithStrictProfileValidation` also rejects a `certConf` with more than one `CertStatus`.
* **Unsupported protection algorithms are reported as `badAlg`** instead of `badMessageCheck`. This includes SHA-1 signatures, which **`WithSHA1Signatures`** accepts in message protection and in CRMF proof of possession.

### Requirements

* **github.com/misiektoja/go-composite-mldsa v0.1.0** is a new dependency. It has no dependencies of its own.
* **golang.org/x/crypto v0.57.0 or newer** is required. Older versions carry published advisories, none of which reach the code this library calls.

## v0.1.0 - 27 Sep 2026

Enroll and confirm certificates with **post-quantum ML-DSA keys and signatures**.

### `pkicmp`

* **ML-DSA-44, ML-DSA-65 and ML-DSA-87 (post-quantum)** support covers certificate keys, CRMF proof of possession and pure message signatures. Algorithm parameters must be absent.
* **`NewCertStatus`** supplies the explicit SHA-512 confirmation hash identifier for ML-DSA-signed certificates.
* **Ed25519 message protection** signs the original protected bytes instead of incorrectly prehashing them.

### `client`

* **ML-DSA certificate confirmation** uses CMPv3 and an explicit hash algorithm. Peers must support these fields.

### `server`

* **ML-DSA proof of possession** is required for signing-capable requests unless the configured registration-authority proof path applies.

### Requirements

* **Go 1.27.1 or newer** is required. Classical algorithms remain supported.

## v0.0.6 - 26 Sep 2026

OpenSSL clients can complete certificate confirmation after enrollment from an Ed25519-signing CA.

### `pkicmp`

* **Explicit confirmation hash algorithms** use the CMP ASN.1 tag format. Malformed tags and trailing confirmation fields are rejected.

### `server`

* **Certificate confirmation** verifies the declared hash algorithm when supplied. Unsupported algorithms and invalid digests are rejected without accepting the certificate.

## v0.0.5 - 23 Sep 2026

Servers can save CMP transaction state and resume certificate confirmation or polling after a restart.

### `server`

* **`SnapshotTransactions` and `RestoreTransactions`** preserve credential binding, nonces, certificates and MAC protection parameters. The host supplies durable storage, serializes access and saves responses before delivery. Snapshots must come from trusted storage and use the same response-signing certificate. JSON-serializable issuance references support an optional restore decoder. Recovery does not provide an automatic response cache or database integration.

## v0.0.4 - 4 Sep 2026

Correctness release. Several ways a server could fail quietly are now reported, including a freshness check a client could opt out of, a signer misconfiguration that dropped response protection, and a certificate confirmation the CA refused to record. Handler error text no longer reaches the peer, and enrollment works against an Ed25519-signing CA.

### `pkicmp`

* **`PKIHeader.HasMessageTime`** reports whether a message carried a `messageTime`. The zero time is a legal `GeneralizedTime`, so the field alone could not tell an absent value from one a peer actually sent. Re-encoding a parsed message keeps the field as received.
* **`CertHash`** computes the certHash of a certificate with the hash its signature algorithm requires. The client and server previously kept private copies of that mapping and had drifted apart.

### `client`

* **Enrollment from an Ed25519-signing CA completes.** The client could not compute the certHash for such a certificate, so it failed after the CA had already issued one and never sent `certConf`, leaving the certificate to expire unconfirmed.
* **An empty `pollRep` no longer bypasses the minimum poll interval.** The floor set by `WithCheckAfterLimits` was applied only when the response carried a `checkAfter`, so a peer sending empty poll responses could drive polling as fast as the network allowed.

### `server`

* **`WithMessageTimeTolerance` can no longer be switched off by the peer it constrains.** A client sending `00010101000000Z` looked like it had sent no `messageTime` and skipped the check entirely. Presence is now read from the wire, so every value present is checked and only a genuinely absent `messageTime` is exempt.
* **A signer key that does not match its certificate is reported by the new `Server.Err`.** Previously the mismatch was discovered while building each response and then discarded, so the server returned issued certificates in unprotected messages that no conforming client accepts. Such a server now answers every request with `systemFailure` and issues nothing. Check `Server.Err` at startup.
* **A `CertificateConfirmer` that returns an error now rejects the `certConf` with that status** instead of replying `pkiConf` as though the certificate had been confirmed (RFC 9483 §3.6.2). The transaction is kept, so the client can retry and the CA still receives `ConfirmExpired` if no retry succeeds.
* **A Handler error that is not a `server.Error` no longer puts its text on the wire.** The peer is told only `systemFailure`, so an error carrying a connection string or a file path discloses nothing. A wrapped `server.Error` also keeps the status and `failInfo` the Handler chose, instead of being downgraded to `systemFailure`.
* **Errors raised after a shared secret authenticated the request are MAC-protected**, not signed. A bootstrapping client with no trust anchor can now verify a rejection such as `transactionIdInUse`. Errors raised before authentication have no credential and stay signed.

### Requirements

* **Go 1.26.8 or later is now required**, raised from 1.26.1. The intervening patch releases fix standard library issues this library is exposed to, including unbounded recursion in `encoding/asn1`, which parses every message a peer sends.

### Documentation

* **Package and option documentation is shorter.** The reference content, RFC citations and interoperability notes are unchanged, with the surrounding justification prose removed.

## v0.0.3 - 25 Aug 2026

Interoperability and server-validation release. Repeated key updates can identify the exact certificate being replaced, while CMP servers can enforce a deployment-specific freshness window for protected requests.

### `pkicmp`

* **CRMF `CertRequest.controls` are parsed and serialized**, with **`NewOldCertIDControl`** encoding the existing certificate issuer and serial exactly as required by RFC 4211. Controls are covered by CRMF proof of possession, so changing one invalidates the POP signature.

### `client`

* **KUR includes the recommended `oldCertID` control automatically** when signature credentials expose the existing certificate. This disambiguates repeated same-key renewal on servers that cannot infer which of several certificates is being updated. Custom credentials can supply it with **`WithOldCertificate`**.

### `server`

* **`WithMessageTimeTolerance` optionally rejects stale or excessively future-dated protected messages with `badTime`**. Validation is disabled by default because RFC 9483 leaves the allowed difference to local policy. A missing `messageTime` remains accepted.

## v0.0.2 - 21 Aug 2026

Security and interoperability release. Response verification is stricter, shared-secret protection is safer against hostile input, and enrollment works reliably against common CAs and vendor CMP clients.

### `pkicmp`

* **Pin the protection mechanism you expect** with **`VerifyOptions.RequiredProtection`**. The default accepts either MAC or signature, which remains right when the peer's mechanism is unknown. When you already know what a message should use, pin that mechanism instead.
* **Signature verification binds the sender to the protection certificate**, so a trusted leaf cannot sign for another identity.
* **PBKDF2 parameters from untrusted messages are bounded** before key derivation, closing a remote crash and abusive CPU use.
* **PBMAC1 omits optional PBKDF2 fields** the way RFC 8018 allows; absent `keyLength` and `prf` now default correctly.
* **`confirmWaitTime` is encoded as `GeneralizedTime`**, with **`ParseConfirmWaitTime`** to read it.
* **CMP protection certificates with CMP extended key usages verify** instead of being rejected for lacking `serverAuth`.
* **An unsupported hash algorithm in PBMAC1 parameters is rejected** with a `VerificationError` instead of crashing during key derivation.
* **An expired protection certificate no longer authenticates** on the pre-trusted (`TrustedCert`) verification path used by `server.WithCertificateLookup`.
* **`VerifyResult.ProtectionCertificate`** carries the signer across a transaction when later messages omit `extraCerts`.
* **`RequireDigitalSignatureKeyUsage`** is available for strict deployments; off by default for common CA setups.
* **Package docs now list caller responsibilities** for verification, polling, `caPubs` trust and issued-certificate checks.

### `client`

* **Forged issuance responses are rejected** by binding the signer to the claimed sender, checking that the issued certificate matches the requested public key, and optionally pinning the response protection mechanism with **`WithResponseProtection`**.
* **Enrollment against real CAs is fixed**: recipient names built in Go are sent, distinguished names keep attributes Go cannot rebuild from typed fields (so a recipient copied from an EJBCA CA certificate is no longer truncated), intermediate-issued certificates validate against a configured root, and the final `pkiConf` verifies when `extraCerts` appear only once.
* **Other fixes**: CMP content on HTTP 4xx/5xx responses is handled, delayed issuance accepts the original request nonce, and CMP media type parsing follows HTTP rules instead of exact-string matching.
* **Polling is safer**: each `checkAfter` wait is clamped with **`WithCheckAfterLimits`** (default 1s to 1h), and deadline errors name the wait they expired in.
* **Unauthenticated CA rejections are surfaced** as **`UnverifiedStatusError`** when a shared-secret client has no trust anchors. Set **`WithTrustedCAs`** wherever an anchor is already available.

### `server`

* **Vendor clients complete enrollment** against the reference server (OpenSSL `cmp`, Nokia `ssh-cmpclient`).
* **Strict RFC 9483 profile checks are opt in** via **`WithStrictProfileValidation`**. Default behavior favors field interoperability.
* **Issuance is hardened**: proof of possession is enforced without a policy wrapper, malformed `BasicConstraints` are rejected, and looked-up protection certificates must match the header sender.
* **Other fixes**: `confirmWaitTime` is sent as a `GeneralizedTime`, response `extraCerts` lead with the protection certificate and no longer repeat one, and a transaction cleanup race under concurrent `CleanupExpired` is fixed.

## v0.0.1 - 27 May 2026

Initial pre-release, providing a partial implementation of CMP as specified in RFC 9810, which obsoletes RFC 4210, profiled by RFC 9483 (Lightweight CMP Profile), with RFC 4211 (CRMF) and RFC 6712 (CMP over HTTP), split into three packages. Both protocol versions defined by RFC 9810 are supported, so the library interoperates with peers implementing the original RFC 4210 CMPv2 (`cmp2000`) as well as CMPv3 (`cmp2021`).

### Features

* **`pkicmp`** provides the core CMP and CRMF ASN.1 types, covering parsing, serialization, PVNO 2 and 3, and message protection using either a shared secret (PasswordBasedMac and PBMAC1) or X.509 signatures.
* **`client`** implements the IR, CR, KUR and P10CR enrollment flows, including polling for deferred issuance, response verification and certificate confirmation.
* **`server`** exposes a CMP endpoint as a standard `http.Handler` that authenticates clients, tracks transactions, supports asynchronous issuance and enforces policy through middleware, including the Lightweight CMP Profile.

Interoperability is exercised by integration tests: the client against EJBCA and OpenSSL, and the server against the Siemens CMP Test Suite.
