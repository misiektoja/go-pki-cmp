# Release Notes

Notable changes to go-pki-cmp. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.8.0 - TBD

This release adds central key generation (RFC 9483 section 4.1.6) to the client and the server: a device can have the CA generate its key pair and receive the private key signed and encrypted for it. The release also lets a client act as a registration authority that forwards requests in nested messages, ask for implicit confirmation, collect a certificate the CA keeps waiting in a later process, revoke a certificate it holds no copy of by issuer and serial number, send an invalidity date with a revocation and shape its requests the way vendor clients and test scenarios need: a chosen certReqId, extra generalInfo items, a requested validity and a chosen digest for signatures. Test aids let a client send deliberately wrong messages to check how a CA handles them.

### `client`

* **`SendIRWithCentralKeyGeneration`**, **`SendCRWithCentralKeyGeneration`** and **`SendKURWithCentralKeyGeneration`** ask the CA to generate the key pair. The request names a key algorithm or leaves the choice to the CA. **`EnrollResult.GeneratedKey`** holds the private key as a parsed key and as PKCS #8. The CA encrypts it to the shared secret of MAC credentials or for an RSA or ECDSA protection key. The client checks its signature and that it matches the issued certificate. A **`ConfirmationError`** keeps the key in `GeneratedKey` when the certConf fails afterwards. With `WithTrustedCAs` the signer must also chain to the trusted CAs and be a key generation authority. The client reads the AsymmetricKeyPackage of RFC 9810 as well as the id-data form that OpenSSL sends. A deferred request resumes with `ResumeEnrollment` and gets the key with the certificate.
* **`WithRegistrationAuthority`** makes the client act as a registration authority (RFC 9483 section 5.2.2.1). Every request of an operation, including certConf, pollReq and popdecr, goes out in a nested message signed with the RA credentials, which copies the transaction ID and nonces of the request inside. The request keeps the protection of the end entity. The CA answers it with a plain response, which the client verifies as usual. One request goes in each nested message. Tested against the server of this module. The OpenSSL 4.1 mock server does not accept nested messages.
* **`SendRRBySerial`** revokes a certificate named by its issuer and serial number, for a requester that has no copy of it, such as a registration authority or an operator who knows only the serial number and the CA. The CA decides whether the signer may revoke it, as for `SendRR`.
* **`WithInvalidityDate`** adds the invalidityDate CRL entry extension (RFC 5280 section 5.3.2) to a revocation request: the time at which the key was compromised or the certificate otherwise became invalid, which the CA may publish in the CRL entry. It is sent as a GeneralizedTime in UTC with a resolution of one second.
* **`WithImplicitConfirm`** asks the CA for implicit confirmation of an ir, cr, kur or p10cr, as RFC 9483 section 4.1.1 recommends. When the CA grants it, the client returns with **`EnrollResult.ImplicitConfirm`** set and sends no certConf, which saves a round trip. A CA that does not grant it gets the certConf as before. A grant the request did not ask for is honored as well, because the CA has closed the transaction. Before this release the client sent a certConf after such a grant, which a CA refuses as an unknown transaction.
* **`WithDeferredPolling`** returns an ir, cr, kur or p10cr at the first answer with status waiting, with **`EnrollResult.Pending`** set, instead of polling until the CA decides. The **`PendingEnrollment`** state encodes to JSON and holds no key or secret. **`ResumeEnrollment`** continues from it later, also in another process, with the same credentials: it polls, checks the certificate and confirms it as the Send methods do. **`ResumeEnrollmentWithIndirectPOP`** does the same for a request that proves possession with an encrypted certificate. Polling that stops while the CA still waits, at the context deadline, at `WithMaxPolls` or when a pollReq gets no answer, now returns a **`PendingError`** whose state resumes the transaction. `errors.Is` still finds a context error in it.
* **`WithCertReqID`** sets the certReqId of an ir, cr or kur. The CA must repeat it in its certificate response, which the client checks as before. A negative value is refused.
* **`WithGeneralInfo`** adds items to the generalInfo field of the request header after the certProfile, for example a vendor profile identifier a CA keys its policy on.
* **`WithPOPHash`** selects SHA-1, SHA-256, SHA-384 or SHA-512 for the signature proof of possession of an RSA or ECDSA key. Other key types take no digest and refuse the option.
* **`WithTemplateValidity`** asks for a validity period in the certificate template of an ir, cr or kur (RFC 4211 section 5): a notBefore, a notAfter or both. The CA decides the validity it grants and may shorten or ignore the request. RFC 9483 does not profile the field, so a lightweight CMP server need not honor it. A p10cr ignores the option.
* **`WithCertConfStatus`**, **`WithMessageMutator`** and **`WithProtectedMessageMutator`** are test aids for checking how a CA handles messages that break RFC 9483. `WithCertConfStatus` sends a statusInfo in the certConf, such as a rejection of the certificate. `WithMessageMutator` changes every message of the call before it is protected, for example to send a wrong certHash or a stale recipNonce. `WithProtectedMessageMutator` changes it after protection, for example to remove the protection. Without them the client sends what it sent before. Do not use them in production.

### `server`

* **`WithCentralKeyGeneration`** generates the key pair for an ir, cr or kur that asks for it. A **`KeyGenerator`** you provide makes the pair. A key generation authority whose certificate asserts id-kp-cmKGA or is a CA certificate signs the private key. The server encrypts it to the shared secret of a MAC-protected request or for the RSA or ECDSA protection key of a signed one. By default it uses the id-data form and the RFC 3211 key wrap that OpenSSL clients read. **`WithCentralKeyGenerationAsymmetricKeyPackage`** selects the RFC 9810 AsymmetricKeyPackage and **`WithCentralKeyGenerationAESKeyWrap`** the AES key wrap of RFC 9481. Your CA sees **`POPCentralKeyGeneration`** and gets the generated key from **`GeneratedPublicKeyFromContext`**. Delayed requests and snapshots keep the encrypted key until the certificate is ready.
* **`WithAnyCertReqID`** accepts an ir, cr or kur with a certReqId other than 0, which `LightweightPolicy` refuses by default as RFC 9483 asks, and repeats it in the response. Use it for RFC 4210 clients that number their requests or to test how a client checks the certReqId.
* **`RevocationRequest.InvalidityDate`** holds the invalidityDate a revocation request asks for, zero when it carries none, so a `Revoker` can publish it in the CRL entry. A request whose invalidityDate is not a GeneralizedTime is refused with badDataFormat and one that carries two with badRequest.
* **A certConf after the confirmWaitTime** is refused with badRequest and the `CertificateConfirmer` hears `ConfirmExpired`, as RFC 9483 section 4.1.1 asks. Before, the server confirmed such a certificate until `CleanupExpired` removed the transaction.

### `pkicmp`

* **`NewKeyPackage`** and **`ParseKeyPackage`** sign and verify the SignedData around a centrally generated private key in either content form. **`CertTemplate.RequestsCentralKeyGeneration`** and **`CentralKeyGenerationPublicKey`** read and build a request for central key generation. **`IsKeyGenerationAuthority`** checks a signer certificate. **`CertifiedKeyPair.EncryptedPrivateKey`** and **`SetEncryptedPrivateKey`** read and set the encrypted key. **`SignatureCredentials.Key`** returns the protection key.
* **`NewRevDetailsBySerial`** builds the RevDetails of a revocation request from an issuer name and a serial number, without the certificate. **`NewInvalidityDateExtension`** encodes an invalidityDate and **`RevDetails.AddCRLEntryExtension`** adds a CRL entry extension after the reasonCode.
* **`CertTemplate.Validity`** holds the **`OptionalValidity`** of a certificate template, which marshalling encodes and parsing reads. Times are encoded as UTCTime through 2049 and GeneralizedTime from 2050. A malformed validity or one with neither bound fails parsing, where before this release a received validity was skipped. The server does not pass it to the CA.
* **`SignatureCredentials.WithHash`** returns credentials that protect messages with the chosen digest instead of the one the key type selects, with the same choices and limits as `WithPOPHash`. **`CertReqMsg.GeneratePOPWithHash`** does the same for a proof of possession built by hand. A SHA-1 signature is still refused by a verifier unless it allows SHA-1.

### `cms`

* **`EncryptSignedData`** encrypts a SignedData for one recipient. **`Password`** and **`PWRIKEKPassword`** encrypt for a shared secret with PBKDF2 and either the AES key wrap of RFC 9481 or the RFC 3211 key wrap that OpenSSL reads. **`Decrypt`** opens both.

### `examples/mockserver`

* **The mock CA generates key pairs** for central key generation: ECDSA, RSA, Ed25519 and ML-DSA keys, signed by a key generation authority certificate with id-kp-cmKGA. **`MockCA.CentralKeyGeneration`** returns the server option. The example command enables it.
* **The mock CA accepts registration authorities.** **`MockCA.AuthorizeRA`** accepts nested messages signed with a certificate the CA issued with id-kp-cmcRA and has not revoked and refuses a MAC with wrongIntegrity. The example command enables it with `WithRAAuthorizer`.
* **The mock CA records the invalidityDate** of a revocation request, logs it and publishes it in the CRL entry.
* **The mock CA certifies ML-KEM-768 and ML-KEM-1024 keys** that prove possession by decryption, when the server accepts it with `WithEncryptedCertificatePOP` or `WithChallengeResponsePOP`. Their certificates have keyEncipherment as the only key usage. Before, the mock CA failed to sign them.

## v0.7.2 - 22 Oct 2026

This release lets a client keep the CA certificates in caPubs from becoming trust anchors and requires Go 1.27.3, which fixes GO-2026-6809 in `crypto/x509`.

### `client`

* **`WithoutCAPubsTrust`** keeps the CA certificates in caPubs of a MAC-protected response from extending `WithTrustedCAs`, so the issued certificate must chain to the configured trusted CAs. Use it when the anchors are known out of band. Without the option caPubs are still trusted, as RFC 9810 section 5.3.2 allows. `EnrollResult.CAPubs` still holds them.

### Requirements

* **Go 1.27.3 or newer** is required. Go 1.27.2 has GO-2026-6809 in `crypto/x509`, which the client and server reach when they verify certificate chains.

## v0.7.1 - 21 Oct 2026

This release fixes how the server answers faulty requests. A senderKID that names another key is refused, a malformed request gets an error message with badDataFormat and a reused transaction ID gets transactionIdInUse. The first and last fixes matter most to hosts whose certificate lookup ignores senderKID or that restore stored transactions into a server with small limits.

### `pkicmp`

* **infoValue** in genm, genp and generalInfo items must be one DER element. A value that is not valid ASN.1 or carries trailing data now fails parsing with a `ParseError`. Before, it was kept as raw bytes.
* **`ParseError.Header`** holds the message header when parsing failed after a readable header, so a receiver can still answer the sender.

### `server`

* **senderKID check.** A signed request whose senderKID does not match the subject key identifier of the certificate that verifies it is refused with badMessageCheck, as RFC 9483 section 3.5 requires. Before, a `CertificateLookup` that ignored senderKID let such a request through. A certificate without a subject key identifier is not compared.
* **Malformed requests** whose header can be read get an error message with badDataFormat over HTTP 200. Before, a malformed infoValue in a genm got a genp. A malformed ir, cr or kur body or malformed template extensions got systemFailure. A malformed protection or extraCerts field or trailing data got HTTP 400. Input without a readable header still gets HTTP 400. That now includes a request whose generalInfo holds a malformed infoValue, which was processed before.
* **transactionIdInUse** answers a first message that reuses the transaction ID of a transaction the server still holds, also when a transaction limit is full. Before, a full limit answered systemUnavail with "maximum transaction limit reached".

## v0.7.0 - 19 Oct 2026

This release adds **SLH-DSA keys** (FIPS 205, RFC 9909) for all twelve parameter sets. Devices can enroll SLH-DSA keys with `ir`, `cr`, `kur` and `p10cr` and protect CMP messages with them. A CA can hold an SLH-DSA key, sign the CMP responses with it and have clients verify its certificates. It works with OpenSSL 3.5 and later in both directions and with EJBCA 9.6.3. The library now depends on `github.com/cloudflare/circl` for SLH-DSA.

### `pkicmp`

* **SLH-DSA keys.** `ParsePublicKey` returns an SLH-DSA key as an `slhdsa.PublicKey` value from `github.com/cloudflare/circl/sign/slhdsa`. `MarshalPublicKey`, `PublicKeysEqual`, `GeneratePOP`, `VerifyPOP`, `NewSignatureCredentials` and `Verify` support SLH-DSA keys and signatures. Signatures use the pure mode with an empty context. The pre-hash variant HashSLH-DSA is refused. **`SLHDSAAlgorithmOID`** and **`SLHDSAAlgorithmFromOID`** map parameter sets to their identifiers.
* **`CheckCertificateRequestSignature`** checks the self-signature of a PKCS #10 request, SLH-DSA requests included, which crypto/x509 cannot check.
* **`NewCertStatus`** confirms a certificate signed by an SLH-DSA CA with SHA-512 and names it in `hashAlg`, as for ML-DSA. `Verify` checks protection certificates issued by an SLH-DSA CA and `RootCAKeyUpdate.Verify` checks SLH-DSA root certificates.

### `client`

* `SendIR`, `SendCR`, `SendKUR` and `SendP10CR` accept SLH-DSA keys and requests. `NewSignatureCredentials` with an SLH-DSA key protects requests with SLH-DSA signatures.
* The client trusts certificates and responses from a CA with an SLH-DSA key when that CA certificate is in the trust pool and travels in the response.

### `server`

* The server checks SLH-DSA proofs of possession, PKCS #10 requests and message protection. The CA receives an SLH-DSA key in the template as `slhdsa.PublicKey`. crypto/x509 cannot certify it, so the CA encodes the SubjectPublicKeyInfo with `pkicmp.MarshalPublicKey` and signs the certificate itself. Its key usage must not allow encipherment.
* **`WithSigner`** accepts an SLH-DSA CA key. `WithStrictProfileValidation` checks `extraCerts` chains that an SLH-DSA CA signed. Each SLH-DSA signature is slow, so a separate classical or ML-DSA signer keeps the responses fast.

### Requirements

* **github.com/cloudflare/circl v1.6.5** is now required for SLH-DSA. It brings in golang.org/x/sys v0.49.0.

## v0.6.0 - 16 Oct 2026

This release enrolls keys that cannot sign, such as ML-KEM-768 and ML-KEM-1024, through proof of possession by decryption: the encrypted certificate and challenge-response methods of RFC 9810. It works against EJBCA, with OpenSSL 3.0 and later for RSA keys and with OpenSSL 4.0 for ML-KEM keys. CAs can hold enrollment and revocation requests until someone approves or rejects them. They can also answer grantedWithMods. Some refusal reasons and the handling of waiting requests changed. Code that checks refusal reasons or relies on waiting requests should read the `pkicmp` and `server` entries before upgrading.

The new **documentation site** at [misiektoja.github.io/go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/) has client and server guides, option references, troubleshooting and the list of tested CMP implementations.

### `pkicmp`

* **Proof of possession by decryption.** **`NewKeyAgreementPOP`** joins `NewKeyEnciphermentPOP`. Both take `SubsequentMessageEncrCert` or `SubsequentMessageChallengeResp`. `NewEncryptedCertificate` carries an encrypted certificate in EnvelopedData and `NewEncryptedValueCertificate` in the EncryptedValue of CMP version 2. `CertOrEncCert.EncryptedCertificate` and `EncryptedValueCertificate` read them. `NewPopDecCBody`, `NewPopDecRBody`, `PKIBody.PopDecC`, `PKIBody.PopDecR`, `ChallengeWitness`, `Challenge.VerifyWitness`, `Rand` and `ParseRand` build and check the challenge and its answer.
* **ML-KEM public keys.** `ParsePublicKey` returns ML-KEM-768 and ML-KEM-1024 keys and refuses ML-KEM-512 with `ErrMLKEM512`. `MarshalPublicKey`, `IsKEMKey`, `PublicKeysEqual` and certificate requests support them.
* **Refusal reasons are more precise.** **`ReasonUntrustedSigner`** reports a protection certificate that does not chain to the trusted CAs, which used to fail with `ReasonSignatureFailed`. **`ReasonSenderKIDMismatch`** reports a senderKID that names none of the candidate certificates, which used to fail with `ReasonNoCandidateSigner`. That reason now means no certificate was available. A response that carries CA certificates without a senderKID, as Nokia NCM sends them, now reports the failure of the certificate with the sender's name instead of `ReasonSenderMismatch`, which now means no candidate has that name.
* **`VerifyOptions.AllowSenderKIDMismatch`** tries every candidate when the senderKID names none of them, for CAs that copy the senderKID of the request. Each candidate must still chain to the trusted CAs, have the sender's name and verify the signature.
* **`VerifyOptions.CurrentTime`** checks the protection certificate and its chain at a chosen time, such as when a recorded message was received. Do not take that time from the message when the result decides whether to act on it, because the sender sets its `messageTime`.

### `client`

* **`SendIRWithIndirectPOP`, `SendCRWithIndirectPOP` and `SendKURWithIndirectPOP`** enroll a key that cannot sign with `EncryptedCertificate` or `ChallengeResponse`. They accept ML-KEM-768 and ML-KEM-1024, RSA and elliptic curve keys on P-256, P-384 and P-521. They read certificates sent as EnvelopedData or as EncryptedValue and use CMP version 3 for the whole transaction. The CA must support the method. RFC 9483 lets it refuse both for a key that can sign.
* **`WithSenderKIDMismatch`** accepts signed responses whose senderKID names none of the candidate signer certificates. It is off by default.

### `server`

* **`WithEncryptedCertificatePOP`** and **`WithChallengeResponsePOP`** accept proof of possession by decryption. Both are off by default. `WithStrictProfileValidation` allows them only for keys that cannot sign. An encrypted certificate never gets implicit confirmation and a certConf with the wrong hash gets badPOP. Publish the certificate only after `ConfirmAccepted` and revoke it on `ConfirmExpired` or `ConfirmRejected`. A challenge-response request reaches the CA only after the right answer. **`POPMethodFromContext`** tells the CA which method a request used. Keys the server cannot encrypt for, such as X25519, are refused with badAlg.
* **Encrypted certificate format.** A CMP version 2 request for an RSA key gets its certificate as EncryptedValue in a version 2 response, because OpenSSL 3.0 and 3.2 read only that format. Other requests get EnvelopedData in a version 3 response. **`WithEnvelopedDataForVersion2`** sends EnvelopedData to version 2 RSA requests too, for clients that read only EnvelopedData, such as Bouncy Castle 1.86.
* **Snapshots** keep the proof-of-possession method and any challenge waiting for its answer. Earlier versions refuse a snapshot that holds such a challenge.
* **`Response.GrantedWithMods`** answers grantedWithMods for a CA that changed the request. **`Response.StatusText`** sets the statusString of the issued certificate. Both are off by default.
* **Waiting requests end the way immediate ones do.** A request that `PendingChecker.CheckPending` rejects gets an `ip`, `cp` or `kup` with its certReqId instead of an error message. The final response with a certificate grants implicit confirmation only when the request asked for it. Waiting and rejected responses no longer grant it. `WaitingResponse.Reason` becomes the statusString of the waiting response.
* **Polling follows RFC 9483 section 4.4.** An early pollReq gets another pollRep with the time left instead of failing with "polling too frequently". A pollReq must name the waiting request by its certReqId or by -1, otherwise it gets badRequest. **`WithOptionalPollReqRecipNonce`** accepts a pollReq without recipNonce, which the Insta Certifier 10 cmpclient and the Insta Certifier 7 ssh-cmpclient send. Without it they cannot collect a certificate that waited for a decision.
* **`WaitingError`** lets a `Revoker` or `RevocationAuthorizer` delay a revocation until `PendingChecker.CheckPending` decides. Such a revocation used to fail with systemFailure.
* **`WithWaitingLifetime`** keeps a waiting request for 24 hours after its last poll by default. Waiting requests used to expire with the confirmation wait of 10 seconds. **`WaitingExpirer`** and **`WithWaitingExpirer`** tell the CA about each waiting request that `CleanupExpired` removes.

### `cms`

* **New package** for the EnvelopedData of proof by decryption, with RSA-OAEP, ECDH on P-256, P-384 and P-521 and ML-KEM-768 and ML-KEM-1024 recipients. `Encrypt` derives ML-KEM keys with HKDF-SHA256. `Decrypt` also accepts the KDF2, KDF3 and SHAKE256 derivations that Bouncy Castle and EJBCA use. RSA PKCS #1 v1.5 key transport is refused in EnvelopedData.
* **`NewEncryptedValue` and `DecryptEncryptedValue`** handle the EncryptedValue of CMP version 2 for RSA keys. Encryption uses AES-256-CBC with PKCS #1 v1.5 key transport, the only combination OpenSSL reads. Decryption also accepts AES-128, AES-192, Triple DES and RSA-OAEP and reports a padding error like any other failure.

### `examples/mockserver`

* **`MockCA` certifies composite ML-DSA keys.** Enrolling one used to fail with systemFailure.

### Requirements

* **golang.org/x/crypto v0.58.0 or newer** is now required.

## v0.5.0 - 12 Oct 2026

This release adds the RFC 9483 support messages. Clients can ask a CA for its CA certificates, a root CA update, a certificate request template and newer CRLs. Servers can answer these requests.

### `pkicmp`

* **General messages** (`genm` and `genp`) are built with `NewGenMBody` and `NewGenPBody` and read with `PKIBody.GenM` and `PKIBody.GenP`. Typed helpers encode and parse CA certificates, root CA key updates, certificate request templates, CRL status lists, CRLs, the current CRL and unsupported OIDs. `RootCAKeyUpdate.Verify` checks that the old root certified the new one.
* **`NewCertProfileInfo`** builds the certProfile header item.

### `client`

* **Support messages:** `GetCACertificates`, `GetRootCAUpdate`, `GetCertReqTemplate`, `GetCRLUpdate` and `GetCurrentCRL` ask the CA for information. `SendGenM` sends other info types. A root CA update is returned only if the current root signed the new one. A CRL update is returned only if it is newer than the CRL the caller holds. **`ErrInfoTypeNotSupported`** reports a type the CA lists as unsupported or leaves out of its answer. Nokia NCM leaves all of them out. EJBCA Community Edition rejects general messages with `badRequest`.
* **`WithCertProfile`** names a certificate profile in the request header, for enrollment or for `GetCertReqTemplate`.

### `server`

* **Support messages** are answered by the optional **`CACertificatesProvider`**, **`RootCAUpdateProvider`**, **`CertReqTemplateProvider`** and **`CRLProvider`** interfaces. The server lists every requested type without a provider as unsupported. It refuses a root CA update that lacks a valid newWithOld certificate with `systemFailure`. A custom `Handler` answers through `Response.GeneralResponse`.
* **`WithStrictProfileValidation`** requires one item per general message and no value where RFC 9483 defines none.

## v0.4.0 - 11 Oct 2026

The library is now **go-pki-cmp**, with a new module path. This release adds device compatibility options, configurable MAC iteration limits and exact subject preservation. It fixes same-key update confirmation and enrollment with only a subjectAltName. Clients can distinguish failed certificate confirmation from a refused request.

### `pkicmp`

* **MAC iteration limits** are configurable through `VerifyOptions.MinMACIterationCount`, `MaxMACIterationCount` and `WithMACIterationLimits`. PasswordBasedMac and PBMAC1 defaults remain 1 to 500000. `VerifyResult.ProtectionParams` preserves the accepted range when echoing a peer's parameters.
* **`CertTemplate.RawSubject`** preserves the received subject DER. Marshalling uses `Subject` and now supports subjects built with `NewDirectoryNameFromRawDER`.
* **`VerifyPOPWithOptions`** supports poposkInput proofs. It checks publicKeyMAC against `POPOptions.SharedSecret` or the sender against `POPOptions.Sender`. Malformed inputs fail parsing. `AllowPoposkInputVariants` accepts Insta Certifier 10 cmpclient encodings. These proofs verify possession of the key but do not cover the certificate template.
* **`CertRequest.OldCertID`** reads a key update's issuer and serial number. **`CertID.Identifies`** matches them to a certificate.
* **Directory names use crypto/x509 string types:** PrintableString where possible and UTF8String otherwise. Unencodable values now fail marshalling instead of producing an invalid name.

### `client`

* **`WithMACIterationLimits`** bounds MAC iterations in responses. Sending a count outside the defaults also requires `pkicmp.WithMACIterationCount` and wider `pkicmp.WithMACIterationLimits` on the credentials.
* **`SendKUR` preserves the old certificate's subject encoding** unless `WithTemplateSubject` overrides it. For an empty subject it also copies subjectAltName unless one is supplied. Signed requests preserve the signer's subject encoding unless `WithSender` overrides it.
* **SAN-only requests carry a NULL-DN subject** as RFC 9483 requires, instead of omitting the subject field.
* **`ConfirmationError`** carries the issued certificate when certConf fails. The CA may keep or revoke it, so retrying enrollment may issue another certificate. `errors.As` still exposes the underlying error.

### `server`

* **`WithMACIterationLimits`** bounds MAC iterations in requests. Responses echo the accepted count. Out-of-range requests fail before key derivation with `badMessageCheck`. Rejected MAC parameters now report "MAC protection parameters not accepted".
* **`WithRawSubject`** preserves every requested subject attribute, its order and string type for CRMF and PKCS#10 requests. It is off by default. CAs must check all attributes in `Subject.Names` and clear `RawSubject` before changing `Subject`.
* **`WithOptionalCertConfRecipNonce`** accepts certConf without recipNonce. A supplied nonce must still match and certificate hashes are still checked.
* **`WithPoposkInputVariants`** accepts Insta Certifier 10 cmpclient proofs for `ir`, `cr` and `kur`. Signatures and publicKeyMACs are verified, but only message protection binds the requested names to the key holder.
* **`WithSignatureProtectionPOP`** accepts a missing CRMF proof when the message is signed with the requested key, as in Nokia ssh-cmpclient same-key updates. MAC-protected requests still need a proof.
* **NULL-DN subjects with subjectAltName are accepted**, including under strict validation. The CA template marks subjectAltName critical. `WithOptionalSubject` also accepts CRMF templates that omit the subject field. Both cases require subjectAltName.
* **Revocation options** accept missing reasonCode (`WithOptionalRevocationReason`), missing issuer (`WithOptionalRevocationIssuer`) or MAC protection (`WithMACRevocation`). An absent reason becomes unspecified. A missing issuer comes from the signer's certificate when its serial matches. Otherwise the CA must resolve the serial without an issuer and reject ambiguous matches. MAC revocation requires `RevocationAuthorizer` approval.
* **`WithStrictProfileValidation`** overrides the optional nonce, proof, subject and revocation rules above and rejects all poposkInput proofs. Raw subject preservation and MAC limits still apply. Strict validation now accepts extraCerts without a self-signed root, while checking chain order. `CertificateLookup` remains responsible for trust.
* **Rejection status texts** now identify unsupported protocol versions and message types.
* **Same-key updates complete confirmation** when certConf uses the original request's credentials. Confirmation with the newly issued certificate remains refused.
* **MAC-protected responses repeat the request's senderKID**, including when a server signer is configured.

### Requirements

* **The module path is `github.com/misiektoja/go-pki-cmp`.** Update imports and the `go.mod` requirement from `github.com/misiektoja/go-pkicmp-ng`. Package names are unchanged. Releases through v0.3.2 use the old path.
* **go-composite-mldsa v0.2.1** is now required, with fixes for key parsing and certificate signing.

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
