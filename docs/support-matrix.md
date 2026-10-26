# Support matrix

What the library implements, which option turns a feature on and what is out of scope.
[Known limitations](known-limitations.md) explains the consequences of the gaps and
[Tested implementations](interoperability/tested-implementations.md) names the peers each feature
was tested with.

## Standards

| Standard | Coverage |
| --- | --- |
| RFC 9810 (obsoletes RFC 4210 and RFC 9480) | CMP version 2 and version 3 messages, MAC and signature protection, transactions, polling, certificate confirmation, proof of possession by decryption |
| RFC 9483 | Lightweight CMP Profile: enrollment, central key generation, revocation, support messages, delayed delivery and requests a registration authority forwards in nested messages |
| RFC 4211 | CRMF certificate requests, controls and proof of possession |
| RFC 9811 (obsoletes RFC 6712) | HTTP transfer: `POST` with `application/pkixcmp` |
| RFC 9481 | CMP algorithms. PBMAC1 (RFC 8018) is the default MAC |
| RFC 5652, RFC 4211 | CMS EnvelopedData and CMP version 2 EncryptedValue for encrypted certificates. EnvelopedData and SignedData for centrally generated keys |
| RFC 5958 | OneAsymmetricKey and AsymmetricKeyPackage for centrally generated keys |
| RFC 9629, RFC 9936 | KEMRecipientInfo for ML-KEM recipients |
| RFC 9935 | ML-KEM public keys in certificates |
| RFC 9909 | SLH-DSA keys and pure signatures for the twelve FIPS 205 parameter sets, through [circl](https://github.com/cloudflare/circl) |
| draft-ietf-lamps-pq-composite-sigs-19 | Composite ML-DSA keys and signatures, through [go-composite-mldsa](https://github.com/misiektoja/go-composite-mldsa) |

## Messages

| Message | Client | Server |
| --- | --- | --- |
| `ir` / `ip` | `SendIR`, `SendIRWithIndirectPOP`, `SendIRWithCentralKeyGeneration` | Always |
| `cr` / `cp` | `SendCR`, `SendCRWithIndirectPOP`, `SendCRWithCentralKeyGeneration` | Always |
| `kur` / `kup` | `SendKUR`, `SendKURWithIndirectPOP`, `SendKURWithCentralKeyGeneration` | Always |
| `p10cr` / `cp` | `SendP10CR` | Always |
| `rr` / `rp` | `SendRR`, `SendRRBySerial` | A CA that implements `Revoker` |
| `certConf` / `pkiConf` | Sent and checked automatically, unless the CA grants the implicit confirmation `WithImplicitConfirm` asks for | Always. `WithImplicitConfirm` skips it |
| `pollReq` / `pollRep` | Sent automatically, or later by `ResumeEnrollment` | A CA that implements `PendingChecker` |
| `genm` / `genp` | `GetCACertificates`, `GetRootCAUpdate`, `GetCertReqTemplate`, `GetCRLUpdate`, `GetCurrentCRL`, `SendGenM` | The matching provider interfaces |
| `popdecc` / `popdecr` | Answered automatically with `ChallengeResponse` | `WithChallengeResponsePOP` |
| `nested` | Not sent | `WithRAAuthorizer`, one message per nested message |
| `error` | Parsed and verified | Sent for every refusal |

## Message protection

| Mechanism | Algorithms |
| --- | --- |
| MAC | PBMAC1 (default) and PasswordBasedMac with HMAC-SHA1 to HMAC-SHA512. Iteration counts from 1 to 500000 are accepted by default |
| Signature | RSA PKCS #1 v1.5 and ECDSA with SHA-256, SHA-384 or SHA-512, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA and composite ML-DSA |
| SHA-1 signatures | RSA and ECDSA with SHA-1, off by default. `WithSHA1Signatures` in the `client` or `server` package accepts them |

## Proof of possession

| Method | Server |
| --- | --- |
| Signature (`POPOSigningKey`) | Always |
| PKCS #10 self-signature in a `p10cr` | Always |
| Signature protection made with the requested key, no `popo` | `WithSignatureProtectionPOP` |
| Encrypted certificate (`encrCert`) | `WithEncryptedCertificatePOP` |
| Challenge-response (`challengeResp`) | `WithChallengeResponsePOP` |
| `raVerified` | Refused with notAuthorized |
| None, the server generates the key pair | `WithCentralKeyGeneration` |

The client sends a signature proof for every key that can sign and either decryption method
through the `*WithIndirectPOP` methods.

## Keys

| Use | Accepted |
| --- | --- |
| Certificates that sign | RSA, ECDSA on P-256, P-384 and P-521, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87, the twelve SLH-DSA parameter sets and composite ML-DSA |
| Proof by decryption | ML-KEM-768 and ML-KEM-1024, RSA and elliptic curve keys on P-256, P-384 and P-521 |
| EncryptedValue for CMP version 2 | RSA only |
| Receiving a centrally generated key | MAC credentials, RSA protection keys and ECDSA protection keys on P-256, P-384 and P-521 |

## Server interfaces

| Interface | Required | Purpose |
| --- | --- | --- |
| `CA` | Yes or a custom `Handler` | Issues certificates |
| `SecretLookup` | For MAC-protected requests | Finds the shared secret |
| `CertificateLookup` | For signature-protected requests | Finds the sender's certificate |
| `CertificateConfirmer` | No | Learns whether the client accepted the certificate |
| `PendingChecker` | For delayed requests | Decides a waiting request when the client polls |
| `WaitingExpirer` | No | Learns that a client stopped polling |
| `Revoker` | For revocation | Revokes a certificate |
| `RevocationAuthorizer` | For revocation by a signer other than the certificate holder | Approves the request |
| `CACertificatesProvider`, `RootCAUpdateProvider`, `CertReqTemplateProvider`, `CRLProvider` | For support messages | Answer each general message |
| `RAAuthorizer` | For nested messages | Approves the registration authority |
| `KeyGenerator` | For central key generation | Generates the key pair |

## Not supported

| Capability | Status |
| --- | --- |
| Key recovery, cross-certification and announcements | Not implemented |
| A centrally generated private key in EncryptedValue | Refused by the client and never sent by the server |
| Several requests in one nested message (RFC 9483 section 5.2.2.2) | Refused with badRequest |
| Sending nested messages from the client | Not implemented |
| ML-KEM-512 | Refused, the Go standard library does not implement it |
| Older Dilithium encodings | Not supported |
| HashSLH-DSA, the pre-hash variant of SLH-DSA | Refused |
| SHAKE256 as the `hashAlg` of a certificate confirmation | Refused. An explicit `hashAlg` may be SHA-256, SHA-384 or SHA-512 |
| X25519 keys for proof by decryption | Refused with badAlg |
| RSA PKCS #1 v1.5 key transport in EnvelopedData | Refused |
| Protocol versions other than 2 and 3, such as `pvno` 0 or 1 | Refused with unsupportedVersion |
