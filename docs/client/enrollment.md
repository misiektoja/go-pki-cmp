# Enrollment

The `client` package requests certificates with the four CMP enrollment messages. Each call runs the
whole exchange: protection, response verification, polling and certificate confirmation.

| Method | Message | Use |
| --- | --- | --- |
| `SendIR` | `ir` | First certificate of a device, usually with a shared secret |
| `SendCR` | `cr` | Another certificate for a device that already has one |
| `SendKUR` | `kur` | Replace a certificate, signed with the certificate being replaced |
| `SendP10CR` | `p10cr` | Send an existing PKCS #10 CSR |

Keys that cannot sign, such as ML-KEM, use the methods in [Keys that cannot sign](indirect-pop.md).

## Credentials

Every request is protected with a `pkicmp.Credentials`:

* **`pkicmp.NewMACCredentials(secret)`** protects with a shared secret. It uses PBMAC1 by default.
  `pkicmp.WithPBM()` selects PasswordBasedMac and `pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1)`
  selects the SHA-1 suite that RFC 4210 peers expect.
* **`pkicmp.NewSignatureCredentials(key, cert, chain...)`** signs with an existing certificate. The
  chain is sent in `extraCerts` so the CA can verify the certificate. The digest follows the key
  type. `WithHash` on the credentials chooses SHA-1, SHA-256, SHA-384 or SHA-512 for an RSA or ECDSA
  key, for example for a CA that expects one algorithm.

A MAC-protected request names its secret through the sender name or the reference in `senderKID`.
A new device usually has no name yet, so set `client.WithSenderKID` to the reference the CA gave
you.

## Initial enrollment

```go
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

// A bootstrapping device has no trust anchor yet. Add client.WithTrustedCAs when
// one is available, so that a signed rejection can be verified.
c := client.NewClient("http://localhost:8080/cmp")
result, err := c.SendIR(context.Background(), key, creds,
	client.WithSenderKID([]byte("my-device")),
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
)
```

`result.Certificate` is the issued certificate. `result.CAPubs` holds the CA certificates from the
response. The client trusts them to verify the issued certificate only when the response was
MAC-protected, as RFC 9810 section 5.3.2 allows and a device can keep them as its first trust
anchors under the same condition. [Response verification](response-verification.md) explains when
the client needs `WithTrustedCAs`.

## Key update

```go
creds, _ := pkicmp.NewSignatureCredentials(existingKey, existingCert)
c := client.NewClient("http://localhost:8080/cmp", client.WithTrustedCAs(trustedCAs))

result, err := c.SendKUR(context.Background(), newKey, creds)
```

With `SignatureCredentials`, `SendKUR` names `existingCert` in the CRMF `oldCertID` control. The
sender and the template subject repeat its subject with the bytes the certificate encodes, so a CA
that compares names byte by byte finds them unchanged. A certificate with an empty subject is
renewed with a NULL-DN subject and its subjectAltName. `WithOldCertificate` sets the certificate for
custom credential types and `WithSender` and `WithTemplateSubject` override either name.

## Request options

Request options apply to one call:

| Option | Effect |
| --- | --- |
| `WithSender` | Sender name in the header. A signed request otherwise names the subject of its certificate |
| `WithSenderKID` | `senderKID` in every message of the call, the reference of a shared secret |
| `WithTemplateSubject` | Subject in the certificate template |
| `WithTemplateExtension` | Adds an extension to the template, such as subjectAltName |
| `WithCertProfile` | Names a certificate profile in the header (RFC 9483 section 3.1) |
| `WithOldCertificate` | The certificate a key update replaces |
| `WithGeneralInfo` | Adds items to `generalInfo` of the header, such as a vendor profile identifier |
| `WithCertReqID` | The `certReqId` of the request, which the CA repeats in its answer. Default 0 |
| `WithPOPHash` | The digest of the signature proof of possession of an RSA or ECDSA key |

Many CAs route requests on the recipient name and refuse a request without one. Set
`client.WithRecipient` on the client whenever the CA name is known. [Client options](../reference/client-options.md)
lists every client and request option.

## Waiting and polling

A CA that cannot issue at once answers with status waiting. The method then polls with `pollReq`
until the CA decides, sends `certConf` and returns. It waits the `checkAfter` the CA asks for,
clamped by `WithCheckAfterLimits` to between 1 second and 1 hour by default and gives up after
`WithMaxPolls` attempts, 60 by default.

Give every call a context with a deadline. It is the only bound on the whole operation, because the
CA chooses each wait.

## Results and errors

| Error | Meaning |
| --- | --- |
| `*pkicmp.PKIStatusError` | The CA refused the request in a verified response. `pkicmp.HasFailure(err, pkicmp.FailBadPOP)` tests a failure bit |
| `*client.UnverifiedStatusError` | The CA refused in a signed error the client could not verify, usually because no trust anchor is set. Log it, do not act on it |
| `*client.ConfirmationError` | The CA issued a certificate but the `certConf` exchange failed. The error holds the certificate |
| `*client.Error` | A transport or verification failure, with the failed step in `Op` |

`pkicmp.HasFailure` never reports bits from an unverified message.

A `ConfirmationError` needs care. The CA may keep the certificate or revoke it as unconfirmed, so
check the CA before retrying, because a retry may issue a second certificate.

The client rejects an issued certificate that does not certify the requested key, does not chain to
the trust anchors or carries the wrong `certReqId`. It reports the rejection to the CA in `certConf`
before it returns the error. It does not compare the subject, because a CA may change it and answer
grantedWithMods.
