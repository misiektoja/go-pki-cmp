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
A device that lets the CA generate its key pair uses the methods in
[Keys the CA generates](central-key-generation.md).

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
| `WithTemplateValidity` | Asks for a validity period in the template. The CA decides the validity it grants |
| `WithCertProfile` | Names a certificate profile in the header (RFC 9483 section 3.1) |
| `WithOldCertificate` | The certificate a key update replaces |
| `WithGeneralInfo` | Adds items to `generalInfo` of the header, such as a vendor profile identifier |
| `WithCertReqID` | The `certReqId` of the request, which the CA repeats in its answer. Default 0 |
| `WithPOPHash` | The digest of the signature proof of possession of an RSA or ECDSA key |
| `WithImplicitConfirm` | Asks for implicit confirmation, so that a CA that grants it needs no `certConf` |

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

`WithDeferredPolling` collects the certificate later instead, for example from a job that runs
again the next day. The method returns at the first waiting answer with `EnrollResult.Pending` set.
`PendingEnrollment` encodes to JSON and holds no key or secret, but anyone with it and the
credentials can collect the certificate, so store it like the credentials.

```go
result, err := c.SendIR(ctx, key, creds, client.WithDeferredPolling())
if err == nil && result.Pending != nil {
	state, _ := json.Marshal(result.Pending)
	// Store state and run again later.
}

// Later, possibly in another process, with the same credentials and trust settings:
var pending client.PendingEnrollment
_ = json.Unmarshal(state, &pending)
result, err = c.ResumeEnrollment(ctx, &pending, creds)
if pendingErr, ok := errors.AsType[*client.PendingError](err); ok {
	// The CA still waits. Store pendingErr.Pending and try again later.
}
```

`ResumeEnrollment` waits until `PendingEnrollment.NextPoll`, polls until the CA decides, checks the
certificate and confirms it as the Send* methods do. Under `WithDeferredPolling` it sends one
`pollReq` and returns the next state while the CA still waits. A Send* method without the option
returns a `PendingError` when polling stops at the deadline, at `WithMaxPolls` or when a `pollReq`
gets no answer, and its state resumes the same way. A request that proves possession with `EncryptedCertificate`
is resumed with `ResumeEnrollmentWithIndirectPOP` and its private key.

Always store the state from the latest call. The CA checks that each `pollReq` answers its last
`pollRep`, so an older state is refused with badRecipientNonce. The same happens when a `pollReq`
reached the CA but its answer was lost.

## Confirmation

The method confirms an issued certificate with `certConf` and waits for `pkiConf` before it returns.
`WithImplicitConfirm` adds `implicitConfirm` to the request header (RFC 9810 section 5.1.1.1), which
asks the CA to skip that round trip. A CA that agrees repeats the item in its certificate response.
The method then returns with `EnrollResult.ImplicitConfirm` set and sends nothing more, because the
CA has closed the transaction. A CA that wants the confirmation leaves the item out and the method
confirms as usual. RFC 9483 section 4.1.1 asks an end entity to request implicit confirmation unless
it needs the confirmation.

A grant the request did not ask for is honored as well, as OpenSSL does, since the CA would refuse
a `certConf` for a closed transaction. A certificate the client refuses after a grant is not
reported to the CA, as RFC 9483 section 3.6.1 asks. The option applies to `ir`, `cr`, `kur` and
`p10cr` and is ignored by `SendRR` and the general messages.

## Results and errors

| Error | Meaning |
| --- | --- |
| `*pkicmp.PKIStatusError` | The CA refused the request in a verified response. `pkicmp.HasFailure(err, pkicmp.FailBadPOP)` tests a failure bit |
| `*client.UnverifiedStatusError` | The CA refused in a signed error the client could not verify, usually because no trust anchor is set. Log it, do not act on it |
| `*client.ConfirmationError` | The CA issued a certificate but the `certConf` exchange failed. The error holds the certificate and the key the CA generated for a request for central key generation |
| `*client.PendingError` | Polling stopped while the CA still had the request waiting. `Pending` resumes it with `ResumeEnrollment` |
| `*client.Error` | A transport or verification failure, with the failed step in `Op` |

`pkicmp.HasFailure` never reports bits from an unverified message.

A `ConfirmationError` needs care. The CA may keep the certificate or revoke it as unconfirmed, so
check the CA before retrying, because a retry may issue a second certificate.

The client rejects an issued certificate that does not certify the requested key, does not chain to
the trust anchors or carries the wrong `certReqId`. It reports the rejection to the CA in `certConf`
before it returns the error. It does not compare the subject, because a CA may change it and answer
grantedWithMods.
