# Messages and protection

The `pkicmp` package is the base of the module. It defines the CMP and CRMF types, builds and parses
messages and applies and verifies their protection. The `client` and `server` packages build on it.
Use it directly for custom tooling, a registration authority proxy or tests.

## Building a message

`PKIMessage` corresponds to the ASN.1 PKIMessage. Create one from a body and header options:

```go
body := pkicmp.NewPKIConfBody()
msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
	Sender:     sender,
	Recipient:  recipient,
	RecipNonce: previous.Header.SenderNonce,
})
```

The transaction ID and senderNonce default to 128 random bits (RFC 9810 section 5.1.1) and
messageTime to the current time. Body constructors such as `NewIRBody`, `NewIPBody` and
`NewGenMBody` wrap each CHOICE variant. `PKIBody` keeps the raw DER and decodes it only when a typed
getter such as `PKIBody.IR` is called.

`PKIMessage.MarshalBinary` and `pkicmp.ParsePKIMessage` are the only points where messages become
bytes and back.

## Protection

`Credentials` applies protection:

```go
creds, err := pkicmp.NewMACCredentials([]byte("shared-secret"))
if err != nil {
	return err
}
if err := creds.Protect(msg); err != nil {
	return err
}
```

| Credentials | Protection |
| --- | --- |
| `NewMACCredentials` | PBMAC1 by default, the algorithm RFC 9481 section 7 recommends. `WithPBM` selects PasswordBasedMac and `WithPBMAlgorithms` its hash functions |
| `NewSignatureCredentials` | A signature with an X.509 certificate and key. The chain is sent in `extraCerts`. The digest follows the key type unless `WithHash` chooses one |

To answer a MAC-protected message with the same algorithm suite, as RFC 9483 section 3.2 requires,
pass `VerifyResult.ProtectionParams` from the verified request to `NewMACCredentials`. It reuses the
suite with a fresh salt.

## Verification

`PKIMessage.Verify` checks the protection:

```go
result, err := msg.Verify(pkicmp.VerifyOptions{
	SharedSecret:       []byte("shared-secret"),
	TrustPool:          trustedCAs,
	RequiredProtection: pkicmp.ProtectionSignature,
})
```

With both a secret and a trust pool, the message decides which is used. Set `RequiredProtection` to
pin one mechanism, as RFC 9483 section 3.1 asks within one operation. The zero value accepts either.

A signature check also binds the protection certificate to the sender: when the header sender is a
directory name, it must equal the certificate subject (RFC 9483 section 3.5). A NULL-DN sender is
accepted on the trust chain alone.

| Option | Effect |
| --- | --- |
| `ExtraCerts`, `TrustedCert` | Candidate signer certificates beyond those the message carries |
| `SenderKID`, `AllowSenderKIDMismatch` | Select candidates by subject key identifier or try all of them |
| `CurrentTime` | Validate the certificates at another time, such as when a recorded message arrived |
| `AllowSHA1Signatures` | Accept SHA-1 signatures, refused by default |
| `MinMACIterationCount`, `MaxMACIterationCount` | Bound the MAC iteration count, 1 to 500000 by default |
| `RequireDigitalSignatureKeyUsage` | Require the digitalSignature bit that RFC 9483 section 3.5 asks for. Deployed CAs often lack it |

Do not take `CurrentTime` from the message when the result decides whether to act on it, because
the sender sets its messageTime.

## Errors

Every error is typed and carries an `InvalidReason`:

| Type | Meaning |
| --- | --- |
| `ParseError` | Malformed message, missing field or a parameter outside the accepted range. When the failure comes after a readable header, its `Header` field holds that header, so a server can answer with an error message |
| `ProtectionError` | Protection could not be applied |
| `VerificationError` | Bad MAC or signature, wrong mechanism, sender mismatch or no certificate to verify with |

Common verification reasons:

| Reason | Cause |
| --- | --- |
| `ReasonBadMAC` | The MAC does not match the shared secret |
| `ReasonUnexpectedProtection` | The message used another mechanism than `RequiredProtection` |
| `ReasonSenderMismatch` | No candidate certificate has the sender's name |
| `ReasonUntrustedSigner` | No candidate with the sender's name chains to the trust pool |
| `ReasonNoCandidateSigner` | No certificate was available to verify the signature |
| `ReasonSenderKIDMismatch` | The senderKID names none of the candidate certificates |
| `ReasonUnsupportedAlgorithm` | The algorithm is unknown or disabled, such as SHA-1 |

`PKIStatusInfo.AsError` turns a peer status into a `*pkicmp.PKIStatusError`, and
`pkicmp.HasFailure(err, bit)` tests its failure bits.

## Your responsibilities

The package verifies protection and parses CMP. It does not implement a client or CA policy. When
you use it directly:

* **Pin the mechanism** you expect on the message you verify, which is not always the one you send
  with. Holding both kinds of trust material under the default lets a peer pick the weaker one.
* **Keep the protection certificate** across a transaction. `extraCerts` may appear only on the
  first response, so pass `VerifyResult.ProtectionCertificate` back through `ExtraCerts` or
  `TrustedCert`.
* **Bind the issued certificate** to the request by comparing its public key with the key you asked
  for. Subjects may differ under grantedWithMods.
* **Trust caPubs** only when `VerifyResult.MACVerified` is set (RFC 9810 section 5.3.2).
* **Clamp checkAfter** yourself. `PollRepContent` holds the peer's value as sent.
* **Sanitize peer text** before logging. `PKIStatusInfo.AsError` joins the free text without
  validating UTF-8 or removing control characters.

## Certificate confirmation

`pkicmp.NewCertStatus` computes the certificate hash for a manual `certConf`, including the explicit
hash identifier that ML-DSA and composite ML-DSA certificates need.
