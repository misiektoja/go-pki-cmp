# Keys that cannot sign

By default only a signature proves possession of a key, so the server refuses a CRMF request for a
key that cannot sign, such as ML-KEM. Two options accept proof by decryption (RFC 9810 section
5.2.8.3) for RSA, elliptic curve (ECDH) and ML-KEM keys:

| Option | Method | When possession is proven |
| --- | --- | --- |
| `WithEncryptedCertificatePOP` | The server returns the certificate encrypted for the requested key. The client proves possession by sending `certConf` with the hash of the decrypted certificate | After the certificate is issued |
| `WithChallengeResponsePOP` | The server first sends a `popdecc` with a random number encrypted for the key. A `popdecr` with that number continues the request | Before the request reaches your CA |

Both are off by default. A key the server cannot encrypt for, such as X25519, is refused with badAlg.
`server.POPMethodFromContext` tells your CA which method a request used.

## Encrypted certificate

The certificate exists before the client has proved anything, so treat it as undelivered until a
matching `certConf` arrives:

* Publish the certificate only after `ConfirmAccepted`.
* Revoke it on `ConfirmExpired` or `ConfirmRejected` (RFC 9810 sections 5.2.8.3.2 and 8.11).

Such a request never gets implicit confirmation. A `certConf` with the wrong hash is refused with
badPOP and leaves the transaction open until a matching one arrives or the confirmation wait ends.
Implement `CertificateConfirmer` to hear the outcome, see
[Delayed issuance and confirmation](delayed-issuance.md#confirmation).

## Challenge-response

A wrong answer ends the transaction with badPOP and the certificate is never created. The challenge
waits for its answer as long as an issued certificate waits for `certConf`, see
`WithConfirmWaitTime`. Your CA sees the request only after the right answer, as if it had just
arrived.

## Certifying an ML-KEM key

crypto/x509 cannot certify an ML-KEM key, so the CA needs another way to sign such a certificate.
The template carries the key as `*mlkem.EncapsulationKey768` or `*mlkem.EncapsulationKey1024`.
`pkicmp.MarshalPublicKey` encodes its SubjectPublicKeyInfo (RFC 9935), whose only allowed key usage
is keyEncipherment.

## Response format

The encrypted certificate travels in CMS EnvelopedData, which is CMP version 3 syntax, so the response
is version 3. One case differs:

| Request | Response |
| --- | --- |
| Version 3, any key | EnvelopedData in a version 3 response |
| Version 2, ML-KEM or elliptic curve key | EnvelopedData in a version 3 response |
| Version 2, RSA key | EncryptedValue in a version 2 response |
| Version 2, RSA key, with `WithEnvelopedDataForVersion2` | EnvelopedData in a version 3 response |

Version 2 RSA requests get the older EncryptedValue because OpenSSL 3.0 and 3.2 clients cannot read
EnvelopedData. Other keys have no EncryptedValue form.

A Bouncy Castle client built on its `CertificateResponse` class reads only EnvelopedData. It must
send version 3 for an RSA key, as RFC 9810 section 7 asks of a client that expects version 3
syntax. Set `WithEnvelopedDataForVersion2` when your version 2 clients read only EnvelopedData. OpenSSL
3.0 and 3.2 clients then cannot read the certificate.

## Profile restrictions

RFC 9483 section 4.1.1 requires a signature proof for a key that can sign. Under
`WithStrictProfileValidation` only an ML-KEM key may use either method.
