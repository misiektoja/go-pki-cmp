# Authentication

The server verifies the protection of every message before your code sees it. It has no credential
store of its own. You supply two lookups:

* **`WithSecretLookup`** finds the shared secret of a MAC-protected message.
* **`WithCertificateLookup`** finds the certificate of a signature-protected message.

Without a lookup, messages with that kind of protection are refused: MAC-protected ones with
badMessageCheck and signed ones with signerNotTrusted.

## Shared secrets

```go
type SecretLookup interface {
	LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error)
}
```

RFC 9810 section 5.1.1 covers two cases:

* **Known sender.** The sender field carries the name and `senderKID` should be set. Either or both
  may locate the secret.
* **Unknown sender**, usually a first enrollment. The sender is a NULL-DN and `senderKID` carries the
  reference number of the secret (RFC 4210 section 5.1.3.1).

The reference and the secret work like a user name and a password. Two clients that share a
reference cannot be told apart and one could obtain certificates in the other's name. Enforce unique
references when you provision secrets:

```go
func Register(senderKID, secret []byte) error {
	if exists(senderKID) {
		return errors.New("senderKID already registered")
	}
	store[string(senderKID)] = secret
	return nil
}
```

The server keeps a MAC client's transactions apart from other clients by its `senderKID` and sender
name together. Clients that send only a name, as RFC 4210 allows, do not share transactions or
quotas.

The client chooses the MAC iteration count and the server runs every iteration before it can check
the MAC. `WithMACIterationLimits` bounds that work, 1 to 500000 by default. A request outside the
range is refused with badMessageCheck and the text "MAC protection parameters not accepted" before
any key derivation. Raise the minimum, for example to the 100 that RFC 4211 section 4.4 requires, to
refuse protection too cheap to slow an offline guess of a weak secret.

## Certificates

```go
type CertificateLookup interface {
	LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)
}
```

`issuer` is the recipient in the header, `subject` the sender and `senderKID` the key identifier.
Any of them may be empty. The names are lookup keys only: the server verifies the signature against
the certificate you return, so a client that lies about its name either finds nothing or fails the
signature check. Trust comes from your store and proof of the private key.

Return only certificates you issued or otherwise trust and do not return revoked ones.

## The sender identity

A verified message reaches your code with a `SenderIdentity`:

| Field | Content |
| --- | --- |
| `Certificate` | The signer certificate of a signature-protected message |
| `Sender` | The sender name. For a signed message it equals the certificate subject, so you can authorize on it |
| `SenderKID` | The reference of a MAC-protected message |
| `MACVerified` | True for a MAC-protected message |
| `RA` | The registration authority that forwarded the request, see [Registration authorities](registration-authorities.md) |

For a MAC-protected message the sender name is whatever resolved the secret. Authorize on
`SenderKID` or on the name the secret is registered to.

## Algorithms

A request protected with an algorithm the server does not implement is refused with badAlg. This
includes SHA-1 signatures, which RFC 9481 section 7.1 deprecates. `WithSHA1Signatures` accepts them
from RFC 4210 era devices, in the protection and in the proof of possession.

## Response protection

The server answers a MAC-protected request with a MAC from the same secret and algorithm suite, with
a fresh salt, as RFC 9483 section 3.2 requires. It repeats the client's `senderKID`. Responses to
signed requests and to messages whose protection failed are signed with the `WithSigner` key.
