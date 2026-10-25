# Policy and client compatibility

The server authenticates every message, but it does not decide who may request which certificate.
That is the job of the policy middleware you pass to `NewCAServer`. Without a policy, any
authenticated client could request any certificate for any name.

## Lightweight CMP Profile

`server.LightweightPolicy()` enforces the RFC 9483 rules a server needs:

* A CRMF request proves possession of its key.
* A key update is signature-protected.
* A MAC-protected message identifies its secret through the sender name or `senderKID`.
* A certificate template names the entity in its subject or in a requested subjectAltName with a
  NULL-DN subject (RFC 9483 section 4.1.1).
* A request for a CA certificate is refused and BasicConstraints path lengths are validated.
* A revocation request is signature-protected and carries a reasonCode.

Two checks run with or without a policy, because they establish what a request is rather than
whether you grant it: proof of possession and the decoding of BasicConstraints.

## Your own authorization

A middleware wraps a `server.Handler`. Chain yours with `MiddlewareChain`. The first one runs first:

```go
srv := server.NewCAServer(ca,
	server.MiddlewareChain(auditLog(logger), myPolicy(), server.LightweightPolicy()),
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(secrets),
	server.WithCertificateLookup(certs),
)
```

```go
func myPolicy() func(server.Handler) server.Handler {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(
			ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity,
		) (*server.Response, error) {
			if !isAllowed(sender) {
				return nil, &server.Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailNotAuthorized,
					StatusText:  "not authorized",
				}
			}
			return next.HandleCMP(ctx, msg, sender)
		})
	}
}
```

Middleware is also the place for audit logging, metrics and rate limiting.

## Strict profile validation

Some RFC 9483 rules govern how a peer builds a message rather than how the server authenticates it.
Deployed clients break them, so they are off by default. `WithStrictProfileValidation` turns them on:

* A MAC-protected message must name its secret in a directoryName sender.
* A signed request must carry `extraCerts` that lead with the protection certificate and form a
  chain.
* A request must carry a transaction ID and every message a senderNonce of at least 128 bits.
* A `certConf` must hold one CertStatus and must not reuse a senderNonce.
* A signature proof of possession must not carry poposkInput.
* Proof by decryption is allowed only for keys that cannot sign.

It also overrides every option in the table below except `WithSHA1Signatures`. Use it for a conformance test suite or a fleet
known to follow RFC 9483 exactly. The Siemens CMP test suite runs against the server with it.

## Message time

`WithMessageTimeTolerance` refuses a messageTime further than the tolerance from server time with
badTime (RFC 9483 section 3.5). It is off by default because no single tolerance suits every
deployment. A message without messageTime is not refused.

## Options for deployed clients

Each option relaxes one rule for clients that break it. The server still checks everything that
authenticates the request.

| Option | Accepts | Needed by |
| --- | --- | --- |
| `WithOptionalCertConfRecipNonce` | A `certConf` without recipNonce | Clients that leave the field out |
| `WithOptionalPollReqRecipNonce` | A `pollReq` without recipNonce | Insta Certifier 10 cmpclient and Insta Certifier 7 ssh-cmpclient, to collect a delayed result |
| `WithPoposkInputVariants` | A signature proof that carries poposkInput although the template holds subject and key | Insta Certifier 10 cmpclient |
| `WithSignatureProtectionPOP` | A CRMF request without proof whose protection was signed with the requested key | Insta Certifier 7 ssh-cmpclient `UPDATE` that keeps the key |
| `WithOptionalSubject` | A template without the subject field that names the entity in subjectAltName | Clients that leave the field out |
| `WithAnyCertReqID` | An ir, cr or kur with a certReqId other than 0, repeated in the response | RFC 4210 clients that number their requests, tests of the certReqId check of a client |
| `WithOptionalRevocationReason` | A revocation request without reasonCode | Insta Certifier 10 cmpclient `rr` |
| `WithOptionalRevocationIssuer` | A revocation request without an issuer | Clients that name only the serial number |
| `WithMACRevocation` | A MAC-protected revocation request, decided by `RevocationAuthorizer` | Clients that revoke with a shared secret |
| `WithSHA1Signatures` | SHA-1 signatures in protection and proof of possession | RFC 4210 era devices |

[Server options](../reference/server-options.md) describes each option in full and
[Tested implementations](../interoperability/tested-implementations.md) lists which client needs
which option. A refused request names its rule in the status text, and
[Troubleshooting](../operations/troubleshooting.md) maps that text to the option.

## RFC 4210 clients

Clients that implement only RFC 4210 work with the defaults. The server assigns a transaction ID to
a first request without one, accepts a shorter senderNonce and accepts the MAC from a NULL-DN sender
with `senderKID`. The SHA-1 PasswordBasedMac suite such clients often use is accepted and the
response repeats it.
