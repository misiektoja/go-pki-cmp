# Registration authorities

A registration authority (RA) can approve a request by forwarding it unchanged inside a nested
message that carries the RA's own protection (RFC 9483 section 5.2.2.1). Accept such messages with
`WithRAAuthorizer`:

```go
server.WithRAAuthorizer(server.RAAuthorizerFunc(func(ctx context.Context,
	ra *server.SenderIdentity, req *pkicmp.PKIMessage, sender *server.SenderIdentity) error {

	if ra.Certificate == nil || !ra.Certificate.Equal(raCert) {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}
	}
	return nil
}))
```

Without an authorizer, nested messages are refused with badRequest.

## How a forwarded request is handled

1. The server verifies the protection of the nested message with `SecretLookup` or
   `CertificateLookup`.
2. It verifies the protection of the forwarded request the same way.
3. It calls the authorizer with both identities.
4. It handles the request as if the end entity had sent it directly. `SenderIdentity.RA` tells your
   CA which RA approved it.

The response is protected for the end entity, uses its protocol version and is not wrapped in a
nested message. Problems with the nested message itself, including a refusal by the authorizer, are
reported to the RA in an error message.

The authorizer runs for every forwarded message, including `certConf` and `pollReq`.

## Identify the RA

A verified protection proves only who sent a message. Every end entity with a certificate or shared
secret can produce a valid nested message, so the authorizer must identify the RA itself, for example
by comparing `ra.Certificate` with the RA certificates you trust.

RFC 9483 requires the RA to sign the nested message, while RFC 4210 also allows a MAC.
`ra.MACVerified` reports a MAC. Refuse it with wrongIntegrity to follow the Lightweight CMP Profile.
The example above refuses a MAC, because `ra.Certificate` is nil for one.

## Rules

* The nested message must copy the transaction ID and senderNonce of the request it wraps.
* One nested message carries one request. Batches of several messages (RFC 9483 section 5.2.2.2) are
  refused with badRequest.

A go-pki-cmp client acts as the RA with `client.WithRegistrationAuthority`, see
[Acting as a registration authority](../client/registration-authority.md).

An RA that revokes on behalf of end entities signs the `rr` with its own certificate. That is handled
by `RevocationAuthorizer`, see [Revocation](revocation.md#who-may-revoke).
