# Acting as a registration authority

A registration authority (RA) approves a request of an end entity by forwarding it inside a nested
message that carries the RA's own signature (RFC 9483 section 5.2.2.1). `WithRegistrationAuthority`
makes the client do that for every request it sends:

```go
raCreds, err := pkicmp.NewSignatureCredentials(raKey, raCert, raChain...)
if err != nil {
	log.Fatal(err)
}
c := client.NewClient("https://ca.example.com/.well-known/cmp",
	client.WithTrustedCAs(roots),
	client.WithRegistrationAuthority(raCreds),
)
// creds protect the request itself, as the end entity would.
result, err := c.SendIR(ctx, deviceKey, creds,
	client.WithSenderKID([]byte("device-42")),
	client.WithTemplateSubject(pkix.Name{CommonName: "device-42"}),
)
```

## What is sent

* Every request of an operation goes out in its own nested message: the `ir`, `cr`, `kur`, `p10cr`,
  `rr` or `genm` and then each `pollReq`, `popdecr` and `certConf`.
* The nested message copies the transaction ID, senderNonce and recipNonce of the request inside it.
  Its sender is the subject of the RA certificate. `extraCerts` holds the RA certificate and its
  chain.
* The request inside keeps the protection made with the credentials of the `Send` method. The CA
  verifies both protections.

The CA answers the request, not the nested message, so responses are verified as without the option.
A CA that refuses the RA answers with an error message, which the call returns as a
`*pkicmp.PKIStatusError`, usually with notAuthorized.

RFC 9483 requires the RA to sign, so the option takes `*pkicmp.SignatureCredentials`. RFC 9810
section 4.5 marks an RA certificate with the id-kp-cmcRA extended key usage. Whether a CA requires it
is CA policy.

## Limits

* One request per nested message. Batches of several requests (RFC 9483 section 5.2.2.2) are not
  sent.
* Tested against the server of this module. The OpenSSL 4.1 mock server answers a nested message with
  "unsupported pkibody".

The server side is described in [Registration authorities](../server/registration-authorities.md).
