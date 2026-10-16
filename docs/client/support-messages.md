# Support messages

General messages ask the CA for information rather than a certificate (RFC 9483 section 4.3):

| Method | Returns |
| --- | --- |
| `GetCACertificates` | Intermediate and issuing CA certificates |
| `GetRootCAUpdate` | A new root certificate, certified by the current one |
| `GetCertReqTemplate` | The template a request should follow, for the profile named with `WithCertProfile` |
| `GetCRLUpdate` | A CRL newer than the one the caller holds |
| `GetCurrentCRL` | The current CRL |
| `SendGenM` | The raw items of any other info type |

```go
update, err := c.GetRootCAUpdate(context.Background(), currentRoot, creds)
switch {
case errors.Is(err, client.ErrInfoTypeNotSupported):
	// The CA does not offer root updates. RFC 4210 CAs often ignore the request.
case err != nil:
	return err
case update != nil:
	// update.NewWithNew is the new root. The client has checked that currentRoot
	// signed update.NewWithOld.
}
```

The other methods follow the same pattern.

## Results

* A **nil result with a nil error** means the CA has nothing to send, such as no newer root or CRL
  and no template requirements.
* **`client.ErrInfoTypeNotSupported`** covers both a CA that lists the type as unsupported and one
  that leaves it out of its answer. Nokia NCM leaves every type out.
* A CA that refuses general messages altogether answers with an error message, returned as
  `*pkicmp.PKIStatusError`. EJBCA Community Edition does this with badRequest.

## What to verify yourself

The response is verified like any other, so its content is as trustworthy as its protection:

* Validate CA certificates against a trust anchor before you use them to build chains.
* Verify a CRL signature against its issuer before you use it. `GetCRLUpdate` only refuses a CRL
  that is not newer than the one you hold, which would roll you back.
* A root update is returned only if the current root signed the new one.
