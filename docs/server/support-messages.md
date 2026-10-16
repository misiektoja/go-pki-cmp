# Support messages

RFC 9483 section 4.3 defines general messages that ask the CA for information. Implement the matching
provider to answer each one:

| Interface | Request | RFC |
| --- | --- | --- |
| `CACertificatesProvider` | Intermediate and issuing CA certificates | RFC 9483 section 4.3.1 |
| `RootCAUpdateProvider` | An update of the root CA certificate | RFC 9483 section 4.3.2 |
| `CertReqTemplateProvider` | A certificate request template, per certificate profile | RFC 9483 section 4.3.3 |
| `CRLProvider` | A CRL update or the current CRL | RFC 9483 section 4.3.4, RFC 9810 section 5.3.19.6 |

The server answers a `genm` with a `genp` and lists every requested type without a provider in an
unsupportedOIDs item (RFC 9810 section 5.3.19.7). The client then knows that the CA does not offer
the type, rather than reading an absent value as "no update".

```go
func (c *myCA) LatestCRL(ctx context.Context, source pkicmp.CRLSource,
	sender *server.SenderIdentity) (*x509.RevocationList, error) {

	// A zero source asks for the current CRL of the CA's choice.
	if !source.IsZero() && !slices.ContainsFunc(source.DirectoryNames(), c.issues) {
		return nil, nil // no CRL from this source
	}
	return c.store.LatestCRL()
}
```

Return nil when the CA has nothing to send. The response then carries an absent value.

## Rules the server enforces

* A root CA update must carry newWithOld, the new root certified by the old one. The server checks
  it with `pkicmp.RootCAKeyUpdate.Verify` before sending it and answers systemFailure when it fails.
* A CRL update is sent only when the CRL is newer than the thisUpdate the client reported.
* A general message completes its transaction at once and is never delayed. A custom `Handler`
  answers with `Response.GeneralResponse` and gets systemFailure if it returns a `WaitingResponse`.
* `WithStrictProfileValidation` requires one item per request and an absent value where RFC 9483
  defines none.

The [example CA](https://github.com/misiektoja/go-pki-cmp/blob/main/examples/mockserver/support.go)
implements every provider. Its root never changes, so it reports no root CA update.
