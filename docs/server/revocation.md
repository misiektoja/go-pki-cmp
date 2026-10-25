# Revocation

Implement `server.Revoker` to accept revocation requests (RFC 9483 section 4.2). Without it the
server refuses every `rr` with badRequest.

```go
func (c *myCA) RevokeCertificate(ctx context.Context, req *server.RevocationRequest,
	sender *server.SenderIdentity) error {

	cert := c.store.Find(req.Issuer, req.SerialNumber)
	if err := req.Match(cert); err != nil {
		return err // badCertId
	}
	if c.store.IsRevoked(cert) {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailCertRevoked}
	}
	return c.store.Revoke(cert, req.Reason)
}
```

The CA must find the certificate itself and report, as RFC 9483 section 5.1.3 asks:

* **badCertId** when it did not issue the certificate. `RevocationRequest.Match` also checks the
  optional template fields against the certificate found.
* **certRevoked** when the certificate is already revoked.

A nil error reports the revocation as accepted in the `rp`. `pkicmp.CRLReasonRemoveFromCRL` asks to
release a certificate from hold.

`RevocationRequest.InvalidityDate` is the invalidityDate the request asks for (RFC 5280 section
5.3.2), the time at which the key was compromised or the certificate otherwise became invalid, for
the CA to publish in the CRL entry. It is zero when the request carries none. A request whose
invalidityDate is not a GeneralizedTime is refused with badDataFormat and one that carries two with
badRequest. `Extensions` holds every requested CRL entry extension for the CA to read.

## Who may revoke

The server authorizes the request before it calls `RevokeCertificate`. By default only the
certificate being revoked may sign the request, as RFC 9483 section 4.2 requires. A request signed by
anyone else, such as a registration authority (RFC 9483 section 5.3.2), is refused with notAuthorized
unless the CA implements `server.RevocationAuthorizer` and approves it:

```go
func (c *myCA) AuthorizeRevocation(ctx context.Context, req *server.RevocationRequest,
	sender *server.SenderIdentity) error {

	if sender.Certificate != nil && c.isRA(sender.Certificate) {
		return nil
	}
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}
}
```

`LightweightPolicy` refuses MAC-protected revocation requests with wrongIntegrity.
`WithMACRevocation` passes them on and they always go to `RevocationAuthorizer`. A shared secret
proves who holds the secret, not who holds the certificate, so decide which certificates that secret
may revoke, for example only those it enrolled.

## Missing fields

| Option | Accepts |
| --- | --- |
| `WithOptionalRevocationReason` | A request without reasonCode. It reaches the CA with reason unspecified, which RFC 5280 treats the same way |
| `WithOptionalRevocationIssuer` | A request that names only a serial number. A request signed with that certificate revokes the signer's own certificate and the server fills in the issuer. Any other request reaches `RevocationAuthorizer` with an empty `RawIssuer` and the CA must refuse it when several issuers use that serial number |

## Delayed revocation

`RevokeCertificate` or `AuthorizeRevocation` can return a `*server.WaitingError` when the decision has
to wait, for example for an operator. The client gets an error message with status waiting and polls
with `certReqId` -1. Each poll reaches `PendingChecker.CheckPending` with the `PollRef`. A nil
`Response` from `CheckPending` means the revocation is done and the client receives the `rp`. See
[Delayed issuance and confirmation](delayed-issuance.md).
