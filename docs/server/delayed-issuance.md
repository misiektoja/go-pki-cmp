# Delayed issuance and confirmation

A CA does not have to decide at once. It can hold a request until an operator approves it or an HSM
queue drains and it can learn whether the client accepted the certificate it issued.

## Waiting for a decision

Implement `server.PendingChecker` and return a `WaitingResponse` from `IssueCertificate`:

```go
func (c *myCA) IssueCertificate(ctx context.Context, reqType server.RequestType,
	tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {

	jobID := c.queue.Add(tmpl, sender)
	return &server.Response{Waiting: &server.WaitingResponse{
		CheckAfter: 30 * time.Second,
		Reason:     "waiting for operator approval",
		PollRef:    jobID,
	}}, nil
}

func (c *myCA) CheckPending(ctx context.Context, pollRef string,
	sender *server.SenderIdentity) (*server.Response, error) {

	switch job := c.queue.Get(pollRef); {
	case job.Pending():
		return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: 30 * time.Second, PollRef: pollRef}}, nil
	case job.Rejected():
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}
	default:
		return &server.Response{Certificate: job.Certificate()}, nil
	}
}
```

The flow follows RFC 9483 section 4.4:

1. The server answers the request with status waiting. `Reason` becomes its statusString.
2. The client polls with `pollReq` after `CheckAfter`.
3. The server calls `CheckPending` with the stored `PollRef`.
4. `CheckPending` returns the certificate, another `WaitingResponse` or a `*server.Error`.

A rejection reaches the client in the `ip`, `cp` or `kup` it would have got at once, with the
request's `certReqId` and ends the transaction. The final response grants implicit confirmation
only when the delayed request asked for it.

### Polling rules

* `pollRep` advertises `CheckAfter` in whole seconds, at least one. A `pollReq` that arrives earlier
  gets another `pollRep` with the time left and does not reach the CA.
* A `pollReq` names the request by its `certReqId` or by -1 for the whole message. A `p10cr` may also
  be polled with 0. Any other value is refused with badRequest.
* A `pollReq` must repeat the senderNonce of the previous response in its recipNonce.
  `WithOptionalPollReqRecipNonce` accepts one without it, which the Insta Certifier clients need.

### Clients that stop polling

A request waits until `CleanupExpired` removes it, 24 hours after its last message by default. Set
the lifetime with `WithWaitingLifetime`. It must exceed the `CheckAfter` you return. A CA that
implements `WaitingExpirer` is told the `PollRef` of each request it loses this way, so it can close
its own record.

How long a request may wait for a decision is your policy: `CheckPending` rejects a request you no
longer want to decide.

The waiting state lives in the server. Replicas share it only through
[snapshots](transactions.md#durable-recovery).

## Confirmation

After an issued certificate, the client sends `certConf` to accept or reject it and the server
answers `pkiConf`. Implement `server.CertificateConfirmer` to hear the outcome:

```go
func (c *myCA) ConfirmCertificate(ctx context.Context, cert *x509.Certificate,
	status server.ConfirmStatus, issueRef any) error {

	switch status {
	case server.ConfirmAccepted, server.ConfirmImplicit:
		return c.store.Publish(issueRef)
	case server.ConfirmRejected, server.ConfirmExpired:
		return c.store.Revoke(issueRef)
	}
	return nil
}
```

| Status | Meaning |
| --- | --- |
| `ConfirmAccepted` | The client accepted the certificate |
| `ConfirmRejected` | The client rejected it or sent a `certConf` without any CertStatus |
| `ConfirmImplicit` | Implicit confirmation was granted, so no `certConf` follows |
| `ConfirmExpired` | No `certConf` arrived before the confirmation wait ended |

`issueRef` is the `Response.IssueRef` you set in `IssueCertificate`, such as a database row ID.

`WithConfirmWaitTime` sets how long the server waits for `certConf`, 10 seconds by default. The
value is sent to the client in the response.

### Rules for certConf

* Every CertStatus must carry the `certHash` and `certReqId` of the issued certificate. All of them
  must accept it or all must reject it. The CA is notified once.
* For a `p10cr` the `certReqId` may be -1 or 0, because RFC 9810 and RFC 9483 disagree and deployed
  peers use both.
* `certConf` must repeat the senderNonce of the certificate response in its recipNonce.
  `WithOptionalCertConfRecipNonce` accepts one without it. A different value is always refused.
* `certConf` must use the credentials of the request, because the transaction is found by them. A
  key update that keeps its key is confirmed with the old certificate.

### Implicit confirmation

`WithImplicitConfirm` grants implicit confirmation in every successful certificate response to a
client that asks for it. The certificate then counts as confirmed and the `certConf` round trip is
skipped. A certificate encrypted for proof by decryption never gets implicit confirmation, because
its `certConf` is the proof. See [Keys that cannot sign](indirect-pop.md).

## Context values

A custom `Handler` built with `server.New` sees polls and confirmations as calls whose context
carries these values. The `CA` callbacks get the same details as arguments.

| Function | Set while the server handles |
| --- | --- |
| `server.PollRefFromContext` | A poll for a delayed request |
| `server.IssueRefFromContext` | A `certConf`, with the `IssueRef` of the certificate |
| `server.IssuedCertFromContext` | A `certConf`, with the certificate being confirmed |
| `server.POPMethodFromContext` | A certificate request and its confirmation, with the proof of possession method |
