# Transactions and recovery

The server tracks multi-message exchanges such as `ir`, `ip`, `certConf` and `pkiConf` and the
polling flows. This page covers the limits, the cleanup and moving the state to durable storage.

## Transaction identity

Transactions are keyed by the sender's verified credential and the transaction ID, so one client
cannot continue another client's transaction (RFC 9810 section 5.1.1). A client may leave the
transaction ID out of its first request. The server then assigns a random 128-bit one and returns it,
as RFC 4210 and RFC 9810 require. `WithStrictProfileValidation` refuses such requests instead.

## Limits

| Option | Default | Effect |
| --- | --- | --- |
| `WithMaxTransactions` | 10000 | Concurrent transactions in the server |
| `WithMaxTransactionsPerCredential` | 100 | Concurrent transactions per client credential |
| `WithConfirmWaitTime` | 10 seconds | How long an issued certificate or a challenge waits for its answer |
| `WithWaitingLifetime` | 24 hours | How long a waiting request stays after the client's last poll |
| `server.MaxRequestBodySize` | 1 MiB | Largest accepted request body |

A new request beyond a transaction limit is refused with systemUnavail. A first message that reuses
the transaction ID of a transaction the server still holds is refused with transactionIdInUse, also
when the limits are full.

## Cleanup

Call `CleanupExpired` periodically. It removes completed and stale transactions, tells
`CertificateConfirmer` about certificates that were never confirmed and tells `WaitingExpirer` about
requests whose client stopped polling:

```go
go func() {
	for range time.Tick(time.Minute) {
		srv.CleanupExpired()
	}
}()
```

Entries expire by last activity: `WithConfirmWaitTime` for most, `WithWaitingLifetime` for waiting
requests.

## Durable recovery

`SnapshotTransactions` saves the active, waiting, issued and completed protocol state.
`RestoreTransactions` loads it into a fresh server with the same response-signing certificate before
that server accepts requests. Original nonces, credential binding, timestamps and MAC parameters
survive.

The host must:

* Exclude concurrent `ServeHTTP`, `CleanupExpired`, snapshot and restore calls.
* Persist a successful response and its snapshot before sending that response to the peer.
* Commit issuance records and credential usage in the same durable operation.
* Keep a response cache when exact request retries must not issue another certificate or reuse a
  completed transaction ID. The library provides neither database transactions nor a response cache.

Treat snapshots as trusted private server data, never as client input. They have a versioned format
and contain no secrets or signing keys, unless your `IssueRef` holds them. `IssueRef` must be JSON
serializable. Pass a decoder to `RestoreTransactions` when its original Go type matters. A nil
decoder uses the standard encoding/json value types.

Restore refuses a different signer, invalid state and capacity overruns without replacing existing
state. Snapshots are limited to 64 MiB. Expiration timestamps are preserved, so keep calling
`CleanupExpired` after a restore.

## Several replicas

The state lives in one process. Replicas behind one endpoint share it only through snapshots, so
either route every message of a transaction to the same replica or restore the state before a replica
serves the next message.
