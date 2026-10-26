# Known limitations

Behavior to plan around in the current release. Each item states what is missing and what it means
for your application.

## Protocol scope

### Some CMP operations are not implemented

Key recovery, cross-certification and announcements are not implemented.
Requests for them are refused with badRequest and the text "message type not supported".

### One request per nested message

A registration authority may forward one request per nested message. Batches (RFC 9483 section
5.2.2.2) are refused with badRequest. The client does not send nested messages.

### Central key generation needs a key that can decrypt

A centrally generated private key is encrypted for the requester. A signature-protected request
needs an RSA or ECDSA P-256, P-384 or P-521 protection key. Other keys, such as Ed25519 or ML-DSA, can
receive a generated key only through a MAC-protected request. The CMP version 2 EncryptedValue form
of the private key is not supported.

### ML-KEM-512 and older Dilithium encodings

ML-KEM-512 keys are refused because the Go standard library does not implement them. Only the final
ML-DSA encodings are supported, not the older Dilithium ones.

### Composite ML-DSA and SLH-DSA chains

crypto/x509 cannot check composite ML-DSA or SLH-DSA signatures, so the library verifies such paths
itself. A certificate signed with a composite or SLH-DSA key is accepted only when its issuer
certificate travels in the message, in `extraCerts` or `caPubs`, even if that issuer is a trust anchor. No certificate in such a
path may carry name constraints.

### SLH-DSA CAs sign slowly

An SLH-DSA CA key signs every issued certificate and, as the `WithSigner` key, every protected
response. The small parameter sets, whose names end in `s`, can take hundreds of milliseconds or more
per signature. An enrollment with explicit confirmation needs at least two signatures. A separate
classical or ML-DSA signer certificate in `WithSigner` keeps the responses fast.

### Proof by decryption needs a capable CA

The client can enroll a key that cannot sign only at a CA that supports the encrypted certificate or
challenge-response method. RFC 9483 lets a CA refuse both for keys that can sign. X25519 keys are
refused by the server.

## Server

### State lives in memory

Transactions, waiting requests and challenges live in the `Server`. Replicas share them only through
`SnapshotTransactions` and `RestoreTransactions`, which your application must call while it excludes
concurrent requests. See [Transactions and recovery](server/transactions.md).

### No response cache

A client that retries an exact request after a lost response starts a new operation, which may issue
a second certificate. Keep a response cache when that matters.

### Subjects lose attributes without WithRawSubject

The template subject is rebuilt from `pkix.Name`, which drops types such as domainComponent and
emailAddress and may reorder the rest. `WithRawSubject` keeps the requested encoding.

### crypto/x509 cannot certify every key

Composite ML-DSA keys need `compositex509.CreateCertificate`. ML-KEM and SLH-DSA subject keys need
a signer outside crypto/x509, and so does a CA whose own key is SLH-DSA.

### No built-in rate limits

The server caps transactions in total and per credential. Other limits belong in your middleware.

## Client

### No sender for nested messages

A client cannot act as a registration authority and wrap requests in nested messages.

### Polling time is chosen by the CA

The client waits as long as the CA asks, within `WithCheckAfterLimits`, up to `WithMaxPolls` times.
Only a context deadline bounds the whole operation. `WithDeferredPolling` returns at the first
waiting answer, so that `ResumeEnrollment` can collect the certificate later.

## Operational limits

| Limit | Default | Setting |
| --- | --- | --- |
| Request body at the server | 1 MiB | `server.MaxRequestBodySize` |
| Response body at the client | 10 MiB | `client.WithMaxResponseBytes` |
| Concurrent transactions | 10000 | `server.WithMaxTransactions` |
| Transactions per credential | 100 | `server.WithMaxTransactionsPerCredential` |
| Confirmation wait | 10 seconds | `server.WithConfirmWaitTime` |
| Waiting request lifetime | 24 hours | `server.WithWaitingLifetime` |
| MAC iteration count | 1 to 500000 | `WithMACIterationLimits` in either package |
| Poll attempts | 60 | `client.WithMaxPolls` |
| Wait between polls | 1 second to 1 hour | `client.WithCheckAfterLimits` |
| Snapshot size | 64 MiB | Fixed |
