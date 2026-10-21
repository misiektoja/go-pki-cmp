# Getting started

This page runs the example CA and client from the repository and explains what they exchange.
Every piece of the example maps to a page of the client or server guide, so once it runs you know
what to replace in your own code.

The example CA keeps everything in memory and signs with a throwaway self-signed root. The client
enrolls a key with a shared secret, updates it with a signed request and revokes the result.

## What you need

* Go 1.27.3 or newer, the minimum the module declares
* A clone of the repository
* Port 8080 free on localhost

```bash
git clone https://github.com/misiektoja/go-pki-cmp.git
cd go-pki-cmp
```

## Step 1: start the CA

```bash
go run ./examples/mockserver/cmd
```

```text
INFO CA ready subject="CN=Test CA" serial=240565888259335087214779031597002404039
INFO mockserver listening addr=localhost:8080 path=/cmp
```

The program creates the CA, registers one shared secret under the reference `my-device` and serves
CMP on `http://localhost:8080/cmp`:

```go
--8<-- "examples/mockserver/cmd/main.go"
```

`mockserver.MockCA` implements the CA side: issuance, revocation, the shared secret and certificate
lookups and the support messages. Its source is in
[examples/mockserver](https://github.com/misiektoja/go-pki-cmp/tree/main/examples/mockserver).

## Step 2: run the client

In a second terminal:

```bash
go run ./examples/mockclient/cmd
```

```text
INFO sending IR with MAC protection
INFO enrolled subject="CN=my-device" issuer="CN=Test CA" serial=322200269625980906720798033765771843406
INFO received CA subject="CN=Test CA" issuer="CN=Test CA" serial=240565888259335087214779031597002404039
INFO certificate verified
INFO sending KUR with signature protection
INFO renewed subject="CN=my-device" issuer="CN=Test CA" serial=296525914232565556297304034835094423049
INFO certificate verified
INFO sending RR with signature protection
INFO certificate revoked serial=296525914232565556297304034835094423049
```

The client runs three operations in turn:

```go
--8<-- "examples/mockclient/cmd/main.go"
```

## What happens behind the scenes

1. **Initial enrollment.** The client sends an `ir` protected with a MAC derived from the shared
   secret. `senderKID` carries `my-device`, so the server finds the secret through `LookupSecret`.
   The server verifies the MAC and the proof of possession, builds a certificate template from the
   request and calls `IssueCertificate`. The `ip` carries the certificate and the CA certificate in
   `caPubs`. The client confirms the certificate with `certConf` and the server answers `pkiConf`.
2. **Key update.** The client signs a `kur` with the certificate from step 1. The server finds that
   certificate through `LookupCertificate`, verifies the signature and issues a certificate for the
   new key. The client verifies the signed `kup` against the CA certificate it received in step 1.
3. **Revocation.** The client sends an `rr` signed with the certificate it revokes. The server checks
   that the signer is that certificate and calls `RevokeCertificate`. The `rp` reports acceptance.

The server log shows each lookup, issuance, confirmation and revocation.

## Use the library in your own module

```bash
go get github.com/misiektoja/go-pki-cmp
```

Each piece of the example has a production replacement:

| Example piece | What replaces it |
| --- | --- |
| The `secrets` map of `MockCA` | A `SecretLookup` over your device registry with unique references, see [Authentication](server/authentication.md) |
| The in-memory self-signed CA | Your CA behind `CA.IssueCertificate` and a `crypto.Signer` such as an HSM key in `WithSigner`, see [Implementing a CA](server/ca.md) |
| `LightweightPolicy` alone | A `MiddlewareChain` with your authorization policy in front of it, see [Policy and client compatibility](server/policy.md) |
| The `CleanupExpired` ticker | Keep it. Add snapshots when the server must survive a restart, see [Transactions and recovery](server/transactions.md) |
| A client without a trust anchor | `client.WithTrustedCAs` wherever an anchor is known, see [Response verification](client/response-verification.md) |

## Next steps

For a client:

1. [Enrollment](client/enrollment.md) - the request types, credentials and request options
2. [Response verification](client/response-verification.md) - trust anchors and the CAs that need extra options
3. [Revocation](client/revocation.md) and [Support messages](client/support-messages.md)

For a server:

1. [Implementing a CA](server/ca.md) - the `CA` interface and what the template carries
2. [Authentication](server/authentication.md) - shared secret and certificate lookups
3. [Policy and client compatibility](server/policy.md) - authorization and the options deployed clients need
4. [Transactions and recovery](server/transactions.md) - limits, cleanup and snapshots
