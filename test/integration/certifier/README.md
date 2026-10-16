# Insta Certifier client integration tests

Integration tests for the CMP server against two proprietary CMP clients:

* the **Insta Certifier 10 cmpclient**
* the **Insta Certifier 7 ssh-cmpclient**

The clients run in a Docker container and send their requests to a server the test starts on the host. Each test checks what the client saved and what the server reported to the CA. Both clients exit with status 0 when the server rejects a request, so their exit status proves nothing.

Both clients deviate from RFC 4211 and RFC 9483 in places. The tests check that the server defaults refuse those requests and that the matching compatibility option accepts them.

| Client and operation | Server setting needed |
| --- | --- |
| cmpclient `ir`, `cr` and `kur` with a signature proof of possession | `WithPoposkInputVariants` |
| cmpclient `p10cr` and `ir` from a CSR template | none |
| cmpclient `rr` | `WithOptionalRevocationReason` |
| cmpclient `genm` (`--type info`), which sends no items | none |
| ssh-cmpclient `INITIALIZE`, `ENROLL`, `P10CR` and `UPDATE` with a new key | none |
| ssh-cmpclient `UPDATE` without `-P`, which keeps the key and sends no proof of possession | `WithSignatureProtectionPOP` |
| ssh-cmpclient `REVOKE` | not accepted, because it sends pvno 0 |
| cmpclient `ir` that waits for a decision, which it polls for without recipNonce | `WithOptionalPollReqRecipNonce` |
| ssh-cmpclient `POLL` after an `INITIALIZE` that waits for a decision, without recipNonce | `WithOptionalPollReqRecipNonce` |

`WithStrictProfileValidation` refuses MAC-protected requests from ssh-cmpclient and from cmpclient without `--sender`, because their sender is the NULL-DN. It also refuses cmpclient requests that carry poposkInput and a signed ssh-cmpclient `UPDATE`, which leaves the signer certificate out of extraCerts.

## Building the client image

The clients are not distributed with this repository. Put them in a local directory:

```text
bin/cmpclient          Certifier 10 cmpclient
bin/ssh-cmpclient      Certifier 7 ssh-cmpclient, optional
lib/libssl.so.3        OpenSSL from the same installation as ssh-cmpclient
lib/libcrypto.so.3
```

`lib/` must exist even when it is empty. Then build the image:

```bash
make setup-certifier-clients CERTIFIER_CLIENTS_DIR=/path/to/clients
```

The image is named `go-pkicmp-certifier-clients`. Set `CERTIFIER_CLIENT_IMAGE` to build or use another name. Never push it to a public registry.

## Running the tests

```bash
make test-integration-certifier
```

The tests skip when Docker or the image is missing, so `make test-integration` passes without them. The ssh-cmpclient tests skip when the image has no ssh-cmpclient.

The server listens on 127.0.0.1. On Linux the container shares the host network. Elsewhere it reaches the server through `host.docker.internal`.

Both clients are linux/amd64 binaries, so an arm64 host runs them under emulation. There cmpclient can compute wrong PasswordBasedMac values when its Go runtime uses several threads and ssh-cmpclient sometimes crashes before printing anything. The tests therefore run cmpclient with `GOMAXPROCS=1` and retry a crashed client once.
