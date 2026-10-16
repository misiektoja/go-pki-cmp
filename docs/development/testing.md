# Testing

The library is tested at three levels: unit tests in each package, fuzz targets over the message
parser and protection checks and integration tests against independent CMP implementations.

## Unit tests

```bash
make test
```

Runs `go vet` and every unit test under the race detector. The `server` tests drive complete flows
through the handler, including delayed issuance, confirmation, revocation, nested messages, snapshots
and the compatibility options. The `client` tests run against an in-process server. The unit tests
have no external dependencies.

## Fuzzing

```bash
make fuzz
make fuzz FUZZTIME=10m
```

Fuzzes whole-message parsing, MAC protection parameters and signature verification in `pkicmp`, each
for `FUZZTIME`. CI runs 30 seconds per target. Go writes a failing input under `pkicmp/testdata/fuzz`.
Commit that input with the fix so it stays a regression test.

Minimization is off by default, because a worker still minimizing when `FUZZTIME` expires makes Go
report the run as failed. Set `FUZZMINIMIZETIME` to a duration such as `1m` to minimize a crashing
input.

## Integration tests

The integration tests need Docker, OpenSSL 3.2 or newer, Git and `uv`:

```bash
make setup             # start the EJBCA container and clone the CMP test suite
make test-integration  # run every integration test
make teardown          # stop and remove the EJBCA container
```

| Target | Peer | Needs |
| --- | --- | --- |
| `make test-integration-ejbca` | EJBCA as the CA for the client | `make setup-ejbca` |
| `make test-integration-openssl` | OpenSSL `cmp` and `cms` in both directions | OpenSSL 3.2 or newer on the path |
| `make test-integration-cmp-test-suite` | The Siemens CMP test suite against the server | `make setup-cmp-test-suite` |
| `make test-integration-ncm` | A Nokia NCM instance | The `NCM_CMP_*` variables |
| `make test-integration-certifier` | The Insta Certifier 10 cmpclient and the Insta Certifier 7 ssh-cmpclient against the server | A local client image |

Some OpenSSL cases need a newer release and skip on older ones:

* The certificate request template test against the OpenSSL mock server needs OpenSSL 4.0, because
  the OpenSSL 3 server crashes on that request.
* The ML-KEM cases of the CMS and proof of possession tests need OpenSSL 4.0, the first release with
  ML-KEM in CMS.
* The elliptic curve case of the encrypted certificate test needs OpenSSL 3.5, because earlier
  releases cannot read a certificate in EnvelopedData.

CI runs the OpenSSL tests with 3.5 and 4.0.

### Nokia NCM

The NCM tests need the endpoint and credentials in `NCM_CMP_*` variables and skip without them.
[test/integration/ncm/README.md](https://github.com/misiektoja/go-pki-cmp/blob/main/test/integration/ncm/README.md)
lists the variables and the profile the tests expect. CI runs them for pushes to `dev` and `main` and
once a week when the repository has the NCM secrets.

### Insta Certifier clients

The clients are proprietary, so the tests need an image built from your own copies and skip without
it. CI does not run them.
[test/integration/certifier/README.md](https://github.com/misiektoja/go-pki-cmp/blob/main/test/integration/certifier/README.md)
describes the image. Never push it to a public registry.

## Testing your integration

| Your code | Verify with |
| --- | --- |
| A CA behind `server.NewCAServer` | The client package against an `httptest.Server`, as the example tests do |
| Compatibility options | The real clients you support. [Tested implementations](../interoperability/tested-implementations.md) lists the known needs |
| Snapshot and restore | A test that restores into a fresh server and completes an open transaction |
| A client against your CA | A staging CA with the same profile as production |
