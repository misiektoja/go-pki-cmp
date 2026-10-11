# Contributing

go-pki-cmp is a Go library for the Certificate Management Protocol (CMP). Bug reports, interoperability results and code contributions are welcome. Usage questions go through the question issue form, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another CMP implementation without checking its license and naming the source in the pull request. The project derives from [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp), as [NOTICE](NOTICE) records.

Never commit shared secrets, private keys, full CSRs, CMP messages captured from a production system or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test, fuzz, integration and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make fuzz
```

`make test` runs `go vet` and the unit tests under the race detector, because the documented server deployment sweeps expired transactions from a background goroutine while serving requests. The unit tests have no external dependencies. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`, and also lints the integration tests.

Every parser in `pkicmp` consumes bytes chosen by a peer, and message protection is verified before anything establishes who that peer is. The fuzz targets cover whole-message parsing, MAC protection parameters and signature verification. `make fuzz` runs each for 30 seconds, as CI does. Use `make fuzz FUZZTIME=10m` for a longer local run and set `FUZZMINIMIZETIME` to minimize a crashing input.

Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and `make gitleaks` before pushing. `make help` lists every target.

## Integration tests

The integration tests run the library against independent CMP implementations: the client against EJBCA and OpenSSL, and the server against OpenSSL and the Siemens CMP test suite.

> [!IMPORTANT]
> **Prerequisites**: Docker, OpenSSL 3.2 or newer, Git and `uv`.

```bash
make setup             # Start the EJBCA container and clone the CMP test suite
make test-integration  # Run every integration test
make teardown          # Stop and remove the EJBCA container
```

`make test-integration-ncm` runs the client against a Nokia NCM instance. It needs the endpoint and credentials in `NCM_CMP_*` variables and skips without them. [test/integration/ncm/README.md](test/integration/ncm/README.md) lists the variables. CI runs these tests for pushes to `dev` and `main` and once a week when the repository has the NCM secrets.

`make test-integration-certifier` runs the server against the Insta Certifier 10 cmpclient and the Nokia ssh-cmpclient. The clients are proprietary, so the tests need a local image built from your own copies and skip without it. CI does not run them. [test/integration/certifier/README.md](test/integration/certifier/README.md) describes the image.

Protocol changes need negative tests and an RFC citation. A change must keep working against real CMP peers and against clients that implement only RFC 4210. Interoperability claims need sanitized evidence naming the peer and its version. User-facing behavior changes update the Go doc comments and the README.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning. [RELEASE_NOTES.md](RELEASE_NOTES.md) describes every change that affects callers, including any that needs a code change.

## Releasing

A release is started by pushing a version tag that is reachable from `main` and by nothing else.

Release headings use `## vX.Y.Z - D Mon YYYY`, for example `## v0.4.0 - 11 Oct 2026`. Use an unpadded day and an abbreviated English month. Keep `TBD` until the release date is set.

1. Set the release date in `RELEASE_NOTES.md` and merge `dev` into `main`.
2. Run `make release-check VERSION=vX.Y.Z` on `main`. It builds, vets and tests an export of the tree, imports it from a separate module and checks the release notes heading.
3. Tag the release commit on `main` and push the tag with `git push origin vX.Y.Z`.
4. The Release workflow repeats the check and creates a draft release. The draft carries the release notes section, complete source archives, a CycloneDX SBOM, SHA-256 checksums and a signed build provenance bundle.
5. Review the draft and publish it.

Consumers can check that an artifact was built by the workflow with `gh attestation verify <file> --repo misiektoja/go-pki-cmp`.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, four spaces for shell, Python and Robot Framework files and two spaces for YAML and TOML. Markdown keeps meaningful trailing spaces. `LICENSE`, the RFC texts under `docs/specs/` and the EJBCA profile exports stay verbatim.
