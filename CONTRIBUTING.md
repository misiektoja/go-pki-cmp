# Contributing

go-pki-cmp is a Go library for the Certificate Management Protocol (CMP). Bug reports, interoperability results and code contributions are welcome. Usage questions go through the question issue form, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another CMP implementation without checking its license and naming the source in the pull request. The project derives from [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp), as [NOTICE](NOTICE) records.

Never commit shared secrets, private keys, full CSRs, CMP messages captured from a production system or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test, fuzz, integration, documentation and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make fuzz
make docs-build
```

`make test` runs `go vet` and the unit tests under the race detector. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make docs-build` builds the documentation site strictly and needs `make docs-deps` once. Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and `make gitleaks` before pushing. `make help` lists every target.

`make test-integration` runs the library against EJBCA, OpenSSL, the Siemens CMP test suite, Nokia NCM and the Insta Certifier clients. It needs Docker, OpenSSL 3.2 or newer, Git and `uv`. The NCM and Insta Certifier tests skip without their setup.

[Development](https://misiektoja.github.io/go-pki-cmp/development/development/) and [Testing](https://misiektoja.github.io/go-pki-cmp/development/testing/) describe the repository layout, the fuzz targets, the integration test setup and the OpenSSL versions each test needs.

Protocol changes need negative tests and an RFC citation. A change must keep working against real CMP peers and against clients that implement only RFC 4210. Interoperability claims need sanitized evidence naming the peer and its version. User-facing behavior changes update the Go doc comments and the relevant page under `docs/`.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning. [RELEASE_NOTES.md](RELEASE_NOTES.md) describes every change that affects callers, including any that needs a code change. [Compatibility policy](https://misiektoja.github.io/go-pki-cmp/reference/compatibility/) states what may change before v1.0.0.

## Releasing

A release is started by pushing a version tag that is reachable from `main` and by nothing else. [Release process](https://misiektoja.github.io/go-pki-cmp/development/release-process/) lists the steps, the release notes heading format, the checks and the artifacts every release carries.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, four spaces for shell, Python and Robot Framework files and two spaces for YAML and TOML. Markdown keeps meaningful trailing spaces. `LICENSE`, the RFC texts under `docs/specs/` and the EJBCA profile exports stay verbatim.
