# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-pki-cmp/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares. Every Make target runs with exactly that toolchain, which Go
  downloads on first use when the installed version differs.
* Python 3 with the pinned MkDocs dependencies for the documentation site, installed by
  `make docs-deps`.
* Docker, OpenSSL 3.2 or newer, Git and `uv` for the integration tests. See [Testing](testing.md).

Linters and other tools are downloaded into `bin/` at pinned versions by the Make targets that need
them.

## Repository layout

| Path | Content |
| --- | --- |
| `pkicmp/` | CMP and CRMF types, protection and verification |
| `client/` | The CMP client |
| `server/` | The CMP server |
| `cms/` | EnvelopedData and EncryptedValue for proof of possession by decryption |
| `internal/` | Path verification for composite ML-DSA chains and certificates for ML-KEM keys for the tests and the example CA, not part of the public API |
| `examples/` | The mock CA and client used in [Getting started](../getting-started.md) |
| `test/integration/` | Tests against EJBCA, OpenSSL, Nokia NCM, the Siemens CMP test suite and the Insta Certifier clients |
| `docs/` | This site. `docs/specs/` holds the RFC texts the code cites and is not published |

## Common commands

```bash
make test               # go vet and the unit tests under the race detector
make lint               # golangci-lint, including the integration tests
make fuzz               # every fuzz target in pkicmp for FUZZTIME each, 30s by default
make test-integration   # every integration test, see Testing
make docs-build         # strict MkDocs build
make help               # every target
```

`make test` runs under the race detector because the documented server deployment sweeps expired
transactions from a background goroutine while it serves requests. The unit tests have no external
dependencies.

Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and
`make gitleaks` before pushing. `make tidy-check` fails when `go.mod` or `go.sum` is not tidy and
`make fmt-check` when a tracked Go file is not formatted.

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

`make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from the
navigation fails the build. CI runs the same build on every change to the documentation and
publishes the site from the default branch.

The toolchain is pinned with hashes in `docs/requirements.txt`, which `make docs-deps` installs in
hash-checking mode. The direct dependencies live in `docs/requirements.in`. To change a version, edit
that file and run `make docs-requirements`, which needs pip-tools in the `PYTHON` environment.

Package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-cmp) comes from
the Go doc comments and `make docs` serves it locally with pkgsite. User-facing behavior changes
belong in both places: the doc comment for the API and the relevant page here for the walkthrough.
[Getting started](../getting-started.md) includes the example programs from `examples/`, so change
the program and the page follows.

## Code style

`.editorconfig` records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing
whitespace, tabs for Go and Make recipes, four spaces for shell, Python and Robot Framework files and
two spaces for YAML and TOML. `LICENSE`, the RFC texts under `docs/specs/` and the EJBCA profile
exports stay verbatim.

Protocol changes need negative tests and an RFC citation. A change must keep working against real CMP
peers and against clients that implement only RFC 4210. Interoperability claims need sanitized
evidence naming the peer and its version.
