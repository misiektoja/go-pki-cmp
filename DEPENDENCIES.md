# Dependencies

go-pki-cmp is a modified derivative of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp), as [NOTICE](NOTICE) records. Other third-party code is consumed through versioned packages.

| Dependency | Use | License |
| --- | --- | --- |
| golang.org/x/crypto | ASN.1 encoding through `cryptobyte` and PBKDF2 key derivation in `pkicmp` | BSD-3-Clause |
| github.com/misiektoja/go-composite-mldsa | Composite ML-DSA signatures and certificates | Apache-2.0 |
| github.com/stretchr/testify | Test assertions | MIT |
| github.com/tsaarni/certyaml | Test certificates and keys | Apache-2.0 |
| EJBCA Community | CA for the client integration tests, run in Docker | LGPL-2.1 |
| nginx | HTTP front end of the EJBCA test environment | BSD-2-Clause |
| OpenSSL | CMP client and mock server for the integration tests | Apache-2.0 |
| Siemens CMP test suite | Conformance tests for the server | Apache-2.0 |

Exact Go versions and checksums are in `go.mod` and `go.sum`. The EJBCA and nginx images are pinned in
`test/integration/ejbca/docker-compose.yml`, the CMP test suite commit in the `Makefile` and the OpenSSL
release in `.github/workflows/integration.yml`. Only golang.org/x/crypto and go-composite-mldsa are
dependencies of the library itself. go-composite-mldsa has no dependencies beyond the Go standard
library. The others are used by the tests. Each dependency retains its own license and notices in the
downloaded module or distribution.
