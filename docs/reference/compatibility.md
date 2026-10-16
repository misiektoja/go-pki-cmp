# Compatibility policy

The module uses semantic versioning. The public API is every exported identifier of `pkicmp`,
`client`, `server` and `cms`. The `internal` packages, the examples and the integration tests are not
part of it.

## Before v1.0.0

A minor release may change the public API. The release notes name every such change and what callers
need to do. Patch releases keep the API.

## Rules for every release

* **Structs may gain fields.** Construct them with field names.
* **Enumerations may gain values.** Request types, statuses, failure bits, verification reasons and
  proof of possession methods may grow. Switch statements over them need a default case.
* **Refusal reasons may become more precise.** A failure that used to report one `InvalidReason` may
  report a new, narrower one. Check for the reasons you act on and treat the rest as a failure.
* **New server capabilities use optional interfaces or options.** The server detects an interface
  your CA implements, so existing CAs keep compiling.
* **Wire behavior changes are announced.** Behavior a peer can observe changes only with a release
  notes entry and an RFC citation.

## Upgrading

1. Read the [release notes](https://github.com/misiektoja/go-pki-cmp/blob/main/RELEASE_NOTES.md)
   section for the new version.
2. Run `go get github.com/misiektoja/go-pki-cmp@vX.Y.Z` and build.
3. Run your own integration tests against the CMP peers you support.
   [Tested implementations](../interoperability/tested-implementations.md) names the peers each
   feature was tested with.

Releases up to v0.3.2 use the module path `github.com/misiektoja/go-pkicmp-ng`.

## Go version

The module declares the minimum Go version in `go.mod`. Every check runs with exactly that toolchain.
