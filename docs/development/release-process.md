# Release process

A release is started by pushing a version tag that is reachable from `main` and by nothing else.
`RELEASE_NOTES.md` carries one section per version and that section becomes the release description.

## Versioning

The module follows semantic versioning under the [Compatibility policy](../reference/compatibility.md).
Release headings use `## vX.Y.Z - D Mon YYYY`, for example `## v0.4.0 - 11 Oct 2026`, with an
unpadded day and an abbreviated English month. Keep `TBD` until the release date is set.

## Steps

1. Set the release date in `RELEASE_NOTES.md` and merge `dev` into `main`.
2. Run the release check on `main`:

    ```bash
    make release-check VERSION=vX.Y.Z
    ```

    It exports `HEAD` with `git archive` into a new temporary directory, builds, vets and tests the
    export and imports it from a separate module, so it catches files that are ignored, untracked or
    only present locally. It also checks the release notes heading. Set `RELEASE_CHECK_DIR` to a path
    that does not exist yet to keep the export somewhere else.

3. Tag the release commit on `main` and push the tag:

    ```bash
    git push origin vX.Y.Z
    ```

4. The release workflow repeats the check on the tag and creates a **draft** release with the release
   notes section as its description. Review the draft and publish it.

!!! warning "Never draft a release in the GitHub UI"
    Drafting there creates the tag, which starts the workflow against a release that is already
    published. The workflow refuses to rebuild a published release, so the release and its tag have
    to be removed before the tag can be pushed again.

## Artifacts

Each release carries:

| Artifact | Content |
| --- | --- |
| `go-pki-cmp-<version>-source.zip` and `.tar.gz` | The complete tagged source tree |
| `go-pki-cmp-<version>-sbom.cdx.json` | A CycloneDX software bill of materials with license information |
| `go-pki-cmp-<version>_SHA256SUMS.txt` | SHA-256 checksums of the archives and the SBOM |
| `go-pki-cmp-<version>.intoto.jsonl` | A signed provenance bundle covering the artifacts |

Verify a file with `gh attestation verify <file> --repo misiektoja/go-pki-cmp`. Offline verification
takes `--bundle` and the provenance file.

## Documentation

The documentation workflow publishes this site from the default branch to GitHub Pages whenever
`docs/`, `mkdocs.yml` or the examples change there. Pull requests and pushes to `dev` run the strict
build without publishing. The site therefore describes `main`, which is the latest release plus any
fixes merged since.
