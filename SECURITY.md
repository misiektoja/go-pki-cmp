# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Report it privately through [GitHub security advisories](https://github.com/misiektoja/go-pki-cmp/security/advisories/new), which keeps the report visible only to the maintainer until an advisory is published. If you cannot use that, email <misiektoja-github@rm-rf.ninja>.

Do not include shared secrets, private keys, full CSRs, CMP messages captured from a production system or production endpoint details in a report. Include the affected revision, the impact, the preconditions to reproduce it and a sanitized proof when you have one.

The maintainer will acknowledge the report and coordinate disclosure once a fix is available.

## Severity and fix targets

A report is rated by where the flaw is reachable and what it gives an attacker, not by its CVSS score alone. The tiers and targets are those of the products built on this library.

| Tier | Meaning | Before the fix | Fixed release |
| --- | --- | --- | --- |
| Emergency | Exploited in the wild. Also any flaw reachable by an unauthenticated peer that gives key material, a certificate or signature the caller did not authorize or a trust bypass | Same day: an advisory with a workaround where one exists | Within 3 days |
| Critical | The same impact behind authentication or a non-default setting. Also a flaw in a dependency that `govulncheck` shows reachable from this module | Within 2 days | Within 7 days |
| High | Denial of service from a peer or disclosure of data the caller could not otherwise read | A documented workaround where one exists | Within 30 days |
| Moderate and low | Everything else, including every dependency flaw that `govulncheck` shows unreachable | None | Next release, recorded as not affected |

The targets are what the maintainer works to, not a service commitment.

## Supported versions

Security fixes are made on the default branch and shipped in the next [GitHub release](https://github.com/misiektoja/go-pki-cmp/releases). Only the latest released version is supported. Earlier versions receive no backports.
