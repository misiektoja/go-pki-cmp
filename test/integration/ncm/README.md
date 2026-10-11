# Nokia NCM integration tests

Integration tests for the CMP client against a [Nokia NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) instance. They cover:

* P10CR enrollment protected with PasswordBasedMac
* P10CR enrollment protected with a signature
* P10CR re-enrollment of an identity NCM has already certified
* KUR with a new key
* KUR with the existing key
* RR of a newly enrolled certificate, then a second RR that must draw a verified rejection

Every certificate must certify the requested key and chain to the configured trust anchor. The client confirms each one with `certConf` and verifies the `pkiConf`.

## Running the tests

Set the variables below and run:

```bash
make test-integration-ncm
```

Each test skips when the configuration it needs is missing. Without an endpoint the whole package skips, so `make test-integration` passes without NCM.

The [NCM interoperability](../../../.github/workflows/interop-ncm.yml) workflow runs the tests for pushes to `dev` and `main`, once a week and on request. It reads the same names from the repository secrets and variables. It runs one job per configured transport and never runs for pull requests.

## Configuration

These values are secrets in the repository. Store them as secrets, not variables, so a run against a private instance does not print them in the log.

| Secret | Required | Contents |
| --- | --- | --- |
| `NCM_CMP_HTTP_URL` | one URL at least | Plain HTTP CMP endpoint, for example `http://ncm.example:8080/pkix/` |
| `NCM_CMP_HTTPS_URL` | one URL at least | HTTPS CMP endpoint |
| `NCM_CMP_RECIPIENT_DN` | yes | Name of the issuing CA, for example `C=DE,O=Example,CN=Issuing CA`. `C`, `ST`, `L`, `STREET`, `POSTALCODE`, `O`, `OU`, `CN` and `SERIALNUMBER` are supported |
| `NCM_CMP_RESPONSE_TRUST` | yes | PEM anchors that sign the CMP responses and the issued certificates |
| `NCM_CMP_PBM_REFERENCE` | for PasswordBasedMac | Reference number of the shared secret, sent as `senderKID` |
| `NCM_CMP_PBM_SECRET` | for PasswordBasedMac | Shared secret |
| `NCM_CMP_BOOTSTRAP_CERT` | for signatures | PEM certificate that signs the enrollment requests |
| `NCM_CMP_BOOTSTRAP_KEY` | for signatures | PEM private key of that certificate |
| `NCM_CMP_BOOTSTRAP_CHAIN` | no | PEM issuers of that certificate, sent in `extraCerts` |
| `NCM_CMP_HTTPS_TRUST` | no | PEM anchors for the HTTPS server certificate when it is not publicly trusted |

These are repository variables:

| Variable | Contents |
| --- | --- |
| `NCM_CMP_COMMON_NAME` | Common name for the enrollment tests. Unset gives `go-pki-cmp-test-<UTC YYMMDD-HHMMSS>-<test>` |
| `NCM_CMP_COUNTRY` | Country requested in the subject. Omitted when unset |
| `NCM_CMP_ORGANIZATION` | Organization requested in the subject. Omitted when unset |
| `NCM_CMP_KUR` | `false` skips both key update tests |
| `NCM_CMP_KUR_SAME_KEY` | `false` skips the key update that keeps the existing key |
| `NCM_CMP_REENROLL` | `false` skips the re-enrollment test |
| `NCM_CMP_RR` | `false` skips the revocation test |

PasswordBasedMac uses SHA-256, HMAC-SHA256 and 1024 iterations. The re-enrollment and key update tests enroll with PasswordBasedMac when it is configured and with the bootstrap signature otherwise. A key update is signed by the certificate it replaces and is sent to the enrollment endpoint.

The key update and revocation tests always enroll under a generated name, because a profile that authorizes only `NCM_CMP_COMMON_NAME` could not certify a second identity.

A revocation request is signed by the certificate it revokes. Some NCM releases sign the revocation response with the issuing CA key without attaching that certificate, so the test passes the issuer of the revoked certificate to `client.WithServerCerts`.

## Server profile

The tests expect a profile that:

* accepts P10CR with the configured protection
* certifies an identity again when it is re-enrolled
* accepts KUR signed by a certificate it issued and certifies the same key twice for the same-key update
* accepts RR signed by the certificate being revoked

Turn off the tests a profile does not allow with the variables above.

NCM answers with HTTP 503 and no CMP message once a host exceeds its request rate limit. The limit counts every CMP message, `certConf` included. The tests therefore run one after another, send at most one request every 1.5 seconds and send a refused request again after a pause. NCM refuses such a request before it parses it, so sending it again does not repeat a transaction.
