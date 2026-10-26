# Tested implementations

The integration tests run the library against independent CMP implementations. CI runs the open ones
on every push and pull request. The proprietary clients run locally only.

## In CI

| Peer | Version | Direction | Scenarios |
| --- | --- | --- | --- |
| [EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp) Community Edition | 9.6.3 | Client against EJBCA | `ir` with RSA, P-384 and SLH-DSA keys, `cr` including one protected with an SLH-DSA key, `kur` with a new and the same key, `p10cr` including an SLH-DSA request, extension override, chain verification, wrong secret and wrong subject refusals, general messages refused with badRequest |
| [OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html) `cmp` | 3.5 and 4.0 | Client against the OpenSSL mock server | `ir`, `cr`, `kur`, `p10cr`, `rr`, polling, failure info and support messages. SLH-DSA proofs, PKCS #10 requests and message protection. Root CA key updates made by OpenSSL whose old or new root has an SLH-DSA key, and a refused forged one. Central key generation in a signed `cr` |
| OpenSSL `cmp` | 3.5 and 4.0 | OpenSSL client against the server | Revocation, delayed enrollment and revocation with polling, support messages and the encrypted certificate method (`-popo 2`) for RSA and EC keys. OpenSSL 4.0 also enrolls ML-KEM keys that way. `ir`, `cr`, `kur` and `p10cr` with SLH-DSA keys, the `cr` and `kur` protected with an SLH-DSA key. `ir` and `kur` at a CA with an SLH-DSA key that also signs the responses. Root CA key updates whose old or new root has an SLH-DSA key, which OpenSSL verifies. Central key generation (`-centralkeygen`) in a MAC-protected `ir` and in a `cr` signed with an EC or RSA key |
| OpenSSL `cms` | 3.5 and 4.0 | `cms` package | EnvelopedData in both directions. ML-KEM cases need 4.0 |
| [Nokia NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) | Hosted instance | Client against NCM | `p10cr` with PasswordBasedMac and with a signature, re-enrollment, `kur` with a new and the same key, `rr` and support messages |
| [Siemens CMP test suite](https://github.com/siemens/cmp-test-suite) | Pinned commit | Suite against the server | The conformance tests, with `WithStrictProfileValidation`, implicit confirmation and a registration authority |

The NCM tests run for pushes to `dev` and `main`, once a week and on request, never for pull
requests. They need the endpoint and credentials in repository secrets.

## Locally

The Insta Certifier 10 cmpclient and the Insta Certifier 7 ssh-cmpclient are proprietary, so CI does
not run them. The tests need a local image built from your own copies. Both clients break RFC 4211
and RFC 9483 rules in places. The tests check that the server defaults refuse those requests and that
the matching option accepts them:

| Client and operation | Server setting needed |
| --- | --- |
| cmpclient `ir`, `cr` and `kur` with a signature proof of possession | `WithPoposkInputVariants` |
| cmpclient `p10cr` and `ir` from a CSR template | None |
| cmpclient `rr` | `WithOptionalRevocationReason` |
| cmpclient `genm` (`--type info`), which sends no items | None |
| cmpclient `ir` that waits for a decision, polled without recipNonce | `WithOptionalPollReqRecipNonce` |
| ssh-cmpclient `INITIALIZE`, `ENROLL`, `P10CR` and `UPDATE` with a new key | None |
| ssh-cmpclient `UPDATE` without `-P`, which keeps the key and sends no proof of possession | `WithSignatureProtectionPOP` |
| ssh-cmpclient `POLL` after an `INITIALIZE` that waits for a decision, without recipNonce | `WithOptionalPollReqRecipNonce` |
| ssh-cmpclient `REVOKE` | Not accepted, it sends pvno 0 |

`WithStrictProfileValidation` refuses MAC-protected requests from ssh-cmpclient and from cmpclient
without `--sender`, because their sender is the NULL-DN. It also refuses cmpclient requests that carry
poposkInput and a signed ssh-cmpclient `UPDATE`, which leaves the signer certificate out of
`extraCerts`.

## Other clients

| Client | Note |
| --- | --- |
| OpenSSL 3.0 and 3.2 | Read an encrypted RSA certificate only as EncryptedValue, which the server sends to CMP version 2 requests |
| Bouncy Castle `CertificateResponse` | Reads only EnvelopedData. Send version 3 for RSA keys or set `WithEnvelopedDataForVersion2` on the server |

## Running the tests

[Testing](../development/testing.md) explains the prerequisites and the Make targets.
