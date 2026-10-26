# Keys the CA generates

A device that cannot generate a good key pair itself can ask the CA to do it (RFC 9483 section
4.1.6). `SendIRWithCentralKeyGeneration`, `SendCRWithCentralKeyGeneration` and
`SendKURWithCentralKeyGeneration` send a request without a public key and return the private key with
the certificate:

```go
// nil leaves the key algorithm to the CA.
result, err := c.SendIRWithCentralKeyGeneration(context.Background(), nil, creds,
	client.WithSenderKID([]byte("my-device")),
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
)
key := result.GeneratedKey.PrivateKey
```

To ask for a key algorithm, pass its AlgorithmIdentifier. An elliptic curve key names its curve in the
parameters:

```go
curve, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}) // P-384
algorithm := &pkicmp.AlgorithmIdentifier{
	Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
	Parameters: curve,
}
```

The CA decides which algorithms it generates and refuses others, usually with badAlg.

## Credentials

The CA encrypts the private key for the requester, so the credentials of the request must be able to
decrypt it:

| Credentials | Encryption |
| --- | --- |
| `pkicmp.MACCredentials` | To the shared secret (RFC 5652 section 6.2.4) |
| `pkicmp.SignatureCredentials` with an RSA key | Key transport to the protection key |
| `pkicmp.SignatureCredentials` with an ECDSA key on P-256, P-384 or P-521 | Key agreement with the protection key |

Other protection keys, such as Ed25519 or ML-DSA, cannot receive the key. The call then fails before
it sends anything.

## Checks

The client accepts the key only when its signature verifies with the signer certificate in the key
package and the key matches the public key of the issued certificate. With `WithTrustedCAs` the
signer certificate must also chain to the trusted CAs and either assert id-kp-cmKGA, be a CA
certificate or be the certificate that protected the response. Without trusted CAs the client does
not validate the signer, which RFC 9483 section 4.1.6 allows for a MAC-protected exchange.

When a check fails, the client rejects the certificate in its `certConf` and returns an error. When
the `certConf` itself fails after the checks, the `ConfirmationError` holds the key in `GeneratedKey`
next to the certificate.

## Result

`EnrollResult.GeneratedKey` holds the key:

| Field | Content |
| --- | --- |
| `PrivateKey` | The parsed key: `*rsa.PrivateKey`, `*ecdsa.PrivateKey`, `ed25519.PrivateKey`, `*mldsa.PrivateKey` or a composite ML-DSA key. It is nil for a key type the client cannot parse, such as ML-KEM |
| `PKCS8` | The DER PKCS #8 key. A OneAsymmetricKey version 2 from the CA keeps its public key |
| `Signer` | The certificate of the key generation authority that signed the key |

An ML-KEM key is checked against the certificate through the public key that its OneAsymmetricKey
carries.

## Delayed delivery

The CA may answer with status waiting. The key then arrives with the certificate when the client
polls. With `WithDeferredPolling`, `PendingEnrollment.CentralKeyGeneration` is true and
`ResumeEnrollment` needs the same credentials to decrypt the key.

## Protocol version

These requests are sent as CMP version 3 (cmp2021), because the CA answers with EnvelopedData. The
client reads the key package in both forms a CA may send: the AsymmetricKeyPackage of RFC 9810
section 5.2.2 and the id-data that OpenSSL writes, which may hold a PKCS #1 or SEC 1 key. A private
key in the deprecated EncryptedValue format is refused.
