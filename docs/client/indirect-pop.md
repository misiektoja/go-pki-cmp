# Keys that cannot sign

ML-KEM keys and RSA or elliptic curve keys kept for encryption only cannot sign a proof of
possession. They prove possession by decryption instead (RFC 9810 section 5.2.8.3).
`SendIRWithIndirectPOP`, `SendCRWithIndirectPOP` and `SendKURWithIndirectPOP` take the private key
and the method:

```go
// The CA must support the chosen method.
kemKey, _ := mlkem.GenerateKey768()
result, err := c.SendIRWithIndirectPOP(context.Background(), kemKey, client.EncryptedCertificate, creds,
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device-encryption"}),
)
```

## Methods

| Method | Exchange |
| --- | --- |
| `client.EncryptedCertificate` | The CA returns the certificate encrypted for the key. The hash in the client's `certConf` is the proof |
| `client.ChallengeResponse` | The CA first sends a `popdecc` challenge encrypted for the key and issues the certificate after the client returns the decrypted number |

The client answers the challenge and decrypts the certificate itself. Both methods need a CA that
supports them. RFC 9483 section 4.1.1 lets a CA refuse both for a key that can sign, such as RSA or
an elliptic curve key.

## Accepted keys

| Key | Go type |
| --- | --- |
| ML-KEM-768 and ML-KEM-1024 | `*mlkem.DecapsulationKey768`, `*mlkem.DecapsulationKey1024` or another `crypto.Decapsulator` |
| RSA | `*rsa.PrivateKey` or another `crypto.Decrypter` that implements RSA-OAEP |
| Elliptic curve on P-256, P-384 or P-521 | `*ecdsa.PrivateKey`, `*ecdh.PrivateKey` or another `ecdh.KeyExchanger`, requested with the keyAgreement proof |

ML-KEM-512 is not supported because the Go standard library does not implement it.

## Protocol version

These requests are sent as CMP version 3 (cmp2021), because the EnvelopedData the CA answers with is
cmp2021 syntax (RFC 9810 section 7). Every later message of the transaction keeps that version. A CMP
version 2 CA may still send an RSA certificate in the older EncryptedValue format, which the client
decrypts as well.
