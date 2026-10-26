# Keys the server generates

`WithCentralKeyGeneration` lets a client ask the server to generate its key pair (RFC 9483 section
4.1.6). The certificate template of such an `ir`, `cr` or `kur` has no public key or an algorithm with
an empty key. The request has no proof of possession. Without the option the server refuses it with
badCertTemplate.

```go
srv := server.NewCAServer(myCA, server.LightweightPolicy(),
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(myCA),
	server.WithCertificateLookup(myCA),
	server.WithCentralKeyGeneration(myGenerator, kgaKey, kgaCert),
)
if err := srv.Err(); err != nil {
	log.Fatal(err)
}
```

## Key generator

`server.KeyGenerator` makes the key pair. `GenerateKey` gets the requested algorithm with its
parameters and the authenticated sender. The algorithm is nil when the client leaves the choice to
you. It returns the private key as DER PKCS #8 together with the public key. Return a
`*server.Error` with badAlg for an algorithm you do not generate. A key of another algorithm than the
one requested is refused with badAlg.

The server sends the key as a OneAsymmetricKey version 2 with its public key, as RFC 9483 section
4.1.6 requires.

## Key generation authority

`kgaKey` signs every generated key and `kgaCert` is its certificate. The certificate must assert the
id-kp-cmKGA extended key usage (RFC 9480 section 2.2) or be a CA certificate. OpenSSL clients accept
only id-kp-cmKGA. Pass the certificates between `kgaCert` and the client's trust anchor as the chain,
so that clients can validate the signer. `Server.Err` reports a key that does not match `kgaCert` or a
certificate that may not sign keys.

## Encryption

The signed key is encrypted for the requester:

| Request protection | Encryption |
| --- | --- |
| MAC | To the shared secret with PBKDF2 and the RFC 3211 key wrap, the only form OpenSSL reads. `WithCentralKeyGenerationAESKeyWrap` selects the AES key wrap of RFC 9481 section 4.3 |
| Signature, RSA protection key | Key transport with RSA-OAEP |
| Signature, ECDSA protection key on P-256, P-384 or P-521 | Key agreement with ephemeral-static ECDH |
| Signature, other protection key | Refused with badAlg |

The key usage of the protection certificate is not checked.

## Signed content

By default the server signs the OneAsymmetricKey itself as id-data. This is the form OpenSSL writes
and the only one OpenSSL clients read. `WithCentralKeyGenerationAsymmetricKeyPackage` signs an
AsymmetricKeyPackage with the id-ct-KP-aKeyPackage content type instead, as RFC 9810 section 5.2.2
and RFC 9483 section 4.1.6 specify. OpenSSL 3.5 to 4.1 clients cannot read that form.

## Your CA

`server.POPMethodFromContext` returns `POPCentralKeyGeneration` for these requests. The built-in CA
handler of `NewCAServer` puts the generated public key into the template it passes to
`IssueCertificate`. A custom `Handler` gets the key from `server.GeneratedPublicKeyFromContext` and
must certify it.

The server withholds a certificate that does not certify the generated key. The client gets
systemFailure and a `CertificateConfirmer` hears `ConfirmRejected`.

## Delayed issuance

The key pair is generated when the request arrives. A waiting request keeps the encrypted private key
until the CA decides. The client gets it with the certificate when it polls. Snapshots from
`SnapshotTransactions` carry the encrypted key of every waiting request.

## Protocol version

EnvelopedData is CMP version 3 syntax, so the response is version 3. OpenSSL clients send these
requests as version 2 and read the version 3 answer.
