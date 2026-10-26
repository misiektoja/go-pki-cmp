# mockserver

Demonstrates how to implement the [`server.CA`](../../server/ca.go) interface
to build a CA server with CMP support. [support.go](support.go) answers the
RFC 9483 support messages for CA certificates, a certificate request template
and CRLs.

The CA signs certificates with `compositex509.CreateCertificate` from
[go-composite-mldsa](https://github.com/misiektoja/go-composite-mldsa), so it
also certifies composite ML-DSA keys. A composite certificate it issued can
then sign key update, certConf and revocation messages. It also certifies
ML-KEM-768 and ML-KEM-1024 keys, with keyEncipherment as their only key usage,
when the server accepts an indirect proof of possession such as
`server.WithEncryptedCertificatePOP`.

[keygen.go](keygen.go) implements `server.KeyGenerator` for central key
generation (RFC 9483 section 4.1.6). It generates ECDSA keys on P-256, P-384
and P-521 as well as RSA 2048-bit, Ed25519 and ML-DSA keys. A client that leaves
the choice to the CA gets an ECDSA P-256 key. A key generation authority certificate that
the CA issues with the id-kp-cmKGA extended key usage signs them.
`MockCA.CentralKeyGeneration` returns the server option, which the example
command enables.
