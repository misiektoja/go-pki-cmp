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
