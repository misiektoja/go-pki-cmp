# Revocation

`Client.SendRR` asks the CA to revoke a certificate (RFC 9483 section 4.2). RFC 9483 expects the
request to be signed with the certificate being revoked:

```go
creds, _ := pkicmp.NewSignatureCredentials(certKey, cert)

// Some CAs sign the response without attaching their certificate. WithServerCerts
// supplies it, and it must still chain to trustedCAs and match the response sender.
c := client.NewClient("http://localhost:8080/cmp",
	client.WithTrustedCAs(trustedCAs),
	client.WithServerCerts([]*x509.Certificate{issuingCA}),
)

err := c.SendRR(context.Background(), cert, pkicmp.CRLReasonKeyCompromise, creds)
if pkicmp.HasFailure(err, pkicmp.FailCertRevoked) {
	// The certificate was already revoked.
}
```

A nil error means the CA revoked the certificate. A refusal arrives as a `*pkicmp.PKIStatusError`.

A registration authority or another management entity that revokes for an end entity signs with its
own credentials (RFC 9483 section 5.3.2). The CA decides whether it may.

## Revocation by serial number

A requester that has no copy of the certificate, such as an operator who knows only its serial number
and the CA, names it with `Client.SendRRBySerial`:

```go
serial, _ := new(big.Int).SetString("1A2B", 16)
err := c.SendRRBySerial(context.Background(), pkix.Name{CommonName: "Example CA"}, serial,
	pkicmp.CRLReasonKeyCompromise, raCreds)
```

The issuer name is encoded from the `pkix.Name`. A CA that compares the name bytes needs the
attributes in the order and with the string types of the certificate. The `server` package compares
the decoded attributes, so the string types may differ there.

## Invalidity date

`WithInvalidityDate` adds the invalidityDate CRL entry extension (RFC 5280 section 5.3.2) to the
request: the time at which the key is known or suspected to have been compromised or the certificate
otherwise became invalid. A CA may publish it in the CRL entry. It is sent as a GeneralizedTime in
UTC with a resolution of one second.

```go
err := c.SendRR(context.Background(), cert, pkicmp.CRLReasonKeyCompromise, creds,
	client.WithInvalidityDate(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)))
```

## Holds

`pkicmp.CRLReasonCertificateHold` suspends a certificate and `pkicmp.CRLReasonRemoveFromCRL` releases
it, if the CA supports holds.

## Delayed answers

A CA that waits for a decision, for example an operator's approval, answers with status waiting. The
client polls as it does for enrollment and returns once the CA decides. A revocation has no
`certConf`.

## Signer certificate in the response

Some CAs, including some Nokia NCM releases, sign the revocation response with the issuing CA key
without attaching that certificate. Pass the issuer of the revoked certificate to `WithServerCerts`.
[Response verification](response-verification.md) explains the checks it still has to pass.
