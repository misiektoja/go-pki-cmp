# Implementing a CA

The `server` package handles the protocol. Your code signs certificates by implementing `server.CA`:

```go
type CA interface {
	IssueCertificate(ctx context.Context, reqType RequestType,
		template *x509.Certificate, sender *SenderIdentity) (*Response, error)
}
```

The server calls `IssueCertificate` for every `ir`, `cr`, `kur` and `p10cr` that passed protection,
transaction, policy and proof of possession checks. `reqType` names the request and `sender` the
authenticated requester.

## The template

The template arrives with the subject, public key, extensions and subject key identifier from the
request. `SerialNumber` is nil. The CA must set the serial number and validity and may enforce
policy, change the subject, add or remove extensions or refuse the request.

```go
func (c *myCA) IssueCertificate(ctx context.Context, reqType server.RequestType,
	tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {

	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now()
	tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)

	// Drop a requested keyUsage, otherwise it would override the one set below.
	oidKeyUsage := asn1.ObjectIdentifier{2, 5, 29, 15}
	tmpl.ExtraExtensions = slices.DeleteFunc(tmpl.ExtraExtensions,
		func(e pkix.Extension) bool { return e.Id.Equal(oidKeyUsage) })
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: cert}, nil
}
```

!!! warning "Requested extensions win over typed fields"
    `template.ExtraExtensions` holds the extensions the requester asked for and nothing has vetted
    them. `x509.CreateCertificate` gives an extension in `ExtraExtensions` precedence over the
    matching typed field, so assigning `template.KeyUsage` does not override a requested keyUsage.
    The same applies to `ExtKeyUsage`, `BasicConstraints` and the other typed fields. Remove an
    extension from `ExtraExtensions` before you decide it yourself, as the example does.

### Subject names

The subject is rebuilt from `pkix.Name`, which drops attribute types it does not model, such as
domainComponent and emailAddress. It may also reorder the rest and change their string types.
`server.WithRawSubject` also sets `template.RawSubject` to the requested name, which
`x509.CreateCertificate` issues unchanged. Clear `RawSubject` before you change the subject.

A request that names the entity only in a subjectAltName has an empty subject. The template marks
that subjectAltName critical, as RFC 5280 section 4.2.1.6 requires. A CA that supplies a subject
should clear the flag.

### Post-quantum keys

* A composite ML-DSA subject key arrives as `*compositemldsa.PublicKey`. Only
  `compositex509.CreateCertificate` from [go-composite-mldsa](https://github.com/misiektoja/go-composite-mldsa)
  can certify it. A CA with a composite key signs with the same function.
* Clients can check a composite CA signature only when the CA certificate travels in the response, so
  pass it to `WithExtraCerts` or return it in `Response.CACerts`.
* An ML-KEM key arrives as `*mlkem.EncapsulationKey768` or `*mlkem.EncapsulationKey1024`, which
  crypto/x509 cannot certify. `pkicmp.MarshalPublicKey` encodes its SubjectPublicKeyInfo, whose only
  allowed key usage is keyEncipherment. See [Keys that cannot sign](indirect-pop.md).
* An SLH-DSA key arrives as an `slhdsa.PublicKey` value from
  [circl](https://github.com/cloudflare/circl), which crypto/x509 cannot certify either.
  `pkicmp.MarshalPublicKey` encodes its SubjectPublicKeyInfo (RFC 9909). Its key usage may include
  digitalSignature, nonRepudiation, keyCertSign and cRLSign but no encipherment.
* A CA with an SLH-DSA key signs its certificates outside crypto/x509 too, with the RFC 9909
  identifier and absent parameters. It can also be the `WithSigner` key. Clients and the server
  verify paths through it and confirm its certificates with an explicit SHA-512 hash. Each signature
  is slow, see [Known limitations](../known-limitations.md#slh-dsa-cas-sign-slowly).

The [example CA](https://github.com/misiektoja/go-pki-cmp/tree/main/examples/mockserver) uses
`compositex509.CreateCertificate` for every key, so it certifies composite keys as well as the key
types crypto/x509 supports.

## The response

| Field | Effect |
| --- | --- |
| `Certificate` | The issued certificate |
| `CACerts` | CA certificates sent in `caPubs` |
| `Waiting` | Delays the answer, see [Delayed issuance and confirmation](delayed-issuance.md) |
| `GrantedWithMods` | Answers grantedWithMods instead of accepted for a certificate that differs from the request |
| `StatusText` | The statusString of the issued certificate, for example to name what the CA changed |
| `IssueRef` | Your own reference, passed back when the certificate is confirmed or expires |

Return a `*server.Error` to refuse a request with a chosen status and failure bits:

```go
return nil, &server.Error{
	Status:      pkicmp.StatusRejection,
	FailureInfo: pkicmp.FailBadCertTemplate,
	StatusText:  "subject not allowed",
}
```

Any other error becomes a bare systemFailure. Its text is not sent to the peer, so internal detail is
never disclosed.

## Serving it

```go
srv := server.NewCAServer(ca,
	server.LightweightPolicy(),
	server.WithSigner(caKey, caCert),
	server.WithExtraCerts([]*x509.Certificate{caCert}),
	server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
	server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
	// A messageTime outside this tolerance is refused as badTime.
	server.WithMessageTimeTolerance(5*time.Minute),
)
if err := srv.Err(); err != nil {
	log.Fatal(err)
}
http.Handle("/cmp", srv)
```

`WithSigner` takes a `crypto.Signer`, so the key can live in an HSM. `Err` reports a
misconfiguration such as a signer key that does not match its certificate. Such a server answers
every request with systemFailure rather than issue certificates it cannot protect, so check it at
startup.

The second argument is the policy middleware. [Policy and client compatibility](policy.md) explains
`LightweightPolicy` and how to add your own authorization.

### Several CAs

Each `Server` serves one CA. Create one per CA and route by path. RFC 9483 section 6.1 defines the
well-known path `/.well-known/cmp/p/<name>`:

```go
mux := http.NewServeMux()
mux.Handle("/.well-known/cmp/p/devices", devicesServer)
mux.Handle("/.well-known/cmp/p/servers", serversServer)
```

## Optional interfaces

A CA can implement more interfaces. `NewCAServer` detects them:

| Interface | Page |
| --- | --- |
| `CertificateConfirmer`, `PendingChecker`, `WaitingExpirer` | [Delayed issuance and confirmation](delayed-issuance.md) |
| `Revoker`, `RevocationAuthorizer` | [Revocation](revocation.md) |
| `CACertificatesProvider`, `RootCAUpdateProvider`, `CertReqTemplateProvider`, `CRLProvider` | [Support messages](support-messages.md) |

## Full control

`server.New` takes any `server.Handler`, which receives the raw `*pkicmp.PKIMessage` and the
authenticated `SenderIdentity`. Use it for custom routing or a proxy. Most applications should use
`NewCAServer`, because the handler it builds also runs the proof of possession and BasicConstraints
checks.
