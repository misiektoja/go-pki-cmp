// Package client provides a Certificate Management Protocol (CMP) client for
// requesting X.509 certificates from a CA over HTTP.
//
// Four methods cover the standard enrollment flows: [Client.SendIR] (initial
// registration), [Client.SendCR] (certification), [Client.SendKUR] (key update),
// and [Client.SendP10CR] (PKCS#10 request). All handle the full lifecycle
// transparently: protection, response verification, polling, and certificate
// confirmation. [Client.SendRR] asks the CA to revoke a certificate. The
// support messages of RFC 9483 §4.3, such as [Client.GetRootCAUpdate], ask the
// CA for information.
//
// # Initial enrollment with MAC protection
//
//	// Create the client. A bootstrapping device has no trust anchor yet, so
//	// none is configured here and caPubs from the response supplies the first
//	// one. Add client.WithTrustedCAs wherever an anchor is already available.
//	c := client.NewClient("http://ca.example.com/.well-known/cmp/p/ca/")
//
//	// Generate a key for the new certificate.
//	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	// Create MAC credentials from the pre-shared secret.
//	creds, err := pkicmp.NewMACCredentials([]byte("my-shared-secret"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Send the Initialization Request (IR).
//	result, err := c.SendIR(context.Background(), key, creds,
//	    client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Got certificate:", result.Certificate.Subject)
//
// # Key update with signature protection
//
//	// Existing certificate and key used to authenticate the request.
//	oldCert := loadExistingCert()
//	oldKey := loadExistingKey()
//
//	// New key for the replacement certificate.
//	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	newCreds, err := pkicmp.NewSignatureCredentials(oldKey, oldCert)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	c := client.NewClient("http://ca.example.com/.well-known/cmp/p/ca/",
//	    client.WithTrustedCAs(trustedCAPool),
//	)
//	result, err := c.SendKUR(context.Background(), newKey, newCreds)
//
// SendKUR automatically identifies oldCert through the CRMF oldCertID control
// when newCreds is a [pkicmp.SignatureCredentials]. Custom credential types can
// provide the certificate with [WithOldCertificate]. The request repeats the
// subject of oldCert in the sender and the certificate template with the bytes
// oldCert encodes, so a CA comparing names byte by byte finds them unchanged.
// When oldCert has an empty subject, the template carries a NULL-DN subject and
// the subjectAltName of oldCert instead. [WithSender] and [WithTemplateSubject]
// override either name.
//
// # Revocation
//
// RFC 9483 §4.2 expects the request to be signed with the certificate being
// revoked:
//
//	creds, err := pkicmp.NewSignatureCredentials(certKey, cert)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = c.SendRR(context.Background(), cert, pkicmp.CRLReasonKeyCompromise, creds)
//	if pkicmp.HasFailure(err, pkicmp.FailCertRevoked) {
//	    fmt.Println("certificate was already revoked")
//	}
//
// [pkicmp.CRLReasonCertificateHold] suspends a certificate and
// [pkicmp.CRLReasonRemoveFromCRL] releases it, if the CA supports holds. A CA
// that delays its answer is polled as described below, without certConf.
//
// # Keys that cannot sign
//
// An ML-KEM key, or an RSA or elliptic curve key kept for encryption only,
// proves possession by decryption (RFC 9810 §5.2.8.3).
// [Client.SendIRWithIndirectPOP], [Client.SendCRWithIndirectPOP] and
// [Client.SendKURWithIndirectPOP] take its private key and the method:
//
//	kemKey, _ := mlkem.GenerateKey768()
//	result, err := c.SendIRWithIndirectPOP(ctx, kemKey, client.EncryptedCertificate, creds,
//	    client.WithTemplateSubject(pkix.Name{CommonName: "my-device-encryption"}),
//	)
//
// With [EncryptedCertificate] the CA returns the certificate encrypted for the
// key, and the hash in the certConf the client sends is the proof. With
// [ChallengeResponse] the CA first sends a popdecc challenge encrypted for the
// key and issues the certificate after the client returns the decrypted number.
// The CA must support the method. RFC 9483 §4.1.1 lets it refuse both for a key
// that can sign.
//
// These requests are sent as version 3 (cmp2021), because the EnvelopedData the
// CA answers with is cmp2021 syntax (RFC 9810 §7). Every later message of the
// transaction keeps that version. A CMP version 2 CA may still send an RSA
// certificate in the older EncryptedValue, which the client decrypts as well.
//
// # Support messages
//
// General messages ask the CA for information rather than a certificate:
// [Client.GetCACertificates], [Client.GetRootCAUpdate],
// [Client.GetCertReqTemplate], [Client.GetCRLUpdate] and
// [Client.GetCurrentCRL]. [Client.SendGenM] sends any other info type.
//
//	update, err := c.GetRootCAUpdate(ctx, currentRoot, creds)
//	switch {
//	case errors.Is(err, client.ErrInfoTypeNotSupported):
//	    // The CA does not offer root updates.
//	case err != nil:
//	    log.Fatal(err)
//	case update != nil:
//	    // update.NewWithNew is the new root. The current root has signed
//	    // update.NewWithOld, which the client has checked.
//	}
//
// A nil result with a nil error means the CA has nothing to send, such as no
// newer root or CRL.
// [ErrInfoTypeNotSupported] covers both a CA that lists the type as
// unsupported and one that leaves it out of its answer, as RFC 4210 CAs do. A
// CA that refuses general messages altogether answers with an error message,
// returned as [*pkicmp.PKIStatusError]. [WithCertProfile] names a
// certificate profile in the request header, for example to ask for the
// template of that profile.
//
// # Asynchronous enrollment and polling
//
// When a CA cannot issue immediately it replies with a "waiting" status. The
// client handles this transparently:
//
//  1. If the CA replies with a waiting status, the Send* method enters an
//     internal polling loop.
//  2. The client sleeps for the duration the CA specified in checkAfter before
//     sending the next PollReq, clamped into the range set by
//     [WithCheckAfterLimits] so that a peer cannot park the operation
//     indefinitely or drive polling as fast as the network allows.
//  3. The final response may identify either the last PollReq or the original
//     request whose processing was delayed, as RFC 9483 Section 4.4 requires.
//  4. Once the certificate is issued the client automatically sends certConf.
//  5. The Send* method returns only after the full exchange completes.
//
// Control the blocking behavior with:
//   - A [context.Context] with a deadline or timeout — the method returns the
//     context error if it expires while polling. Set one on every call: it is
//     the only bound that covers the whole operation rather than a single wait.
//   - [WithMaxPolls]: give up after a fixed number of poll attempts (default 60).
//   - [WithCheckAfterLimits]: bound each individual wait (default 1 second to
//     1 hour). The ceiling is a guard against an unusable value rather than a
//     normal-operation bound, because RFC 9810 Section 5.3.22 asks the client to
//     wait at least the interval the CA sent.
//
// # Response verification
//
// Every response is verified before being accepted:
//
//   - MAC-protected response: verified with the shared secret from the
//     [pkicmp.Credentials] passed to the Send* method.
//   - Signature-protected response: verified against trusted CAs configured
//     via [WithTrustedCAs]. The client rejects the response if no trusted CAs
//     are configured. If the server includes caPubs in an IP response,
//     those may be used directly as trusted CAs unless [WithoutCAPubsTrust]
//     is set.
//
// A response signed with SHA-1 is refused unless [WithSHA1Signatures] is set.
//
// A shared-secret enrollment completes without a pool, but errors are signed
// however the request was protected (RFC 9810 §5.3.21), so without one a
// rejection such as transactionIdInUse arrives as an [UnverifiedStatusError]:
// safe to log, not to act on. See [WithTrustedCAs].
//
// CMP responses carried by HTTP 4xx or 5xx are parsed and verified before their
// status is returned, and the error keeps the HTTP status.
// [pkicmp.HasFailure] never reports bits from an unverified message.
//
// Either protection mechanism is accepted by default, since a CA that
// authenticates by shared secret and signs every response is common. Use
// [WithResponseProtection] to pin one, as RFC 9483 §3.1 asks for.
//
// A signature-protected response must come from a certificate whose subject
// matches the sender in its header. Since a server may send extraCerts only on
// its first response, the certificate authenticated earlier in the operation is
// retained and retried for later messages, under the same checks.
//
// Some CAs sign a response, such as the answer to a revocation request, without
// attaching their certificate. Such a response fails with
// [pkicmp.ReasonNoCandidateSigner] unless the certificate is configured with
// [WithServerCerts]. It is tried last and must pass the same checks.
//
// Only candidates whose subject key identifier equals the senderKID of the
// response are tried. A response whose senderKID names none of them fails with
// [pkicmp.ReasonSenderKIDMismatch]. Some CAs copy the senderKID of the request
// into the response. [WithSenderKIDMismatch] accepts that.
//
// A certificate response must hold exactly one CertResponse with the certReqId
// of the request. A p10cr has no certReqId, so both -1 (RFC 9810 §5.3.4) and 0
// are accepted. A rejection is reported whatever certReqId it carries.
//
// The issued certificate must certify the requested public key and must validate
// against the configured anchors, using response extraCerts to complete the path.
// Its subject is not checked, because a CA may return grantedWithMods having
// changed it. A certificate that fails these checks or arrives under another
// certReqId is rejected in certConf before the error is returned, so the CA
// learns of it at once (RFC 9483 §3.6.1).
//
// A certificate the client accepts can still fail in the confirming certConf,
// for example when the CA refuses it. The error is then a [ConfirmationError]
// holding the certificate. The CA may keep it or revoke it as unconfirmed, so
// check the CA before retrying, because a retry may issue a second one.
//
// # Limits
//
// [DefaultMaxResponseBytes] (10 MiB) caps response body size to prevent memory
// exhaustion. [DefaultMaxPolls] (60) caps polling attempts.
// [DefaultMinCheckAfter] (1 second) and [DefaultMaxCheckAfter] (1 hour) cap
// each wait between them. Override with [WithMaxResponseBytes], [WithMaxPolls]
// and [WithCheckAfterLimits].
//
// # Stateless design
//
// All transaction-specific state (TransactionID, nonces) is managed within the
// lifetime of a single Send* call. A single [Client] instance can be used
// concurrently by multiple goroutines.
package client
