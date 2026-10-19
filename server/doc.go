// Package server implements a CMP server framework that can be embedded in a
// CA to add CMP support. It handles all protocol mechanics automatically:
// HTTP transport, message parsing, protection verification, response construction,
// nonce and transaction management, and the certConf round-trip.
//
// # Abstraction levels
//
// The package offers two levels of control:
//
//   - [CA] interface: implement certificate issuance; the framework handles the rest.
//   - [Handler] interface: receive the raw [pkicmp.PKIMessage] for full control
//     (RA proxying, custom routing, non-standard flows).
//
// Most callers should use [CA] via [NewCAServer].
//
// # CA interface
//
// Implement [CA.IssueCertificate]:
//
//	IssueCertificate(ctx context.Context, reqType RequestType,
//	    template *x509.Certificate, sender *SenderIdentity) (*Response, error)
//
// The template arrives with subject, public key, extensions, and SKI already
// populated from the CMP request. The CA has full control before signing:
// it must set SerialNumber and validity, and may enforce policy, override
// the subject, add or strip extensions, or reject the request outright.
//
// The extensions in template.ExtraExtensions are the ones the requester asked
// for, and nothing has vetted them. [x509.CreateCertificate] gives an extension
// in ExtraExtensions precedence over the matching typed field, so assigning
// template.KeyUsage does not override a requested keyUsage extension: the
// assignment is silently discarded and the requested value is issued instead.
// The same applies to ExtKeyUsage, BasicConstraints and the other typed fields.
// A CA that means to decide an extension itself must drop it from
// ExtraExtensions first, as the example below does for keyUsage.
//
// A CA that leaves out or changes a requested extension may set
// [Response].GrantedWithMods, so the client receives grantedWithMods instead of
// accepted, and explain the change in [Response].StatusText.
//
// The subject is rebuilt from [crypto/x509/pkix.Name], which drops attribute
// types it does not model, such as domainComponent and emailAddress. It may
// also change the order and string types of the rest. [WithRawSubject] also sets
// template.RawSubject to the requested name, which [x509.CreateCertificate]
// issues unchanged instead of Subject.
//
// # Basic example
//
//	type myCA struct {
//	    key  crypto.Signer
//	    cert *x509.Certificate
//	}
//
//	func (c *myCA) IssueCertificate(ctx context.Context, reqType server.RequestType,
//	    tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
//
//	    tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
//	    tmpl.NotBefore = time.Now()
//	    tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
//
//	    // Drop a requested keyUsage, otherwise it would override the one set below.
//	    oidKeyUsage := asn1.ObjectIdentifier{2, 5, 29, 15}
//	    tmpl.ExtraExtensions = slices.DeleteFunc(tmpl.ExtraExtensions,
//	        func(e pkix.Extension) bool { return e.Id.Equal(oidKeyUsage) })
//	    tmpl.KeyUsage = x509.KeyUsageDigitalSignature
//
//	    der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
//	    if err != nil {
//	        return nil, err
//	    }
//	    cert, _ := x509.ParseCertificate(der)
//	    return &server.Response{Certificate: cert}, nil
//	}
//
// crypto/x509 cannot create composite ML-DSA signatures. A CA with a composite
// key calls compositex509.CreateCertificate from
// github.com/misiektoja/go-composite-mldsa instead, with the same arguments.
// The same applies to a composite subject key, which the template carries as
// *compositemldsa.PublicKey. crypto/x509 cannot certify an SLH-DSA subject key,
// which the template carries as an slhdsa.PublicKey value. Encode its
// SubjectPublicKeyInfo with [pkicmp.MarshalPublicKey] and sign the certificate
// outside crypto/x509.
// Clients can check such a signature only when the CA certificate travels in
// the response, so pass it to [WithExtraCerts] or return it in
// [Response].CACerts.
//
// Pass the CA implementation and credential lookups to [NewCAServer] along with
// the signing key, CA certificate, and middleware (or chain of middlewares).
//
//	srv := server.NewCAServer(ca,
//	    server.LightweightPolicy(),
//	    server.WithSigner(caKey, caCert),
//	    server.WithExtraCerts([]*x509.Certificate{caCert}),
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//	if err := srv.Err(); err != nil {
//	    log.Fatal(err)
//	}
//	http.ListenAndServe(":8080", srv)
//
// [SecretLookup] and [CertificateLookup] supply credentials for MAC- and
// signature-protected messages respectively. See the Authentication section.
//
// [Server.Err] reports a configuration error such as a signer key that does not
// match its certificate. Such a server answers every request with systemFailure
// rather than issuing certificates it cannot protect, so check it at startup.
//
// # Optional interfaces
//
// CAs may implement additional optional interfaces:
//
//   - [PendingChecker]: asynchronous issuance and revocation with polling.
//   - [WaitingExpirer]: notification when a client stops polling for a waiting request.
//   - [CertificateConfirmer]: notification when a client accepts or rejects a certificate.
//   - [Revoker]: revocation requests (rr).
//   - [RevocationAuthorizer]: revocation by signers other than the certificate holder.
//   - [CACertificatesProvider], [RootCAUpdateProvider], [CertReqTemplateProvider]
//     and [CRLProvider]: general messages (genm), described under Support messages.
//
// # Asynchronous issuance (polling)
//
// When a CA cannot issue immediately (pending approval, HSM queue), implement
// [PendingChecker]:
//
//	type PendingChecker interface {
//	    CheckPending(ctx context.Context, pollRef string, sender *SenderIdentity) (*Response, error)
//	}
//
// Flow (RFC 9483 §4.4):
//
//  1. Client sends ir, cr, kur or p10cr.
//  2. [CA.IssueCertificate] returns a [WaitingResponse]:
//     return &Response{Waiting: &WaitingResponse{CheckAfter: 30*time.Second, PollRef: "job-123"}}, nil
//  3. Server stores the pollRef and replies with a "waiting" status. Reason
//     becomes its statusString.
//  4. Client polls after [WaitingResponse.CheckAfter].
//  5. Server calls [PendingChecker.CheckPending] with the stored pollRef.
//  6. CA returns the issued certificate, another [WaitingResponse] or an
//     [*Error] that rejects the request.
//
// A rejection reaches the client in the ip, cp or kup it would have got at
// once (RFC 9810 §5.3.22), with the request's certReqId, and ends the
// transaction. The final response grants implicit confirmation when the delayed
// request asked for it, and repeats the senderNonce of the last pollReq, as
// OpenSSL expects.
//
// The pollRep advertises CheckAfter in whole seconds, at least one. A pollReq
// that arrives earlier gets another pollRep with the time left and does not
// reach the CA. A pollReq names the request by its certReqId or by -1 for the
// whole message. A p10cr may also be polled with 0. Any other value is refused.
// A pollReq must repeat the senderNonce of the previous response in its
// recipNonce. [WithOptionalPollReqRecipNonce] accepts one that leaves it out.
//
// A revocation waits when [Revoker.RevokeCertificate] or
// [RevocationAuthorizer.AuthorizeRevocation] returns a [*WaitingError]. The
// client gets an error message with status waiting, polls with certReqId -1 and
// receives an rp once CheckPending returns without error. A general message is
// never delayed.
//
// The pollRef is an opaque string the CA uses to correlate with its backend
// (a database ID, job reference, or any identifier). The waiting state itself
// lives in the server, so replicas share it only through
// [Server.SnapshotTransactions].
//
// A client that stops polling leaves its request waiting until
// [Server.CleanupExpired] removes it after [WithWaitingLifetime], 24 hours
// after its last message by default. A CA that implements [WaitingExpirer] is
// told the pollRef. How long a request may wait for a decision is the CA's
// policy: CheckPending rejects a request the CA no longer wants to decide.
//
// # Certificate confirmation
//
// Implement [CertificateConfirmer] to be notified when a client accepts or
// rejects a certificate ([ConfirmAccepted], [ConfirmRejected]), when implicit
// confirm is granted ([ConfirmImplicit]), or when the transaction expires
// ([ConfirmExpired]). The ref parameter echoes [Response.IssueRef] set during
// [CA.IssueCertificate] for correlation.
//
// For the encrypted certificate method the certConf is the proof of possession.
// [POPMethodFromContext] returns [POPEncryptedCertificate] in every call for
// such a certificate, which the CA should revoke unless it hears
// [ConfirmAccepted]. A certConf with the wrong hash is refused with badPOP and
// leaves the transaction open until a right one or [ConfirmExpired].
//
// Every CertStatus in a certConf must carry the certHash and certReqId of the
// issued certificate. All of them must accept it or all must reject it. The
// CA is then notified once. For a p10cr the certReqId may be -1 or 0, because
// RFC 9810 and RFC 9483 disagree on it and deployed peers use both. A certConf
// without any CertStatus rejects the certificate (RFC 9810 §5.3.18) and reaches
// the CA as [ConfirmRejected].
//
// A certConf must repeat the senderNonce of the certificate response in its
// recipNonce. [WithOptionalCertConfRecipNonce] accepts a certConf that leaves
// recipNonce out. One that carries a different value is still rejected.
//
// A certConf must use the credentials of the request (RFC 9483 §4.1.1),
// because the transaction is found by them. A key update that keeps its key is
// therefore confirmed with the old certificate. A certConf signed with the
// newly issued certificate is rejected as an unknown transaction.
//
// # Revocation
//
// Implement [Revoker] to accept revocation requests (RFC 9483 §4.2). Without it
// the server rejects every rr with badRequest.
//
//	func (c *myCA) RevokeCertificate(ctx context.Context, req *server.RevocationRequest,
//	    sender *server.SenderIdentity) error {
//
//	    cert := c.store.Find(req.Issuer, req.SerialNumber)
//	    if err := req.Match(cert); err != nil {
//	        return err // badCertId
//	    }
//	    if c.store.IsRevoked(cert) {
//	        return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailCertRevoked}
//	    }
//	    return c.store.Revoke(cert, req.Reason)
//	}
//
// The server authorizes the request before calling RevokeCertificate. By
// default only the certificate being revoked may sign it, as RFC 9483 §4.2
// requires. Requests signed by anyone else, such as a registration authority
// (RFC 9483 §5.3.2), are rejected with notAuthorized unless the CA implements
// [RevocationAuthorizer] and approves them. The same applies to MAC-protected
// requests, which [LightweightPolicy] refuses unless [WithMACRevocation] is set.
//
// The server answers with an rp that reports either acceptance or the
// rejection RevokeCertificate returned. A revocation that has to wait, for
// example for an operator, returns a [*WaitingError] and is decided through
// [PendingChecker], as described under Asynchronous issuance. A custom
// [Handler] delays an rr by returning a [WaitingResponse] with a PollRef.
//
// # Support messages
//
// RFC 9483 §4.3 defines general messages that ask the CA for information: its
// CA certificates, an update of the root CA certificate, a certificate request
// template or a newer CRL. Implement the matching provider to answer each one.
// The server answers a genm with a genp, and lists every requested type without
// a provider in an unsupportedOIDs item (RFC 9810 §5.3.19.7). The client then
// knows the CA does not offer it, rather than reading an absent value as "no
// update".
//
//	func (c *myCA) LatestCRL(ctx context.Context, source pkicmp.CRLSource,
//	    sender *server.SenderIdentity) (*x509.RevocationList, error) {
//
//	    // A zero source asks for the current CRL of the CA's choice.
//	    if !source.IsZero() && !slices.ContainsFunc(source.DirectoryNames(), c.issues) {
//	        return nil, nil // no CRL from this source
//	    }
//	    return c.store.LatestCRL()
//	}
//
// A root CA update must carry newWithOld, the new root certified by the old
// one, and the server checks it with [pkicmp.RootCAKeyUpdate.Verify] before
// sending it. A CRL is sent only if it is newer than the thisUpdate the client
// reported. A general message completes its transaction at once and is never
// delayed, so a custom [Handler] that returns a [WaitingResponse] for a genm
// gets systemFailure. [WithStrictProfileValidation] enforces one item per
// request and an absent value where RFC 9483 defines none.
//
// # Registration authorities
//
// A registration authority (RA) can approve a request by forwarding it unchanged
// inside a nested message that carries the RA's own protection (RFC 9483
// §5.2.2.1). Accept such messages with [WithRAAuthorizer]:
//
//	server.WithRAAuthorizer(server.RAAuthorizerFunc(func(ctx context.Context,
//	    ra *server.SenderIdentity, req *pkicmp.PKIMessage, sender *server.SenderIdentity) error {
//
//	    if ra.Certificate == nil || !ra.Certificate.Equal(raCert) {
//	        return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}
//	    }
//	    return nil
//	}))
//
// The server verifies the nested message, then handles the forwarded request as
// if the end entity had sent it directly. The request's own protection is
// verified and the response is protected for the end entity, uses its pvno and
// is not wrapped in a nested message. The authorizer runs once both protections
// are verified, and [SenderIdentity.RA] tells the CA which RA approved the
// request.
//
// The nested message must copy the transactionID and senderNonce of the request
// it wraps. Problems with the nested message itself, including a refusal by the
// authorizer, are reported to the RA in an error message. Without an authorizer
// nested messages are rejected with badRequest. Batching several messages in
// one nested message (RFC 9483 §5.2.2.2) is not supported and is also rejected
// with badRequest.
//
// RFC 9483 requires the RA to sign the nested message, while RFC 4210 also
// allows a MAC. The authorizer decides. The example above refuses a MAC, since
// ra.Certificate is nil for one.
//
// # Authentication
//
// The server verifies every message's protection before passing it to the CA or
// Handler. The package does not provide a credential store; it defines the
// [SecretLookup] and [CertificateLookup] interfaces. Provide implementations
// via [WithSecretLookup] and [WithCertificateLookup].
//
// For MAC-protected messages, the server passes the sender DN and senderKID to
// [SecretLookup.LookupSecret]. RFC 9810 §5.1.1 covers two cases:
//
//   - Known sender: sender field carries the name, senderKID SHOULD be set.
//     Either or both may be used to locate the shared secret.
//   - Unknown sender (initial enrollment): sender MUST be a NULL-DN and senderKID
//     MUST carry the reference number identifying the shared secret (RFC 4210 §5.1.3.1).
//
// These fields are analogous to a username, with the shared secret as the
// password. Two clients sharing an identifier become indistinguishable, which
// allows certificate hijacking, so provisioning must enforce uniqueness:
//
//	func Register(senderKID, secret []byte) error {
//	    if exists(senderKID) {
//	        return errors.New("senderKID already registered")
//	    }
//	    store[senderKID] = secret
//	}
//
//	func LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error) {
//	    return store[senderKID]
//	}
//
// The server keeps a MAC client's transactions apart from other clients by its
// senderKID and sender name together, so clients that send only a name, as
// RFC 4210 §5.1.1 allows, do not share transactions or quotas.
//
// For signature-protected messages (e.g., KUR), the client's identity is its
// certificate. The sender DN is only a lookup key: the server resolves a
// candidate certificate from its store and verifies the signature against it, so
// a client that lies about the DN either finds nothing or fails the signature
// check. Trust comes from the store plus proof of the private key.
//
//	func LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
//	    return certStore[issuer, subject]
//	}
//
// A request protected with an algorithm the server does not implement is
// rejected with badAlg. This includes SHA-1 signatures, which RFC 9481 §7.1
// deprecates. [WithSHA1Signatures] accepts them from RFC 4210 era devices.
//
// A MAC-protected request whose iteration count lies outside
// [WithMACIterationLimits] is rejected with badMessageCheck and the status text
// "MAC protection parameters not accepted", before any key derivation. The
// default range is [pkicmp.DefaultMinMACIterationCount] to
// [pkicmp.DefaultMaxMACIterationCount].
//
// # Middleware
//
// [NewCAServer] takes a handler wrapper implementing authorization and request
// validation. The server authenticates (verifies protection) but delegates
// authorization, audit logging, metrics and rate limiting to wrappers. Without
// one, any authenticated client could request any certificate for any name.
//
// Two checks are never delegated, because they establish that a request is what
// it claims to be rather than whether a site wants to grant it, and a nil policy
// would otherwise skip them:
//
//   - Proof of possession, so that a certificate is never issued for a public
//     key the requester did not prove holding (RFC 4211 §4, RFC 9483 §5.1.1).
//     For a p10cr this is the CSR self-signature. By default only a signature
//     proves possession, so a CRMF request without a public key or for a key
//     that cannot sign, such as ML-KEM, is rejected. [WithSignatureProtectionPOP]
//     also accepts a CRMF request without proof whose protection signature was
//     made with the requested key. [WithEncryptedCertificatePOP] and
//     [WithChallengeResponsePOP] accept the indirect methods of RFC 9810
//     §5.2.8.3 for RSA, ECDH and ML-KEM keys. X25519 is refused with badAlg.
//   - Rejection of a BasicConstraints extension that cannot be decoded, so that
//     no extension reaches [CA.IssueCertificate] that the checks above did not
//     understand.
//
// [LightweightPolicy] enforces the RFC 9483 Lightweight CMP Profile:
//
//   - Verifies Proof-of-Possession (POP) on CRMF requests.
//   - Requires KUR to use signature protection (not MAC).
//   - Requires a MAC-protected message to identify its shared secret through
//     either the sender name or senderKID.
//   - Requires a certificate template to name the entity in its subject, or
//     in a requested subjectAltName with a NULL-DN subject (RFC 9483 §4.1.1).
//   - Rejects requests for CA certificates.
//   - Validates BasicConstraints path-length.
//   - Requires a revocation request to use signature protection and to carry
//     a reasonCode.
//
// Options relax some of these rules for deployed clients that break them:
// [WithOptionalSubject] admits a template that leaves out the subject field
// and names the entity in a requested subjectAltName. [WithOptionalRevocationReason] and [WithMACRevocation] admit
// a revocation request without a reasonCode or with MAC protection.
// [WithPoposkInputVariants] and [WithOptionalRevocationIssuer] relax checks
// the server makes with or without the policy.
//
// Some RFC 9483 rules govern how a peer constructs a message rather than how
// this server authenticates it, and deployed clients break them. Those are off
// by default, behind [WithStrictProfileValidation].
//
// [WithMessageTimeTolerance] enforces the RFC 9483 §3.5 freshness check. It is
// separate from [WithStrictProfileValidation] because no single tolerance is
// safe for every deployment.
//
// Add custom authorization policy and logging using [MiddlewareChain].
// In this setup, `myPolicy()` runs before `LightweightPolicy()` to quickly reject
// unauthorized requests before performing verification against lightweight policy:
//
//	srv := server.NewCAServer(ca,
//	    server.MiddlewareChain(auditLog(logger), myPolicy(), server.LightweightPolicy()),
//	    server.WithSigner(caKey, caCert),
//	    server.WithExtraCerts([]*x509.Certificate{caCert}),
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//
// A middleware wraps a [Handler] to reject, inspect, or pass through requests:
//
//	func myPolicy() func(server.Handler) server.Handler {
//	    return func(next server.Handler) server.Handler {
//	        return server.HandlerFunc(func(
//	            ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity,
//	        ) (*server.Response, error) {
//	            if !isAllowed(sender) {
//	                return nil, &server.Error{
//	                    Status:      pkicmp.StatusRejection,
//	                    FailureInfo: pkicmp.FailNotAuthorized,
//	                    StatusText:  "not authorized",
//	                }
//	            }
//	            return next.HandleCMP(ctx, msg, sender)
//	        })
//	    }
//	}
//
//	func auditLog(logger *slog.Logger) func(server.Handler) server.Handler {
//	    return func(next server.Handler) server.Handler {
//	        return server.HandlerFunc(func(
//	            ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity,
//	        ) (*server.Response, error) {
//	            logger.Info("CMP request received", "type", msg.Body.Type, "sender", sender.Sender)
//	            resp, err := next.HandleCMP(ctx, msg, sender)
//	            if err != nil {
//	                logger.Error("CMP request failed", "err", err)
//	            } else {
//	                logger.Info("CMP request succeeded")
//	            }
//	            return resp, err
//	        })
//	    }
//	}
//
// # Multiple CAs
//
// Each [Server] serves a single CA. To support multiple CAs, create separate
// Server instances and route by URL path. RFC 9483 §6.1 defines the well-known
// URI structure: /.well-known/cmp/p/<name>
//
//	mux := http.NewServeMux()
//	mux.Handle("/.well-known/cmp/p/ca1", server.NewCAServer(ca1,
//	    server.LightweightPolicy(),
//	    server.WithSigner(ca1Key, ca1Cert),
//	    server.WithExtraCerts([]*x509.Certificate{ca1Cert}),
//	    server.WithSecretLookup(ca1SecretLookup),
//	    server.WithCertificateLookup(ca1CertLookup),
//	))
//	mux.Handle("/.well-known/cmp/p/ca2", server.NewCAServer(ca2,
//	    server.LightweightPolicy(),
//	    server.WithSigner(ca2Key, ca2Cert),
//	    server.WithExtraCerts([]*x509.Certificate{ca2Cert}),
//	    server.WithSecretLookup(ca2SecretLookup),
//	    server.WithCertificateLookup(ca2CertLookup),
//	))
//	http.ListenAndServe(":8080", mux)
//
// # Transaction management
//
// The server tracks multi-message exchanges (IR→IP->CertConf->PKIConf and polling
// flows). Transactions are keyed by a composite of the client's cryptographically
// verified credentials and the transactionID, preventing cross-client hijacking
// (RFC 9810 §5.1.1).
//
// A client may omit the transactionID from its first request. The server then
// assigns a random 128-bit one and returns it in the response, as RFC 4210 and
// RFC 9810 §5.1.1 require. [WithStrictProfileValidation] rejects such requests
// instead, following RFC 9483 §3.5.
//
// To prevent resource exhaustion, the server enforces transaction caps:
//
//   - [WithMaxTransactions]: global cap on concurrent transactions (default 10000).
//   - [WithMaxTransactionsPerCredential]: per-client cap (default 100).
//
// When limits are exceeded, new requests are rejected with failInfo systemUnavail.
//
// [WithImplicitConfirm] eliminates the certConf round-trip when both server and
// client agree.
//
// Call [Server.CleanupExpired] periodically to remove completed and stale
// transactions:
//
//	go func() {
//	    for range time.Tick(time.Minute) {
//	        srv.CleanupExpired()
//	    }
//	}()
//
// Entries expire based on last activity time. [WithConfirmWaitTime] controls
// the expiry (default 10 seconds), except for waiting requests, which
// [WithWaitingLifetime] controls (default 24 hours).
//
// # Durable transaction recovery
//
// [Server.SnapshotTransactions] saves active, waiting, issued and completed
// protocol state. [Server.RestoreTransactions] loads it into a fresh server with
// the same response-signing certificate before that server accepts requests.
// Original nonces, credential binding, timestamps and MAC parameters survive.
//
// The host must exclude concurrent ServeHTTP, CleanupExpired, snapshot and
// restore calls. Persist a successful response and its snapshot before sending
// that response to the peer. Commit issuance records and credential usage in
// the same durable operation. The library does not provide database transactions
// or a response cache. Exact request retries need a host-managed response cache
// to avoid issuing another certificate or reusing a completed transaction ID.
//
// Treat snapshots as trusted private server data, never client input. They have
// a versioned format and contain no authentication secrets or signing keys,
// unless the application's IssueRef includes them. IssueRef must be JSON
// serializable. Supply a decoder to RestoreTransactions when its original Go
// type matters. A nil decoder uses the standard encoding/json value types.
// Restore rejects a different signer, invalid state and configured capacity
// overruns without replacing existing state. Snapshots are limited to 64 MiB.
// Expiration timestamps are preserved. The host still calls CleanupExpired
// according to its configured confirmation deadline and waiting lifetime.
package server
