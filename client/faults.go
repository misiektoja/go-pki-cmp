package client

import (
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// MessageMutator changes a message the client is about to send. msg is the
// message and answered is the response it answers. answered is nil for the
// first request of an operation and for the first pollReq of
// [Client.ResumeEnrollment], whose response the client does not keep. An error
// stops the operation before msg is sent.
//
// It is a test aid for [WithMessageMutator] and [WithProtectedMessageMutator].
type MessageMutator func(msg, answered *pkicmp.PKIMessage) error

// messageHooks holds the test aids that change outgoing messages. A nil
// *messageHooks changes nothing.
type messageHooks struct {
	beforeProtection []MessageMutator
	afterProtection  []MessageMutator
}

// WithCertConfStatus sends status as the statusInfo of the certConf that
// confirms an issued certificate. Without it the statusInfo is left out, which
// accepts the certificate (RFC 9483 §4.1.1).
//
// It is a test aid for checking how a CA handles a certificate the end entity
// refuses. With status rejection RFC 9483 §3.6.1 and §4.1.1 ask the CA to
// answer with pkiConf and to treat the certificate as rejected. The client
// checks the certificate as usual. When the CA answers with pkiConf the call
// returns it like an accepted one. A certificate the client refuses itself
// gets the client's own rejection. A grant of implicit confirmation sends no
// certConf. Do not use it in production.
func WithCertConfStatus(status *pkicmp.PKIStatusInfo) RequestOption {
	return func(o *requestOptions) { o.certConfStatus = status }
}

// WithMessageMutator calls mutate on every message the client sends in the
// operation: the first request and any popdecr, pollReq and certConf. It runs
// after the header and body are built and before the message is protected, so
// the protection covers the change. Each call adds a mutator. The mutators
// run in the order of the options.
//
// It is a test aid for checking how a server handles messages that break
// RFC 9483, such as a certConf with a wrong certHash or a stale recipNonce.
// The client verifies each response against the message as changed, so a
// server that echoes a changed transactionID or senderNonce still passes
// those checks. Do not use it in production.
func WithMessageMutator(mutate MessageMutator) RequestOption {
	return func(o *requestOptions) {
		o.hooks.beforeProtection = append(o.hooks.beforeProtection, mutate)
	}
}

// WithProtectedMessageMutator calls mutate on every message the client sends
// in the operation, as [WithMessageMutator] does, but after the message is
// protected and before it is encoded or wrapped in the nested message of
// [WithRegistrationAuthority]. Any change but one to the protection itself
// then breaks the protection.
//
// It is a test aid, for example for removing the protection to check that a
// server refuses an unprotected message (RFC 9483 §3.5). Do not use it in
// production.
func WithProtectedMessageMutator(mutate MessageMutator) RequestOption {
	return func(o *requestOptions) {
		o.hooks.afterProtection = append(o.hooks.afterProtection, mutate)
	}
}

// protect protects msg with creds and runs the mutators of h around the
// protection. answered is the response msg answers, nil for the first
// request. name names the message in errors.
func (h *messageHooks) protect(msg, answered *pkicmp.PKIMessage, creds pkicmp.Credentials, name string) error {
	if h != nil {
		if err := runMutators(h.beforeProtection, msg, answered); err != nil {
			return &Error{Op: "change " + name, Err: err}
		}
	}
	if err := creds.Protect(msg); err != nil {
		return &Error{Op: "protect " + name, Err: err}
	}
	if h != nil {
		if err := runMutators(h.afterProtection, msg, answered); err != nil {
			return &Error{Op: "change protected " + name, Err: err}
		}
	}
	return nil
}

// runMutators applies mutators to msg in order and stops at the first error.
func runMutators(mutators []MessageMutator, msg, answered *pkicmp.PKIMessage) error {
	for _, mutate := range mutators {
		if err := mutate(msg, answered); err != nil {
			return err
		}
	}
	return nil
}
