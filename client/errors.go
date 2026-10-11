package client

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// Error indicates a CMP client operational failure.
type Error struct {
	Op  string // operation that failed (e.g., "verify response", "HTTP request")
	Err error  // optional wrapped error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cmp: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("cmp: %s", e.Op)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// ConfirmationError reports that the CA issued Certificate but the certConf
// exchange that confirms it failed. The CA may keep the certificate or revoke
// it as unconfirmed (RFC 9483 §4.1.1), so a caller must not assume either
// outcome, and retrying the request may issue a second certificate. Err is
// the failure, so [errors.As] still finds a [pkicmp.PKIStatusError] or an
// [UnverifiedStatusError] from the CA's answer.
type ConfirmationError struct {
	// Certificate is the certificate the CA issued.
	Certificate *x509.Certificate
	// Err is why the confirmation failed.
	Err error
}

func (e *ConfirmationError) Error() string {
	return fmt.Sprintf("cmp: certConf: %v", e.Err)
}

func (e *ConfirmationError) Unwrap() error {
	return e.Err
}

// UnverifiedStatusError reports the status from an error message the client
// could not verify, which happens when only a shared secret is configured and
// the CA signed the error as RFC 9810 §5.3.21 requires. The exchange still
// fails; the status is surfaced because a rejection such as transactionIdInUse
// is what tells an operator what to do next.
//
// None of it is authenticated: any peer answering the request chooses these
// values. Log them, do not act on them, and configure [WithTrustedCAs] where an
// anchor exists. It does not wrap a [pkicmp.PKIStatusError], so
// [pkicmp.HasFailure] still reports only authenticated failure bits.
type UnverifiedStatusError struct {
	// Status is the unauthenticated status the peer claimed.
	Status pkicmp.PKIStatus
	// StatusString is the unauthenticated free text the peer supplied, joined
	// into one string. It is peer-controlled and unvalidated, so it is left out
	// of the error text: escape it before writing it to a log or a terminal.
	StatusString string
	// FailInfo holds the unauthenticated failure bits the peer claimed.
	FailInfo pkicmp.PKIFailureInfo
	// Err is the verification failure that made the status untrustworthy.
	Err error
}

func (e *UnverifiedStatusError) Error() string {
	msg := fmt.Sprintf("cmp: unverified status %s", e.Status)
	if e.FailInfo != 0 {
		msg += fmt.Sprintf(", failInfo: %s", e.FailInfo)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(": %v", e.Err)
	}
	return msg
}

func (e *UnverifiedStatusError) Unwrap() error {
	return e.Err
}

// withUnverifiedStatus reports the status of an unverifiable error message alongside the verification failure
func withUnverifiedStatus(msg *pkicmp.PKIMessage, err error) error {
	if msg.Body == nil || msg.Body.Type != pkicmp.BodyTypeError {
		return err
	}
	content, parseErr := msg.Body.Error()
	if parseErr != nil {
		return err
	}
	return &UnverifiedStatusError{
		Status:       content.PKIStatusInfo.Status,
		StatusString: strings.Join(content.PKIStatusInfo.StatusString, "; "),
		FailInfo:     content.PKIStatusInfo.FailInfo,
		Err:          err,
	}
}
