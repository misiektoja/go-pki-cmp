package server

import (
	"errors"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Error can be returned by Handler to control the CMP error response.
//
// Any other error becomes a bare systemFailure. Its text is not sent to the
// peer, so returning an error carrying internal detail discloses nothing. Put
// anything the peer should see in StatusText.
type Error struct {
	// Status is the PKI status code for the response.
	Status pkicmp.PKIStatus
	// FailureInfo gives machine-readable reason bits.
	FailureInfo pkicmp.PKIFailureInfo
	// StatusText is an optional human-readable explanation.
	StatusText string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("server: status %s", e.Status)
	if e.FailureInfo != 0 {
		msg += fmt.Sprintf(", failInfo: %s", e.FailureInfo)
	}
	if e.StatusText != "" {
		msg += fmt.Sprintf(": %s", e.StatusText)
	}
	return msg
}

// WaitingError delays the answer to a revocation request (RFC 9483 §4.4).
// Return it from [Revoker.RevokeCertificate] or
// [RevocationAuthorizer.AuthorizeRevocation] when the decision has to wait, for
// example for an operator. The client gets an error message with status
// waiting and polls. Each poll reaches [PendingChecker.CheckPending] with the
// PollRef, which must not be empty.
type WaitingError struct {
	WaitingResponse
}

// Error describes the delay without disclosing the pollRef.
func (e *WaitingError) Error() string {
	return "server: request is waiting"
}

// rejection returns an Error that rejects the request with failInfo and StatusText text.
func rejection(failInfo pkicmp.PKIFailureInfo, text string) *Error {
	return &Error{Status: pkicmp.StatusRejection, FailureInfo: failInfo, StatusText: text}
}

// statusText returns the statusString for a refusal the server found itself:
// the StatusText of an [Error], whose Error method prefixes it for Go callers,
// or the message of any other error.
func statusText(err error) pkicmp.PKIFreeText {
	if se, ok := errors.AsType[*Error](err); ok {
		if se.StatusText == "" {
			return nil
		}
		return pkicmp.PKIFreeText{se.StatusText}
	}
	return pkicmp.PKIFreeText{err.Error()}
}

// errorToStatusInfo maps a handler error to PKIStatusInfo for CMP responses.
// Only the text a Handler put in [Error.StatusText] reaches the peer, so an
// error carrying internal detail is not disclosed by returning it.
func errorToStatusInfo(err error) pkicmp.PKIStatusInfo {
	if err == nil {
		return pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	}
	if se, ok := errors.AsType[*Error](err); ok {
		si := pkicmp.PKIStatusInfo{
			Status:   se.Status,
			FailInfo: se.FailureInfo,
		}
		if se.StatusText != "" {
			si.StatusString = pkicmp.PKIFreeText{se.StatusText}
		}
		return si
	}
	// Internal error details stay server-side.
	return pkicmp.PKIStatusInfo{
		Status:   pkicmp.StatusRejection,
		FailInfo: pkicmp.FailSystemFailure,
	}
}
