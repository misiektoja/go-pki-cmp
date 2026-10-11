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

// rejection returns an Error that rejects the request with failInfo and StatusText text.
func rejection(failInfo pkicmp.PKIFailureInfo, text string) *Error {
	return &Error{Status: pkicmp.StatusRejection, FailureInfo: failInfo, StatusText: text}
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
