package server

import (
	"bytes"
	"context"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// RAAuthorizer decides whether a registration authority may forward requests inside a nested message.
//
// RFC 9483 §5.2.2.1 lets a registration authority (RA) approve a request by
// wrapping it unchanged in a nested message that carries the RA's own
// protection. The server verifies both protections, with [WithSecretLookup] or
// [WithCertificateLookup], before it asks the authorizer. Without an authorizer,
// set with [WithRAAuthorizer], nested messages are rejected with badRequest.
type RAAuthorizer interface {
	// AuthorizeRA decides whether ra may forward req, a request that sender
	// protected. Return nil to accept it, or an [*Error], normally with
	// notAuthorized, to refuse it. The refusal is sent to the RA in an error
	// message.
	//
	// A verified protection proves only who sent a message. Every end entity
	// with a certificate or shared secret can produce a valid nested message,
	// so identify the RA itself, for example by comparing ra.Certificate with
	// the RA certificates you trust.
	//
	// RFC 9483 requires the RA to sign the nested message, while RFC 4210 also
	// allows a MAC. ra.MACVerified reports a MAC. Refuse it with wrongIntegrity
	// to follow the Lightweight CMP Profile.
	//
	// The method is called for every forwarded message, including certConf and
	// pollReq. On acceptance the Handler receives sender with RA set.
	AuthorizeRA(ctx context.Context, ra *SenderIdentity, req *pkicmp.PKIMessage, sender *SenderIdentity) error
}

// RAAuthorizerFunc adapts a function to the RAAuthorizer interface.
type RAAuthorizerFunc func(
	ctx context.Context, ra *SenderIdentity, req *pkicmp.PKIMessage, sender *SenderIdentity,
) error

// AuthorizeRA calls f(ctx, ra, req, sender).
func (f RAAuthorizerFunc) AuthorizeRA(ctx context.Context, ra *SenderIdentity, req *pkicmp.PKIMessage, sender *SenderIdentity) error {
	return f(ctx, ra, req, sender)
}

// forwarding records the verified nested message that carried a request.
type forwarding struct {
	msg *pkicmp.PKIMessage
	ra  *SenderIdentity
}

// handleNested checks that a verified nested message wraps a single forwarded request and answers that request.
//
// The answer is the plain response to the inner request, as RFC 9483 §5.2.2.1
// requires. Problems with the nested message itself are reported to the RA in an
// error message (RFC 9483 §3.6.2).
func (s *Server) handleNested(ctx context.Context, msg *pkicmp.PKIMessage, ra *SenderIdentity) *pkicmp.PKIMessage {
	reject := func(failInfo pkicmp.PKIFailureInfo, text string) *pkicmp.PKIMessage {
		return s.buildErrorResponse(msg, ra, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     failInfo,
			StatusString: pkicmp.PKIFreeText{text},
		})
	}
	if s.cfg.raAuthorizer == nil {
		return reject(pkicmp.FailBadRequest, "nested messages not accepted")
	}
	inner, err := msg.Body.Nested()
	if err != nil {
		return reject(pkicmp.FailBadDataFormat, "invalid nested message")
	}
	// Batching (RFC 9483 §5.2.2.2) needs a nested response, which is not
	// implemented. A batch also has its own transactionID, so a batch of one
	// is refused by the check below.
	if len(inner) != 1 {
		return reject(pkicmp.FailBadRequest, "batched messages not supported")
	}
	req := inner[0]
	if req.Body.Type == pkicmp.BodyTypeNested {
		return reject(pkicmp.FailBadRequest, "nested message inside a nested message")
	}
	// RFC 9483 §5.2.2.1: the RA copies both values from the request it wraps,
	// which binds its protection to that request.
	if !bytes.Equal(msg.Header.TransactionID, req.Header.TransactionID) {
		return reject(pkicmp.FailBadRequest, "transactionID differs from the forwarded message")
	}
	if !bytes.Equal(msg.Header.SenderNonce, req.Header.SenderNonce) {
		return reject(pkicmp.FailBadSenderNonce, "senderNonce differs from the forwarded message")
	}
	return s.process(ctx, req, &forwarding{msg: msg, ra: ra})
}
