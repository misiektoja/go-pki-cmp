package client

import (
	"fmt"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// encodeRequest returns the DER of the protected request msg. With
// [WithRegistrationAuthority] it is wrapped in a nested message signed by the
// registration authority.
func (c *Client) encodeRequest(msg *pkicmp.PKIMessage) ([]byte, error) {
	if c.raCreds == nil {
		return msg.MarshalBinary()
	}
	nested := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(msg), pkicmp.MessageOptions{
		Sender:    certificateSubject(c.raCreds.Certificate()),
		Recipient: msg.Header.Recipient,
		// RFC 9483 §5.2.2.1: copying both values binds the RA protection to
		// the request. The recipNonce lets a receiver that checks it match the
		// nested message to the transaction as well.
		TransactionID: msg.Header.TransactionID,
		SenderNonce:   msg.Header.SenderNonce,
		RecipNonce:    msg.Header.RecipNonce,
	})
	nested.Header.PVNO = msg.Header.PVNO
	if err := c.raCreds.Protect(nested); err != nil {
		return nil, fmt.Errorf("protect nested message: %w", err)
	}
	return nested.MarshalBinary()
}
