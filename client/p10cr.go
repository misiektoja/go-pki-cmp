package client

import (
	"context"
	"crypto/x509"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// SendP10CR sends a PKCS#10 CSR to the CA (RFC 9810 §5.3.3).
// The message envelope is protected by the provided credentials.
func (c *Client) SendP10CR(ctx context.Context, csrDER []byte, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	// crypto/x509 leaves PublicKey nil for composite ML-DSA and SLH-DSA keys.
	requestedKey, err := pkicmp.ParsePublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	body := pkicmp.NewP10CRBody(csr)
	return c.enroll(ctx, body, pkicmp.BodyTypeCP, creds, ropts, requestedKey, nil)
}
