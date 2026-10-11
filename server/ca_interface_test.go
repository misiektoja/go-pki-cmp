package server_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/misiektoja/go-pki-cmp/server"
)

type issueOnlyCA struct{}

func (c *issueOnlyCA) IssueCertificate(_ context.Context, _ server.RequestType, _ *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	return &server.Response{}, nil
}

func TestNewCAServerAcceptsIssueOnlyCA(t *testing.T) {
	_ = server.NewCAServer(&issueOnlyCA{}, nil)
}
