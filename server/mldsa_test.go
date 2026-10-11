package server

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// TestMLDSARequiresProof prevents issuance for signature keys without verified possession.
func TestMLDSARequiresProof(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: pkicmp.CertTemplate{PublicKey: pub}}}
			for _, proof := range []bool{false, true} {
				if proof {
					if err := req.GeneratePOP(key); err != nil {
						t.Fatal(err)
					}
				}
				msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), pkicmp.MessageOptions{})
				der, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := pkicmp.ParsePKIMessage(der)
				if err != nil {
					t.Fatal(err)
				}
				err = enforceProofOfPossession(context.Background(), parsed, nil)
				if proof && err != nil {
					t.Fatal(err)
				}
				if !proof {
					var status *Error
					if !errors.As(err, &status) || status.FailureInfo != pkicmp.FailBadPOP {
						t.Fatalf("missing proof accepted: %v", err)
					}
				}
			}
		})
	}
}
