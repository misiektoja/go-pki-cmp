package server_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// serialCA revokes only certificates it issued and authenticates signers from
// a separate list, as a CA does when devices sign with vendor certificates.
type serialCA struct {
	issued   []*x509.Certificate
	signers  []*x509.Certificate
	allow    func(*server.SenderIdentity) bool
	request  *server.RevocationRequest
	sender   *server.SenderIdentity
	revoked  []*x509.Certificate
	reasons  []pkicmp.CRLReason
	revokeCt int
}

// IssueCertificate refuses every request, since these tests exercise revocation only.
func (c *serialCA) IssueCertificate(context.Context, server.RequestType, *x509.Certificate, *server.SenderIdentity) (*server.Response, error) {
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
}

// LookupCertificate finds a signer by its subject name.
func (c *serialCA) LookupCertificate(_ pkix.Name, subject pkix.Name, _ []byte) (*x509.Certificate, error) {
	for _, cert := range c.signers {
		if cert.Subject.String() == subject.String() {
			return cert, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// AuthorizeRevocation allows the senders c.allow accepts.
func (c *serialCA) AuthorizeRevocation(_ context.Context, _ *server.RevocationRequest, sender *server.SenderIdentity) error {
	if c.allow != nil && c.allow(sender) {
		return nil
	}
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "not authorized"}
}

// RevokeCertificate revokes the one issued certificate the request matches.
func (c *serialCA) RevokeCertificate(_ context.Context, req *server.RevocationRequest, sender *server.SenderIdentity) error {
	c.revokeCt++
	c.request, c.sender = req, sender
	var found []*x509.Certificate
	for _, cert := range c.issued {
		if req.Match(cert) == nil {
			found = append(found, cert)
		}
	}
	if len(found) != 1 {
		return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertId, StatusText: "certificate not found"}
	}
	c.revoked = append(c.revoked, found[0])
	c.reasons = append(c.reasons, req.Reason)
	return nil
}

// newSerialCA returns a CA that issued f's certificates and trusts f's entities as signers.
func newSerialCA(f *revocationFixture) *serialCA {
	return &serialCA{
		issued:  []*x509.Certificate{f.ee.cert, f.ra.cert},
		signers: []*x509.Certificate{f.ee.cert, f.ra.cert},
	}
}

// macRR returns a MAC-protected rr for cert.
func macRR(t *testing.T, cert *x509.Certificate) *pkicmp.PKIMessage {
	t.Helper()
	msg := pkicmp.NewPKIMessage(pkicmp.NewRRBody(&pkicmp.RevReqContent{revDetails(t, cert, pkicmp.CRLReasonKeyCompromise)}), macMessageOpts())
	protectMAC(msg, []byte("revocation-secret"))
	return msg
}

// WithOptionalRevocationReason reads a request without reasonCode as unspecified.
func TestRevocationWithOptionalReason(t *testing.T) {
	withoutReason := func(f *revocationFixture) pkicmp.RevReqContent {
		d := revDetails(t, f.ee.cert, pkicmp.CRLReasonKeyCompromise)
		d.CRLEntryDetails = nil
		return pkicmp.RevReqContent{d}
	}

	t.Run("Accepted", func(t *testing.T) {
		f := newRevocationFixture(t)
		ts := f.serve(t, f.backend, server.LightweightPolicy(), server.WithOptionalRevocationReason())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, withoutReason(f), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status)
		reason, ok := f.backend.revoked[f.ee.cert.SerialNumber.String()]
		require.True(t, ok)
		assert.Equal(t, pkicmp.CRLReasonUnspecified, reason)
	})

	t.Run("StrictProfileRequiresReason", func(t *testing.T) {
		f := newRevocationFixture(t)
		ts := f.serve(t, f.backend, server.LightweightPolicy(), server.WithOptionalRevocationReason(), server.WithStrictProfileValidation())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, withoutReason(f), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.FailBadRequest, si.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"reasonCode required"}, si.StatusString)
		assert.Zero(t, f.backend.calls)
	})
}

// WithOptionalRevocationIssuer accepts a request naming only a serial number,
// without letting a signer revoke another issuer's certificate with that serial.
func TestRevocationWithOptionalIssuer(t *testing.T) {
	serialOnly := func(cert *x509.Certificate) pkicmp.RevReqContent {
		d := revDetails(t, cert, pkicmp.CRLReasonSuperseded)
		d.CertDetails.Issuer = nil
		return pkicmp.RevReqContent{d}
	}

	t.Run("OwnCertificate", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithOptionalRevocationIssuer())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, serialOnly(f.ee.cert), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
		require.Len(t, ca.revoked, 1)
		assert.True(t, ca.revoked[0].Equal(f.ee.cert))
		// The issuer is taken from the signer, so the CA sees a complete request.
		assert.Equal(t, f.ee.cert.RawIssuer, ca.request.RawIssuer)
		assert.Equal(t, "Revocation CA", ca.request.Issuer.CommonName)
	})

	t.Run("SameSerialFromAnotherIssuer", func(t *testing.T) {
		f := newRevocationFixture(t)
		vendorCA := &certyaml.Certificate{Subject: "CN=Vendor CA"}
		vendor := &certyaml.Certificate{Subject: "CN=vendor-device", Issuer: vendorCA, SerialNumber: f.ee.cert.SerialNumber}
		vendorCert, err := vendor.X509Certificate()
		require.NoError(t, err)
		vendorKey, err := vendor.PrivateKey()
		require.NoError(t, err)
		ca := newSerialCA(f)
		ca.signers = append(ca.signers, &vendorCert)
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithOptionalRevocationIssuer())

		// The vendor certificate names its own serial number, which this CA also
		// issued to the end entity. It revokes the vendor certificate or nothing.
		signer := revocationEntity{cert: &vendorCert, key: vendorKey}
		si := rpStatus(t, postCMP(t, ts, signedRR(t, signer, serialOnly(&vendorCert), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.FailBadCertId, si.FailInfo)
		assert.Empty(t, ca.revoked)
		assert.Equal(t, vendorCert.RawIssuer, ca.request.RawIssuer)
	})

	t.Run("AuthorizedSigner", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ca.allow = func(sender *server.SenderIdentity) bool {
			return sender.Certificate != nil && sender.Certificate.Equal(f.ra.cert)
		}
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithOptionalRevocationIssuer())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ra, serialOnly(f.ee.cert), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
		assert.Empty(t, ca.request.RawIssuer, "only the CA can resolve the serial number of another certificate")
		require.Len(t, ca.revoked, 1)
		assert.True(t, ca.revoked[0].Equal(f.ee.cert))
	})

	t.Run("StrictProfileRequiresIssuer", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithOptionalRevocationIssuer(), server.WithStrictProfileValidation())
		si := rpStatus(t, postCMP(t, ts, signedRR(t, f.ee, serialOnly(f.ee.cert), pkicmp.MessageOptions{})))
		assert.Equal(t, pkicmp.FailAddInfoNotAvailable, si.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"issuer required"}, si.StatusString)
		assert.Zero(t, ca.revokeCt)
	})
}

// WithMACRevocation passes a MAC-protected rr to RevocationAuthorizer, never
// treating the shared secret as the certificate holder.
func TestRevocationWithMACRevocationOption(t *testing.T) {
	t.Run("NoAuthorizer", func(t *testing.T) {
		f := newRevocationFixture(t)
		ts := f.serve(t, f.backend, server.LightweightPolicy(), server.WithMACRevocation())
		si := rpStatus(t, postCMP(t, ts, macRR(t, f.ee.cert)))
		assert.Equal(t, pkicmp.FailNotAuthorized, si.FailInfo)
		assert.Zero(t, f.backend.calls)
	})

	t.Run("AuthorizerAllows", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ca.allow = func(sender *server.SenderIdentity) bool { return sender.MACVerified }
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithMACRevocation())
		si := rpStatus(t, postCMP(t, ts, macRR(t, f.ee.cert)))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
		require.Len(t, ca.revoked, 1)
		assert.True(t, ca.revoked[0].Equal(f.ee.cert))
		assert.True(t, ca.sender.MACVerified)
		assert.Equal(t, []byte(testSender.String()), ca.sender.SenderKID)
	})

	t.Run("AuthorizerDenies", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithMACRevocation())
		si := rpStatus(t, postCMP(t, ts, macRR(t, f.ee.cert)))
		assert.Equal(t, pkicmp.FailNotAuthorized, si.FailInfo)
		assert.Zero(t, ca.revokeCt)
	})

	t.Run("StrictProfileRequiresSignature", func(t *testing.T) {
		f := newRevocationFixture(t)
		ca := newSerialCA(f)
		ca.allow = func(sender *server.SenderIdentity) bool { return sender.MACVerified }
		ts := f.serve(t, ca, server.LightweightPolicy(), server.WithCertificateLookup(ca), server.WithMACRevocation(), server.WithStrictProfileValidation())
		si := rpStatus(t, postCMP(t, ts, macRR(t, f.ee.cert)))
		assert.Equal(t, pkicmp.FailWrongIntegrity, si.FailInfo)
		assert.Zero(t, ca.revokeCt)
	})
}
