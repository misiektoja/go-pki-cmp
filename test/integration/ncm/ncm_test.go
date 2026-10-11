//go:build integration

package ncm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestNCMEnrollPasswordBasedMac(t *testing.T) {
	cfg := loadConfig(t)
	creds, opts := cfg.macCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		enrollP10CR(t, cfg, cl, cfg.subject(cfg.enrollmentName("mac")), creds, opts...)
	})
}

func TestNCMEnrollSignature(t *testing.T) {
	cfg := loadConfig(t)
	creds := cfg.signatureCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		enrollP10CR(t, cfg, cl, cfg.subject(cfg.enrollmentName("sig")), creds)
	})
}

// NCM answers a second P10CR for an identity it has already certified with a new certificate. This is
// how a client without key update renews.
func TestNCMReenrollP10CR(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.reenroll {
		t.Skip("NCM_CMP_REENROLL is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		subject := cfg.subject(cfg.enrollmentName("reenroll"))
		firstKey, first := enrollP10CR(t, cfg, cl, subject, creds, opts...)
		secondKey, second := enrollP10CR(t, cfg, cl, subject, creds, opts...)

		assert.NotEqual(t, first[0].SerialNumber, second[0].SerialNumber, "re-enrollment returned the serial number of the first certificate")
		assert.False(t, firstKey.PublicKey.Equal(&secondKey.PublicKey), "re-enrollment reused the first key")
	})
}

func TestNCMKeyUpdate(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.kur {
		t.Skip("NCM_CMP_KUR is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keyUpdate(t, cfg, cl, creds, opts, "kur", newKey)
	})
}

// Updating a certificate for the key it already certifies needs a profile that certifies the same key
// twice. The client names the replaced certificate in the CRMF oldCertID control, which NCM needs once
// a key carries more than one certificate.
func TestNCMKeyUpdateSameKey(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.kurSameKey {
		t.Skip("NCM_CMP_KUR or NCM_CMP_KUR_SAME_KEY is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		keyUpdate(t, cfg, cl, creds, opts, "kur-same", nil)
	})
}

// The certificate being revoked signs the request (RFC 9483 §4.2). Some NCM releases sign the response
// with the issuing CA key without attaching that certificate, so the client is given it out of band.
func TestNCMRevoke(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.revoke {
		t.Skip("NCM_CMP_RR is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachEndpoint(t, func(t *testing.T, connect func(opts ...client.Option) *client.Client) {
		key, chain := enrollP10CR(t, cfg, connect(), cfg.subject(generatedName("rr")), creds, opts...)
		cert, issuer := chain[0], chain[1]
		cl := connect(client.WithServerCerts([]*x509.Certificate{issuer}))
		rrCreds, err := pkicmp.NewSignatureCredentials(key, cert, intermediates(chain)...)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), operationTimeout)
		defer cancel()
		require.NoError(t, cl.SendRR(ctx, cert, pkicmp.CRLReasonCessationOfOperation, rrCreds), "SendRR")

		// Revoking again draws a signed rejection, which has to verify like the acceptance did. The
		// request is now signed by a revoked certificate, so a CA may refuse it as certRevoked or
		// as badMessageCheck. HasFailure reports bits only from a verified message.
		err = cl.SendRR(ctx, cert, pkicmp.CRLReasonCessationOfOperation, rrCreds)
		var statusErr *pkicmp.PKIStatusError
		require.ErrorAs(t, err, &statusErr, "second SendRR")
		assert.Equal(t, pkicmp.StatusRejection, statusErr.Status)
		assert.True(t, pkicmp.HasFailure(err, pkicmp.FailCertRevoked) || pkicmp.HasFailure(err, pkicmp.FailBadMessageCheck), "second SendRR: %v", err)
	})
}

// keyUpdate enrolls a certificate through P10CR and updates it through KUR, reusing its key when newKey is nil.
func keyUpdate(t *testing.T, cfg *ncmConfig, cl *client.Client, creds pkicmp.Credentials, opts []client.RequestOption, purpose string, newKey *rsa.PrivateKey) {
	t.Helper()

	// The updated certificate is always a generated identity, because a profile that authorizes only
	// NCM_CMP_COMMON_NAME could not certify it next to the enrollment tests.
	oldKey, chain := enrollP10CR(t, cfg, cl, cfg.subject(generatedName(purpose)), creds, opts...)
	oldCert := chain[0]
	if newKey == nil {
		newKey = oldKey
	}

	// The certificate being replaced protects the request, so NCM authenticates the update by it
	// rather than by the enrollment credentials.
	oldCreds, err := pkicmp.NewSignatureCredentials(oldKey, oldCert, intermediates(chain)...)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), operationTimeout)
	defer cancel()
	result, err := cl.SendKUR(ctx, newKey, oldCreds, client.WithTemplateSubject(oldCert.Subject))
	require.NoError(t, err, "SendKUR")

	// verifyIssued also establishes that the new certificate certifies newKey, which for a same-key
	// update is the key of the certificate it replaces.
	verifyIssued(t, cfg, result, newKey.Public())
	assert.NotEqual(t, oldCert.SerialNumber, result.Certificate.SerialNumber, "key update returned the serial number it replaced")
}
