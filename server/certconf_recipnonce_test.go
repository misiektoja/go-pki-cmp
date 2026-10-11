package server_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

// omittedNonceCertConf builds a certConf accepting cert with no recipNonce
// unless one is given, an empty statusString and the issued certificate
// repeated in extraCerts.
func omittedNonceCertConf(t *testing.T, resp *pkicmp.PKIMessage, cert *x509.Certificate, secret, recipNonce []byte) *pkicmp.PKIMessage {
	t.Helper()
	status, err := pkicmp.NewCertStatus(cert, 0)
	require.NoError(t, err)
	status.StatusInfo = &pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted, StatusString: pkicmp.PKIFreeText{""}}
	msg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{status}), pkicmp.MessageOptions{
		Sender:        pkicmp.NewDirectoryName(testSender),
		TransactionID: resp.Header.TransactionID,
		RecipNonce:    recipNonce,
	})
	msg.ExtraCerts = []pkicmp.CMPCertificate{{Raw: cert.Raw}}
	protectMAC(msg, secret)
	return msg
}

// A certConf without recipNonce is refused by default and accepted with
// WithOptionalCertConfRecipNonce. A recipNonce that is present must match
// either way.
func TestCertConfOptionalRecipNonce(t *testing.T) {
	secret := []byte("recipnonce-secret")

	t.Run("MissingRejectedByDefault", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret)
		resp, cert := enrollForCertConf(t, ts, secret, false)
		conf := postCMP(t, ts, omittedNonceCertConf(t, resp, cert, secret, nil))
		require.Equal(t, pkicmp.BodyTypeError, conf.Body.Type)
		info := statusInfoOf(t, conf)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"missing recipNonce"}, info.StatusString)
		assert.Empty(t, ca.statuses)
	})

	for _, p10cr := range []bool{false, true} {
		name := "MissingAcceptedWithOption/ir"
		if p10cr {
			name = "MissingAcceptedWithOption/p10cr"
		}
		t.Run(name, func(t *testing.T) {
			ts, ca := newConfirmingServer(t, secret, server.WithOptionalCertConfRecipNonce())
			resp, cert := enrollForCertConf(t, ts, secret, p10cr)
			conf := postCMP(t, ts, omittedNonceCertConf(t, resp, cert, secret, nil))
			require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
			assert.Equal(t, []server.ConfirmStatus{server.ConfirmAccepted}, ca.statuses)
		})
	}

	t.Run("MissingRejectedUnderStrictProfile", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret, server.WithOptionalCertConfRecipNonce(), server.WithStrictProfileValidation())
		resp, cert := enrollForCertConf(t, ts, secret, false)
		conf := postCMP(t, ts, omittedNonceCertConf(t, resp, cert, secret, nil))
		require.Equal(t, pkicmp.BodyTypeError, conf.Body.Type)
		info := statusInfoOf(t, conf)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"missing recipNonce"}, info.StatusString)
		assert.Empty(t, ca.statuses)
	})

	t.Run("MismatchRejectedWithOption", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret, server.WithOptionalCertConfRecipNonce())
		resp, cert := enrollForCertConf(t, ts, secret, false)
		conf := postCMP(t, ts, omittedNonceCertConf(t, resp, cert, secret, []byte("not-the-response-sender-nonce")))
		require.Equal(t, pkicmp.BodyTypeError, conf.Body.Type)
		info := statusInfoOf(t, conf)
		assert.Equal(t, pkicmp.FailBadRecipientNonce, info.FailInfo)
		assert.Equal(t, pkicmp.PKIFreeText{"recipNonce mismatch"}, info.StatusString)
		assert.Empty(t, ca.statuses)
	})

	// The certificate hash still binds the confirmation to the issued certificate.
	t.Run("WrongCertificateRejectedWithOption", func(t *testing.T) {
		ts, ca := newConfirmingServer(t, secret, server.WithOptionalCertConfRecipNonce())
		resp, _ := enrollForCertConf(t, ts, secret, false)
		_, other := enrollForCertConf(t, ts, secret, false)
		conf := postCMP(t, ts, omittedNonceCertConf(t, resp, other, secret, nil))
		require.Equal(t, pkicmp.BodyTypeError, conf.Body.Type)
		assert.Equal(t, pkicmp.FailBadCertId, statusInfoOf(t, conf).FailInfo)
		assert.Empty(t, ca.statuses)
	})
}
