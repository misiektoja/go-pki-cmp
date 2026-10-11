package pkicmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 4211 §6.5: the oldCertID control decodes to the CertId its builder encoded.
func TestCertRequestOldCertID(t *testing.T) {
	device := pkix.Name{CommonName: "device-1"}
	cert := testCertificate(t, pkix.Name{CommonName: "Old Cert CA", Organization: []string{"Example"}}, device)
	other := testCertificate(t, pkix.Name{CommonName: "Other CA"}, device)
	control, err := NewOldCertIDControl(cert)
	require.NoError(t, err)

	t.Run("Absent", func(t *testing.T) {
		id, err := (&CertRequest{}).OldCertID()
		require.NoError(t, err)
		assert.Nil(t, id)
	})

	t.Run("RoundTrip", func(t *testing.T) {
		req := roundTripCertReqMsg(t, &CertReqMsg{CertReq: CertRequest{Controls: []AttributeTypeAndValue{control}}})
		id, err := req.CertReq.OldCertID()
		require.NoError(t, err)
		require.NotNil(t, id)
		assert.Equal(t, 0, id.SerialNumber.Cmp(cert.SerialNumber))
		assert.True(t, id.Identifies(cert))
		assert.False(t, id.Identifies(other), "same serial under another issuer")
		assert.False(t, id.Identifies(nil))
	})

	t.Run("IssuerStringType", func(t *testing.T) {
		// The same issuer encoded with UTF8String values still identifies the certificate.
		id := &CertID{Issuer: NewDirectoryName(cert.Issuer), SerialNumber: cert.SerialNumber}
		assert.True(t, id.Identifies(cert))
	})

	t.Run("IssuerNotDirectoryName", func(t *testing.T) {
		id := &CertID{Issuer: GeneralName{RFC822Name: "ca@example.test"}, SerialNumber: cert.SerialNumber}
		assert.False(t, id.Identifies(cert))
	})

	t.Run("Repeated", func(t *testing.T) {
		_, err := (&CertRequest{Controls: []AttributeTypeAndValue{control, control}}).OldCertID()
		assert.ErrorContains(t, err, "more than one oldCertID control")
	})

	t.Run("Malformed", func(t *testing.T) {
		bad := AttributeTypeAndValue{Type: control.Type, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
		_, err := (&CertRequest{Controls: []AttributeTypeAndValue{bad}}).OldCertID()
		assert.Error(t, err)
	})

	t.Run("TrailingData", func(t *testing.T) {
		bad := AttributeTypeAndValue{Type: control.Type, Value: append(append([]byte(nil), control.Value...), 0x05, 0x00)}
		_, err := (&CertRequest{Controls: []AttributeTypeAndValue{bad}}).OldCertID()
		assert.ErrorContains(t, err, "trailing data in oldCertID")
	})
}

// testCertificate returns a self-issued test certificate with serial number 4711.
func testCertificate(t *testing.T, issuer, subject pkix.Name) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4711), Subject: subject}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &x509.Certificate{Subject: issuer}, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
