package pkicmp_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestP10CRRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test User"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	body := pkicmp.NewP10CRBody(csr)
	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			Sender:        pkicmp.NewDirectoryName(pkix.Name{CommonName: "Sender"}),
			Recipient:     pkicmp.NewDirectoryName(pkix.Name{CommonName: "Recipient"}),
			TransactionID: []byte("trans-123"),
			SenderNonce:   []byte("nonce-123"),
		},
		Body: body,
	}

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	assert.Equal(t, pkicmp.PVNO2, parsed.Header.PVNO)
	assert.Equal(t, []byte("trans-123"), parsed.Header.TransactionID)
	assert.Equal(t, pkicmp.BodyTypeP10CR, parsed.Body.Type)

	parsedCSR, err := parsed.Body.P10CR()
	require.NoError(t, err)
	assert.Equal(t, csr.Subject.String(), parsedCSR.Subject.String())
	assert.Equal(t, csr.Raw, parsedCSR.Raw)
}

func TestImplicitPVNO3Upgrades(t *testing.T) {
	t.Run("CertConfWithHashAlg", func(t *testing.T) {
		conf := &pkicmp.CertConfirmContent{
			pkicmp.CertStatus{CertHash: []byte("hash"), CertReqID: 123, HashAlg: &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}},
		}
		body := pkicmp.NewCertConfBody(conf)

		msg := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				Sender:    pkicmp.NewDirectoryName(pkix.Name{}),
				Recipient: pkicmp.NewDirectoryName(pkix.Name{}),
			},
			Body: body,
		}

		der, err := msg.MarshalBinary()
		require.NoError(t, err)

		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO3, parsed.Header.PVNO)

		gotConf, err := parsed.Body.CertConf()
		require.NoError(t, err)
		assert.Len(t, *gotConf, 1)
		assert.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, (*gotConf)[0].HashAlg.Algorithm)
	})

	t.Run("POPOPrivKeyEncryptedKey", func(t *testing.T) {
		req := pkicmp.CertReqMessages{
			{
				CertReq: pkicmp.CertRequest{CertReqID: 1},
				Popo:    pkicmp.NewEncryptedKeyPOP([]byte{0x30, 0x00}),
			},
		}

		body := pkicmp.NewIRBody(&req)
		msg := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{TransactionID: []byte("trans")},
			Body:   body,
		}

		der, err := msg.MarshalBinary()
		require.NoError(t, err)

		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO3, parsed.Header.PVNO)
	})
}

func TestRoundTripOpenSSLGeneratedMessages(t *testing.T) {
	t.Run("IR", func(t *testing.T) {
		der, err := os.ReadFile("testdata/ir_golden.der")
		require.NoError(t, err)

		msg, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO2, msg.Header.PVNO)
		assert.Equal(t, pkicmp.BodyTypeIR, msg.Body.Type)

		marshaled, err := msg.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, der, marshaled)
	})

	t.Run("CR", func(t *testing.T) {
		der, err := os.ReadFile("testdata/cr_golden.der")
		require.NoError(t, err)

		msg, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO2, msg.Header.PVNO)
		assert.Equal(t, pkicmp.BodyTypeCR, msg.Body.Type)

		marshaled, err := msg.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, der, marshaled)
	})

	t.Run("KUR", func(t *testing.T) {
		der, err := os.ReadFile("testdata/kur_golden.der")
		require.NoError(t, err)

		msg, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO2, msg.Header.PVNO)
		assert.Equal(t, pkicmp.BodyTypeKUR, msg.Body.Type)

		marshaled, err := msg.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, der, marshaled)
	})

	t.Run("P10CR", func(t *testing.T) {
		der, err := os.ReadFile("testdata/p10cr_golden.der")
		require.NoError(t, err)

		msg, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)

		assert.Equal(t, pkicmp.PVNO2, msg.Header.PVNO)
		assert.Equal(t, pkicmp.BodyTypeP10CR, msg.Body.Type)

		marshaled, err := msg.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, der, marshaled)
	})
}

func TestParseRejectsInvalidASN1Structure(t *testing.T) {
	t.Run("MismatchedHeaderTag", func(t *testing.T) {
		der, err := os.ReadFile("testdata/ir_golden.der")
		require.NoError(t, err)

		tampered := make([]byte, len(der))
		copy(tampered, der)
		tampered[4] = 0x31

		_, err = pkicmp.ParsePKIMessage(tampered)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PKIHeader sequence")
	})

	t.Run("InvalidBodyTag", func(t *testing.T) {
		badDer := []byte{
			0x30, 0x11,
			0x30, 0x0b, 0x02, 0x01, 0x02, 0xa4, 0x02, 0x30, 0x00, 0xa4, 0x02, 0x30, 0x00,
			0xa4, 0x00,
		}

		_, err := pkicmp.ParsePKIMessage(badDer)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PKIMessage sequence")
	})
}

// The zero GeneralizedTime is a legal value, so a messageTime carrying it must
// stay distinguishable from an absent one and survive a re-encode.
func TestMessageTimePresenceSurvivesRoundTrip(t *testing.T) {
	build := func(messageTime time.Time) *pkicmp.PKIMessage {
		conf := pkicmp.CertConfirmContent{}
		msg := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&conf), pkicmp.MessageOptions{
			Sender: pkicmp.NewDirectoryName(pkix.Name{CommonName: "presence"}),
		})
		msg.Header.MessageTime = messageTime
		return msg
	}

	t.Run("absent", func(t *testing.T) {
		msg := build(time.Time{})
		assert.False(t, msg.Header.HasMessageTime())
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)
		assert.False(t, parsed.Header.HasMessageTime())
	})

	t.Run("zero time on the wire", func(t *testing.T) {
		real := time.Now().UTC().Truncate(time.Second)
		der, err := build(real).MarshalBinary()
		require.NoError(t, err)
		patched := bytes.Replace(der, []byte(real.Format("20060102150405")+"Z"), []byte("00010101000000Z"), 1)
		require.NotEqual(t, der, patched)

		parsed, err := pkicmp.ParsePKIMessage(patched)
		require.NoError(t, err)
		assert.True(t, parsed.Header.MessageTime.IsZero())
		assert.True(t, parsed.Header.HasMessageTime())

		// Re-encoding must keep the field, otherwise presence is lost silently.
		reencoded, err := parsed.MarshalBinary()
		require.NoError(t, err)
		again, err := pkicmp.ParsePKIMessage(reencoded)
		require.NoError(t, err)
		assert.True(t, again.Header.HasMessageTime())
	})
}
