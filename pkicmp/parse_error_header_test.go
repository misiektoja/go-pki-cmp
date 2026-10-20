package pkicmp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// A failure after the header carries that header. A failure in or before it carries none.
func TestParseErrorHeader(t *testing.T) {
	msg := NewPKIMessage(NewGenMBody(InfoTypeAndValue{InfoType: InfoTypeCACerts}), MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	// appendInside adds extra to the end of the outer PKIMessage SEQUENCE.
	appendInside := func(t *testing.T, extra []byte) []byte {
		s := cryptobyte.String(der)
		var content cryptobyte.String
		require.True(t, s.ReadASN1(&content, cbasn1.SEQUENCE))
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(content)
			b.AddBytes(extra)
		})
		out, err := b.Bytes()
		require.NoError(t, err)
		return out
	}

	t.Run("AfterHeader", func(t *testing.T) {
		for name, input := range map[string][]byte{
			"TrailingDataInside":  appendInside(t, []byte{0x05, 0x00}),
			"MalformedProtection": appendInside(t, []byte{0xa0, 0x02, 0x05, 0x00}),
			"TrailingDataAfter":   append(append([]byte{}, der...), 0x05, 0x00),
		} {
			t.Run(name, func(t *testing.T) {
				_, err := ParsePKIMessage(input)
				pe, ok := errors.AsType[*ParseError](err)
				require.True(t, ok, "error %v", err)
				require.NotNil(t, pe.Header)
				assert.Equal(t, msg.Header.TransactionID, pe.Header.TransactionID)
				assert.Equal(t, msg.Header.SenderNonce, pe.Header.SenderNonce)
			})
		}
	})

	t.Run("NoHeader", func(t *testing.T) {
		bad := NewPKIMessage(NewGenMBody(), MessageOptions{})
		bad.Header.GeneralInfo = []InfoTypeAndValue{{InfoType: oidImplicitConfirm, InfoValue: []byte("True")}}
		malformedHeader, err := bad.MarshalBinary()
		require.NoError(t, err)
		for name, input := range map[string][]byte{
			"NotCMP":          []byte("this dummy input is not a valid PKIMessage"),
			"MalformedHeader": malformedHeader,
		} {
			t.Run(name, func(t *testing.T) {
				_, err := ParsePKIMessage(input)
				pe, ok := errors.AsType[*ParseError](err)
				require.True(t, ok, "error %v", err)
				assert.Nil(t, pe.Header)
			})
		}
	})
}
