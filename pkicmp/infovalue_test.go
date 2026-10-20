package pkicmp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// infoValue is one DER element or absent.
func TestInfoTypeAndValueRequiresOneDERElement(t *testing.T) {
	encode := func(t *testing.T, value []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(InfoTypeCACerts)
			b.AddBytes(value)
		})
		der, err := b.Bytes()
		require.NoError(t, err)
		return der
	}
	for _, tt := range []struct {
		name  string
		value []byte
		ok    bool
	}{
		{name: "Absent", ok: true},
		{name: "OneElement", value: []byte{0x05, 0x00}, ok: true},
		{name: "NotDER", value: []byte("True")},
		{name: "TwoElements", value: []byte{0x05, 0x00, 0x05, 0x00}},
		{name: "TruncatedTLV", value: []byte{0x04, 0x05, 0x01}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var itv InfoTypeAndValue
			s := cryptobyte.String(encode(t, tt.value))
			err := itv.unmarshal(&s)
			if !tt.ok {
				_, isParseError := errors.AsType[*ParseError](err)
				assert.True(t, isParseError, "error %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.value, itv.InfoValue)
		})
	}
}
