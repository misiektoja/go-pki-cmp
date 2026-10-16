package pkicmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// An implicitly tagged encryptedRand, which RFC 9810 does not use, still parses.
func TestChallengeImplicitEncryptedRand(t *testing.T) {
	envelope := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	for name, der := range map[string][]byte{
		"explicit": {0x30, 0x0c, 0x04, 0x01, 0xaa, 0x04, 0x00, 0xa0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00},
		"implicit": {0x30, 0x0a, 0x04, 0x01, 0xaa, 0x04, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			var c Challenge
			s := cryptobyte.String(der)
			require.NoError(t, c.unmarshal(&s))
			assert.True(t, s.Empty())
			assert.Equal(t, envelope, c.EncryptedRand)
			assert.Equal(t, []byte{0xaa}, c.Witness)
		})
	}

	var c Challenge
	trailing := cryptobyte.String([]byte{0x30, 0x0e, 0x04, 0x01, 0xaa, 0x04, 0x00, 0xa0, 0x07, 0x30, 0x03, 0x02, 0x01, 0x00, 0x05, 0x00})
	assert.Error(t, c.unmarshal(&trailing), "nothing may follow the EnvelopedData inside the explicit tag")
}
