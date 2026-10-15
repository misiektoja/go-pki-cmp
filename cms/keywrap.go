package cms

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// keyWrapIV is the default initial value of the AES key wrap (RFC 3394 §2.2.3.1).
var keyWrapIV = [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

// errUnwrap is returned for every unwrap failure so that the cause is not revealed.
var errUnwrap = errors.New("cms: key unwrap failed")

// wrapKey encrypts a key of at least 16 bytes, a multiple of 8, with the AES key wrap of RFC 3394 §2.2.1.
func wrapKey(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("cms: key to wrap must be a multiple of 8 bytes and at least 16 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out, keyWrapIV[:])
	copy(out[8:], key)
	var b [16]byte
	for j := range 6 {
		for i := 1; i <= n; i++ {
			copy(b[:8], out[:8])
			copy(b[8:], out[8*i:8*i+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(out[:8], binary.BigEndian.Uint64(b[:8])^t)
			copy(out[8*i:8*i+8], b[8:])
		}
	}
	return out, nil
}

// unwrapKey reverses wrapKey and checks the integrity value in constant time (RFC 3394 §2.2.2).
func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errUnwrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errUnwrap
	}
	n := len(wrapped)/8 - 1
	out := make([]byte, len(wrapped))
	copy(out, wrapped)
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i) // #nosec G115 -- n*j+i is positive and bounded by the wrapped key length
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(out[:8])^t)
			copy(b[8:], out[8*i:8*i+8])
			block.Decrypt(b[:], b[:])
			copy(out[:8], b[:8])
			copy(out[8*i:8*i+8], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(out[:8], keyWrapIV[:]) != 1 {
		return nil, errUnwrap
	}
	return out[8:], nil
}
