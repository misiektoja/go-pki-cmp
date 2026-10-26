// Package keylimit bounds the size of public keys taken from a peer, so that
// one message cannot make a verifier spend minutes in modular arithmetic.
package keylimit

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

// MaxRSAModulusBits is the largest RSA modulus accepted from a peer. The cost
// of one RSA operation grows with the square of the modulus size and nothing
// in crypto/rsa bounds it, so a 2 Mbit key costs tens of seconds per
// signature check. 16384 bits is the limit OpenSSL applies and is well above
// the 4096 bits of common deployments.
const MaxRSAModulusBits = 16384

// ErrRSAKeyTooLarge reports an RSA public key whose modulus exceeds [MaxRSAModulusBits].
var ErrRSAKeyTooLarge = errors.New("pkicmp: RSA modulus larger than 16384 bits")

// Check returns [ErrRSAKeyTooLarge] for an RSA key above the bound and nil for
// every other key, including a nil key.
func Check(pub crypto.PublicKey) error {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N != nil && k.N.BitLen() > MaxRSAModulusBits {
		return ErrRSAKeyTooLarge
	}
	return nil
}
