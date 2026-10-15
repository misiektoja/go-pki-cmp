package cms

import (
	"crypto"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// x963KDF derives length bytes from the shared secret z with the ANSI X9.63 KDF
// (SEC 1 §3.6.1), as RFC 5753 §7.2 uses it. ANS X9.44 names the same construction KDF2.
func x963KDF(h crypto.Hash, z, sharedInfo []byte, length int) ([]byte, error) {
	return counterKDF(h, z, sharedInfo, length, false)
}

// kdf3 derives length bytes from the shared secret z with ANS X9.44 KDF3
// (RFC 9690 Appendix B.1), which hashes the counter before z.
func kdf3(h crypto.Hash, z, otherInfo []byte, length int) ([]byte, error) {
	return counterKDF(h, z, otherInfo, length, true)
}

// counterKDF concatenates Hash(z || counter || info) blocks, or
// Hash(counter || z || info) blocks when counterFirst is set, with a 32-bit
// big-endian counter starting at 1, and truncates the result to length bytes.
func counterKDF(h crypto.Hash, z, info []byte, length int, counterFirst bool) ([]byte, error) {
	if !h.Available() {
		return nil, errors.New("cms: KDF hash is not available")
	}
	out := make([]byte, 0, length+h.Size())
	var counter [4]byte
	for i := uint32(1); len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		d := h.New()
		if counterFirst {
			d.Write(counter[:])
			d.Write(z)
		} else {
			d.Write(z)
			d.Write(counter[:])
		}
		d.Write(info)
		out = d.Sum(out)
	}
	return out[:length], nil
}

// eccSharedInfo encodes ECC-CMS-SharedInfo (RFC 5753 §7.2) for a wrap algorithm,
// optional user keying material and a KEK size in bytes.
func eccSharedInfo(wrapAlgorithm, ukm []byte, kekLength int) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(wrapAlgorithm)
		if ukm != nil {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(ukm)
			})
		}
		var bits [4]byte
		binary.BigEndian.PutUint32(bits[:], uint32(kekLength*8)) // #nosec G115 -- kekLength is a key wrap size of at most 32
		b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(bits[:])
		})
	})
	return b.Bytes()
}

// kemOtherInfo encodes CMSORIforKEMOtherInfo (RFC 9629 §5), the info input of the KEMRecipientInfo key derivation.
func kemOtherInfo(wrapAlgorithm, ukm []byte, kekLength int) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(wrapAlgorithm)
		b.AddASN1Int64(int64(kekLength))
		if ukm != nil {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(ukm)
			})
		}
	})
	return b.Bytes()
}
