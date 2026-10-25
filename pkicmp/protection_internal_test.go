package pkicmp

import (
	"crypto"
	"crypto/hmac"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pbkdf2"
)

func TestPBMParameterASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		p := pbmParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: oidSHA256},
			IterationCount: 100,
			MAC:            AlgorithmIdentifier{Algorithm: oidHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled pbmParameter
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, p.IterationCount, unmarshaled.IterationCount)
		assert.Equal(t, p.Salt, unmarshaled.Salt)
	})

	// The configured limits are only known to the verifier, so parsing accepts
	// any count that fits an int.
	t.Run("LeavesIterationRangeToVerifier", func(t *testing.T) {
		p := pbmParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: oidSHA256},
			IterationCount: DefaultMaxMACIterationCount + 1,
			MAC:            AlgorithmIdentifier{Algorithm: oidHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled pbmParameter
		s := cryptobyte.String(marshaled)
		require.NoError(t, unmarshaled.unmarshal(&s))
		assert.Equal(t, DefaultMaxMACIterationCount+1, unmarshaled.IterationCount)
	})

	t.Run("RejectsIterationCountBeyondInt", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString([]byte{0x01, 0x02})
			(&AlgorithmIdentifier{Algorithm: oidSHA256}).marshal(nil, b)
			b.AddASN1BigInt(new(big.Int).Lsh(big.NewInt(1), 70))
			(&AlgorithmIdentifier{Algorithm: oidHMACWithSHA256}).marshal(nil, b)
		})
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled pbmParameter
		s := cryptobyte.String(marshaled)
		var pe *ParseError
		require.ErrorAs(t, unmarshaled.unmarshal(&s), &pe)
		assert.Contains(t, pe.Detail, "invalid iterationCount")
	})
}

func TestDerivePBMKey(t *testing.T) {
	k, err := derivePBMKey([]byte("secret"), []byte("salt"), 10, crypto.SHA256, crypto.SHA256)
	assert.NoError(t, err)
	assert.NotEmpty(t, k)
}

func TestValidatePBMIterationCount(t *testing.T) {
	for _, tc := range []struct {
		name            string
		count, min, max int
		detail          string
	}{
		{"ZeroIsBelowDefaultMinimum", 0, 0, 0, "iterationCount too small"},
		{"AboveDefaultMaximum", DefaultMaxMACIterationCount + 1, 0, 0, "iterationCount too large"},
		{"BelowConfiguredMinimum", 99, 100, 0, "iterationCount too small: 99 (minimum 100)"},
		{"AboveConfiguredMaximum", 1001, 0, 1000, "iterationCount too large: 1001 (maximum 1000)"},
		{"NegativeMinimumSelectsDefault", 0, -5, 0, "iterationCount too small"},
		{"MaximumBelowMinimumIsRaised", 2001, 2000, 10, "iterationCount too large: 2001 (maximum 2000)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pe *ParseError
			require.ErrorAs(t, validatePBMIterationCount(tc.count, tc.min, tc.max), &pe)
			assert.Contains(t, pe.Detail, tc.detail)
		})
	}
	for _, tc := range []struct {
		name            string
		count, min, max int
	}{
		{"WithinDefaults", 1000, 0, 0},
		{"DefaultMinimum", DefaultMinMACIterationCount, 0, 0},
		{"DefaultMaximum", DefaultMaxMACIterationCount, 0, 0},
		{"RaisedMaximum", 1048575, 0, 1048575},
		{"MaximumBelowMinimumIsRaised", 2000, 2000, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NoError(t, validatePBMIterationCount(tc.count, tc.min, tc.max))
		})
	}
}

func TestValidatePBKDF2KeyLength(t *testing.T) {
	t.Run("Negative", func(t *testing.T) {
		err := validatePBKDF2KeyLength(-1, crypto.SHA256)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "keyLength too small")
	})
	t.Run("Zero", func(t *testing.T) {
		err := validatePBKDF2KeyLength(0, crypto.SHA256)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "keyLength too small")
	})
	// A searchable key space must be rejected even though RFC 8018 §A.5 permits
	// keyLength 1.
	t.Run("SearchableKeySpace", func(t *testing.T) {
		for _, keyLength := range []int{1, 8, defaultPBKDF2MinKeyLength - 1} {
			err := validatePBKDF2KeyLength(keyLength, crypto.SHA256)
			var pe *ParseError
			require.ErrorAs(t, err, &pe, "keyLength %d", keyLength)
			assert.Contains(t, pe.Detail, "keyLength too small")
		}
	})
	// Deriving 32 bytes for every MAC is common practice, so it must be accepted
	// for the larger hashes too even though it is shorter than their digest.
	t.Run("ThirtyTwoBytesAcceptedForEveryMAC", func(t *testing.T) {
		for _, macHash := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			assert.NoError(t, validatePBKDF2KeyLength(32, macHash), "MAC %v", macHash)
		}
	})
	t.Run("ExceedsBlockSize", func(t *testing.T) {
		err := validatePBKDF2KeyLength(crypto.SHA256.New().BlockSize()+1, crypto.SHA256)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "keyLength too large")
	})
	t.Run("Huge", func(t *testing.T) {
		err := validatePBKDF2KeyLength(1<<40, crypto.SHA512)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "keyLength too large")
	})
	t.Run("Valid", func(t *testing.T) {
		assert.NoError(t, validatePBKDF2KeyLength(crypto.SHA256.Size(), crypto.SHA256))
		assert.NoError(t, validatePBKDF2KeyLength(crypto.SHA256.New().BlockSize(), crypto.SHA256))
		assert.NoError(t, validatePBKDF2KeyLength(crypto.SHA512.Size(), crypto.SHA512))
	})
}

// testPBMAC1IterationCount is the PBKDF2 iteration count that buildPBMAC1Params encodes.
const testPBMAC1IterationCount = 1000

// buildPBMAC1Params encodes PBMAC1-params, omitting keyLength when keyLen is 0 and prf when prf is nil.
func buildPBMAC1Params(t *testing.T, salt []byte, keyLen int, prf, mac asn1.ObjectIdentifier) []byte {
	t.Helper()

	var kdf cryptobyte.Builder
	kdf.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		seq.AddASN1OctetString(salt)
		seq.AddASN1Int64(testPBMAC1IterationCount)
		// RFC 8018 §A.5 marks keyLength OPTIONAL and gives prf a DEFAULT, so a
		// conforming DER encoder leaves them out when they are not needed.
		if keyLen != 0 {
			seq.AddASN1Int64(int64(keyLen))
		}
		if prf != nil {
			seq.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
				alg.AddASN1ObjectIdentifier(prf)
			})
		}
	})
	kdfBytes, err := kdf.Bytes()
	require.NoError(t, err)

	params, err := asn1.Marshal(struct {
		KeyDerivationFunc algorithmIdentifierASN1
		MessageAuthScheme algorithmIdentifierASN1
	}{
		KeyDerivationFunc: algorithmIdentifierASN1{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfBytes}},
		MessageAuthScheme: algorithmIdentifierASN1{Algorithm: mac},
	})
	require.NoError(t, err)
	return params
}

// pbmac1Message builds an unverifiable PBMAC1 message carrying the given parameters.
func pbmac1Message(params []byte) *PKIMessage {
	return &PKIMessage{
		Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: params}},
		Body:       NewPKIConfBody(),
		Protection: []byte{0x01, 0x02, 0x03},
	}
}

// A hostile peer controls the PBKDF2 keyLength, which reaches pbkdf2.Key before
// the MAC is checked. Out-of-range values must be rejected rather than panic,
// and a key weaker than the MAC it feeds must be rejected outright.
func TestVerifyPBMAC1RejectsHostileKeyLength(t *testing.T) {
	for _, tc := range []struct {
		name      string
		keyLength int
		detail    string
	}{
		{"Negative", -1, "keyLength too small"},
		{"OneByteKeySpace", 1, "keyLength too small"},
		{"BelowMinimum", defaultPBKDF2MinKeyLength - 1, "keyLength too small"},
		{"ExceedsBlockSize", crypto.SHA256.New().BlockSize() + 1, "keyLength too large"},
		{"Huge", 1 << 40, "keyLength too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := buildPBMAC1Params(t, []byte("saltsalt"), tc.keyLength, oidHMACWithSHA256, oidHMACWithSHA256)

			_, err := pbmac1Message(params).Verify(VerifyOptions{SharedSecret: []byte("shared-secret")})
			var pe *ParseError
			require.ErrorAs(t, err, &pe)
			assert.Contains(t, pe.Detail, tc.detail)
		})
	}

	t.Run("ValidKeyLengthNotRejected", func(t *testing.T) {
		params := buildPBMAC1Params(t, []byte("saltsalt"), crypto.SHA256.Size(), oidHMACWithSHA256, oidHMACWithSHA256)

		_, err := pbmac1Message(params).Verify(VerifyOptions{SharedSecret: []byte("shared-secret")})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "keyLength")
	})
}

// RFC 8018 §A.5 marks keyLength OPTIONAL and gives prf a DEFAULT of HMAC-SHA-1.
// A peer that omits either field is sending a conforming message, so it must
// verify rather than being rejected as malformed.
func TestVerifyPBMAC1OptionalKeyLengthAndPRF(t *testing.T) {
	secret := []byte("shared-secret")
	salt := []byte("saltsalt")

	for _, tc := range []struct {
		name    string
		keyLen  int
		prf     asn1.ObjectIdentifier
		mac     asn1.ObjectIdentifier
		wantPRF crypto.Hash
		wantMAC crypto.Hash
	}{
		{"AllFieldsPresent", crypto.SHA256.Size(), oidHMACWithSHA256, oidHMACWithSHA256, crypto.SHA256, crypto.SHA256},
		{"KeyLengthOmitted", 0, oidHMACWithSHA256, oidHMACWithSHA256, crypto.SHA256, crypto.SHA256},
		{"PRFOmittedDefaultsToSHA1", crypto.SHA256.Size(), nil, oidHMACWithSHA256, crypto.SHA1, crypto.SHA256},
		{"BothOmitted", 0, nil, oidHMACWithSHA256, crypto.SHA1, crypto.SHA256},
		{"BothOmittedSHA512MAC", 0, nil, oidHMACWithSHA512, crypto.SHA1, crypto.SHA512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := buildPBMAC1Params(t, salt, tc.keyLen, tc.prf, tc.mac)
			msg := &PKIMessage{
				Header: PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: params}},
				Body:   NewPKIConfBody(),
			}
			require.NoError(t, msg.marshalForProtection())
			data, err := msg.protectedPart()
			require.NoError(t, err)

			// Independently derive the MAC the way RFC 8018 says the omitted
			// fields must be interpreted: HMAC-SHA-1 PRF and a key as long as
			// the MAC digest.
			k := pbkdf2.Key(secret, salt, testPBMAC1IterationCount, tc.wantMAC.Size(), tc.wantPRF.New)
			h := hmac.New(tc.wantMAC.New, k)
			h.Write(data)
			msg.Protection = h.Sum(nil)

			result, err := msg.Verify(VerifyOptions{SharedSecret: secret})
			require.NoError(t, err)
			assert.True(t, result.MACVerified)
		})
	}
}

// Echoing a received AlgorithmIdentifier feeds peer-controlled PBKDF2 parameters
// into the protection path, which must bound them exactly as verification does.
func TestProtectWithMACAlgorithmRejectsHostileKeyLength(t *testing.T) {
	for _, tc := range []struct {
		name      string
		keyLength int
		detail    string
	}{
		{"Negative", -1, "keyLength too small"},
		{"OneByteKeySpace", 1, "keyLength too small"},
		{"Huge", 1 << 40, "keyLength too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := buildPBMAC1Params(t, []byte("saltsalt"), tc.keyLength, oidHMACWithSHA256, oidHMACWithSHA256)
			alg := &AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: params}

			msg := &PKIMessage{Body: NewPKIConfBody()}
			err := msg.protectWithMACAlgorithm([]byte("shared-secret"), alg, 0, 0)
			var pe *ParseError
			require.ErrorAs(t, err, &pe)
			assert.Contains(t, pe.Detail, tc.detail)
		})
	}

	// An echoed request that omitted the optional fields must still produce a
	// protected response rather than failing as malformed.
	t.Run("OptionalFieldsOmitted", func(t *testing.T) {
		params := buildPBMAC1Params(t, []byte("saltsalt"), 0, nil, oidHMACWithSHA256)
		alg := &AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: params}

		msg := &PKIMessage{Body: NewPKIConfBody()}
		require.NoError(t, msg.protectWithMACAlgorithm([]byte("shared-secret"), alg, 0, 0))
		assert.NotEmpty(t, msg.Protection)
	})
}

func TestProtectWithMACErrors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithMAC([]byte("secret"))
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("EmptySecret", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMAC([]byte{})
		var pe *ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, ReasonMissingSharedSecret, pe.Reason)
	})
	t.Run("UnsupportedOWF", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:    []byte("secret"),
			Algorithm: oidPasswordBasedMac,
			OWF:       asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("UnsupportedMAC", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:    []byte("secret"),
			Algorithm: oidPasswordBasedMac,
			MAC:       asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("IterationCountTooLarge", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:         []byte("secret"),
			Algorithm:      oidPasswordBasedMac,
			IterationCount: DefaultMaxMACIterationCount + 1,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
	t.Run("IterationCountBelowConfiguredMinimum", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithMACOptions(macOptions{
			Secret:            []byte("secret"),
			Algorithm:         oidPasswordBasedMac,
			IterationCount:    99,
			MinIterationCount: 100,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too small")
	})
}

func TestPBMAC1ParameterASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		salt := []byte{0x01, 0x02, 0x03, 0x04}
		params, err := marshalPBMAC1Params(salt, 5000, 32, oidHMACWithSHA256, oidHMACWithSHA256)
		require.NoError(t, err)

		// Unmarshal and verify round-trip.
		var pbmac1Params struct {
			KeyDerivationFunc algorithmIdentifierASN1
			MessageAuthScheme algorithmIdentifierASN1
		}
		_, err = asn1.Unmarshal(params, &pbmac1Params)
		require.NoError(t, err)
		assert.True(t, pbmac1Params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2))
		assert.True(t, pbmac1Params.MessageAuthScheme.Algorithm.Equal(oidHMACWithSHA256))

		var pbkdf2Params struct {
			Salt           []byte
			IterationCount int
			KeyLength      int
			PRF            algorithmIdentifierASN1
		}
		_, err = asn1.Unmarshal(pbmac1Params.KeyDerivationFunc.Parameters.FullBytes, &pbkdf2Params)
		require.NoError(t, err)
		assert.Equal(t, salt, pbkdf2Params.Salt)
		assert.Equal(t, 5000, pbkdf2Params.IterationCount)
		assert.Equal(t, 32, pbkdf2Params.KeyLength)
		assert.True(t, pbkdf2Params.PRF.Algorithm.Equal(oidHMACWithSHA256))
	})
}

func TestProtectWithPBMAC1Errors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithPBMAC1Options(pbmac1Options{Secret: []byte("secret")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("EmptySecret", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{Secret: []byte{}})
		var pe *ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, ReasonMissingSharedSecret, pe.Reason)
	})
	t.Run("UnsupportedPRF", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret: []byte("secret"),
			PRF:    asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("UnsupportedMAC", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret: []byte("secret"),
			MAC:    asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("IterationCountTooLarge", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:         []byte("secret"),
			IterationCount: DefaultMaxMACIterationCount + 1,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
	t.Run("IterationCountAboveConfiguredMaximum", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:            []byte("secret"),
			IterationCount:    1001,
			MaxIterationCount: 1000,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
}

func TestProtectWithSignatureErrors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithSignature(nil, 0, nil)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
}

func TestPKIMessageProtectedPartErrors(t *testing.T) {
	t.Run("MissingHeader", func(t *testing.T) {
		msg := &PKIMessage{rawBody: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{rawHeader: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
}

func TestVerifyErrors(t *testing.T) {
	t.Run("NoProtectionAlg", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		_, err := msg.Verify(VerifyOptions{})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "message has no protection algorithm")
	})
	t.Run("EmptyProtection", func(t *testing.T) {
		msg := &PKIMessage{
			Header: PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}},
			Body:   NewPKIConfBody(),
		}
		_, err := msg.Verify(VerifyOptions{SharedSecret: []byte("s")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "message is not protected")
	})
	t.Run("NilBody", func(t *testing.T) {
		msg := &PKIMessage{
			Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}},
			Protection: []byte{0x01},
		}
		_, err := msg.Verify(VerifyOptions{SharedSecret: []byte("s")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		msg := &PKIMessage{
			Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}},
			Body:       NewPKIConfBody(),
			Protection: []byte{0x01},
		}
		_, err := msg.Verify(VerifyOptions{})
		var ve *VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, ReasonUnsupportedAlgorithm, ve.Reason)
	})
}
