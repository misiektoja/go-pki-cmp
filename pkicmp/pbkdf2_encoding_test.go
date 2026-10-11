package pkicmp_test

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

var (
	oidPBMAC1TestOnly     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidPBKDF2TestOnly     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1TestOnly   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256TestOnly = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
)

type algIDTestOnly struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbkdf2ParamsTestOnly struct {
	Salt           []byte
	IterationCount int
	KeyLength      int           `asn1:"optional"`
	PRF            asn1.RawValue `asn1:"optional"`
}

type pbmac1ParamsTestOnly struct {
	KeyDerivationFunc algIDTestOnly
	MessageAuthScheme algIDTestOnly
}

// peerPBMAC1AlgID builds the protectionAlg a peer would send, with prf either omitted or explicit.
func peerPBMAC1AlgID(t *testing.T, prf *asn1.ObjectIdentifier) *pkicmp.AlgorithmIdentifier {
	t.Helper()

	kdfParams := pbkdf2ParamsTestOnly{
		Salt:           []byte("0123456789abcdef"),
		IterationCount: 10000,
		KeyLength:      32,
	}
	if prf != nil {
		encodedPRF, err := asn1.Marshal(algIDTestOnly{Algorithm: *prf})
		require.NoError(t, err)
		kdfParams.PRF = asn1.RawValue{FullBytes: encodedPRF}
	}
	kdfDER, err := asn1.Marshal(kdfParams)
	require.NoError(t, err)

	outer, err := asn1.Marshal(pbmac1ParamsTestOnly{
		KeyDerivationFunc: algIDTestOnly{Algorithm: oidPBKDF2TestOnly, Parameters: asn1.RawValue{FullBytes: kdfDER}},
		MessageAuthScheme: algIDTestOnly{Algorithm: oidHMACSHA256TestOnly},
	})
	require.NoError(t, err)

	return &pkicmp.AlgorithmIdentifier{Algorithm: oidPBMAC1TestOnly, Parameters: outer}
}

// emittedPBKDF2Params decodes the PBKDF2 parameters a protected message carries.
func emittedPBKDF2Params(t *testing.T, msg *pkicmp.PKIMessage) pbkdf2ParamsTestOnly {
	t.Helper()
	require.NotNil(t, msg.Header.ProtectionAlg)

	var outer pbmac1ParamsTestOnly
	_, err := asn1.Unmarshal(msg.Header.ProtectionAlg.Parameters, &outer)
	require.NoError(t, err)

	var inner pbkdf2ParamsTestOnly
	_, err = asn1.Unmarshal(outer.KeyDerivationFunc.Parameters.FullBytes, &inner)
	require.NoError(t, err)
	return inner
}

// echoProtect answers a peer's protection parameters the way the server does.
func echoProtect(t *testing.T, alg *pkicmp.AlgorithmIdentifier) *pkicmp.PKIMessage {
	t.Helper()
	msg := &pkicmp.PKIMessage{Body: pkicmp.NewPKIConfBody()}
	creds, err := pkicmp.NewMACCredentials([]byte("shared-secret"), pkicmp.WithProtectionAlgorithm(alg))
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	return msg
}

// RFC 8018 §A.2 makes HMAC-SHA-1 the default prf and X.690 §11.5 forbids
// encoding a component that holds its default, so echoing a peer that omitted
// prf must not add it back.
func TestPBMAC1OmitsDefaultPRFWhenEchoing(t *testing.T) {
	msg := echoProtect(t, peerPBMAC1AlgID(t, nil))

	params := emittedPBKDF2Params(t, msg)
	assert.Empty(t, params.PRF.FullBytes, "prf equal to the RFC 8018 default must be omitted")
}

func TestPBMAC1KeepsNonDefaultPRFWhenEchoing(t *testing.T) {
	msg := echoProtect(t, peerPBMAC1AlgID(t, &oidHMACSHA256TestOnly))

	params := emittedPBKDF2Params(t, msg)
	require.NotEmpty(t, params.PRF.FullBytes, "a non-default prf must be encoded")

	var prf algIDTestOnly
	_, err := asn1.Unmarshal(params.PRF.FullBytes, &prf)
	require.NoError(t, err)
	assert.True(t, prf.Algorithm.Equal(oidHMACSHA256TestOnly))
}

// An explicitly encoded default must also be normalized away on the echo.
func TestPBMAC1OmitsExplicitlyEncodedDefaultPRF(t *testing.T) {
	msg := echoProtect(t, peerPBMAC1AlgID(t, &oidHMACSHA1TestOnly))

	params := emittedPBKDF2Params(t, msg)
	assert.Empty(t, params.PRF.FullBytes, "an explicit HMAC-SHA-1 prf must still be omitted on re-encode")
}

// Omitting prf must not change what the MAC verifies to.
func TestPBMAC1WithOmittedPRFStillVerifies(t *testing.T) {
	msg := echoProtect(t, peerPBMAC1AlgID(t, nil))

	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(encoded)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("shared-secret")})
	require.NoError(t, err)
}
