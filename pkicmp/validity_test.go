package pkicmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// marshalTemplate encodes a CertTemplate on its own.
func marshalTemplate(t *testing.T, tmpl CertTemplate) ([]byte, error) {
	t.Helper()
	var b cryptobyte.Builder
	tmpl.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	return b.Bytes()
}

// parseTemplate decodes a CertTemplate on its own.
func parseTemplate(der []byte) (CertTemplate, error) {
	var tmpl CertTemplate
	s := cryptobyte.String(der)
	err := tmpl.unmarshal(&s)
	return tmpl, err
}

// RFC 4211 §5: validity [4] is IMPLICIT and its Time bounds are EXPLICIT [0] and [1].
func TestCertTemplateValidityEncoding(t *testing.T) {
	tmpl := CertTemplate{Validity: &OptionalValidity{
		NotBefore: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 1, 24, 12, 0, 0, 0, time.UTC),
	}}
	der, err := marshalTemplate(t, tmpl)
	require.NoError(t, err)
	expected := "3024" + "a422" +
		"a00f" + "170d" + hex.EncodeToString([]byte("261026120000Z")) +
		"a10f" + "170d" + hex.EncodeToString([]byte("270124120000Z"))
	assert.Equal(t, expected, hex.EncodeToString(der))

	parsed, err := parseTemplate(der)
	require.NoError(t, err)
	require.NotNil(t, parsed.Validity)
	assert.True(t, parsed.Validity.NotBefore.Equal(tmpl.Validity.NotBefore))
	assert.True(t, parsed.Validity.NotAfter.Equal(tmpl.Validity.NotAfter))
}

// RFC 5280 §4.1.2.5: UTCTime through 2049 and GeneralizedTime from 2050, in UTC to the second.
func TestCertTemplateValidityTimes(t *testing.T) {
	warsaw := time.FixedZone("CET", 3600)
	tests := []struct {
		name     string
		validity OptionalValidity
		tags     []cbasn1.Tag
	}{
		{
			name:     "notAfter only",
			validity: OptionalValidity{NotAfter: time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)},
			tags:     []cbasn1.Tag{cbasn1.UTCTime},
		},
		{
			name:     "notBefore only",
			validity: OptionalValidity{NotBefore: time.Date(2026, 10, 26, 13, 0, 0, 0, warsaw)},
			tags:     []cbasn1.Tag{cbasn1.UTCTime},
		},
		{
			name: "GeneralizedTime from 2050",
			validity: OptionalValidity{
				NotBefore: time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			tags: []cbasn1.Tag{cbasn1.UTCTime, cbasn1.GeneralizedTime},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der, err := marshalTemplate(t, CertTemplate{Validity: &tc.validity})
			require.NoError(t, err)

			s := cryptobyte.String(der)
			var seq, validity cryptobyte.String
			require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE))
			require.True(t, seq.ReadASN1(&validity, cbasn1.Tag(4).ContextSpecific().Constructed()))
			var tags []cbasn1.Tag
			for !validity.Empty() {
				var bound cryptobyte.String
				var tag cbasn1.Tag
				require.True(t, validity.ReadAnyASN1(&bound, &tag))
				var timeTag cbasn1.Tag
				var value cryptobyte.String
				require.True(t, bound.ReadAnyASN1(&value, &timeTag))
				tags = append(tags, timeTag)
			}
			assert.Equal(t, tc.tags, tags)

			parsed, err := parseTemplate(der)
			require.NoError(t, err)
			require.NotNil(t, parsed.Validity)
			assert.True(t, parsed.Validity.NotBefore.Equal(tc.validity.NotBefore), "notBefore")
			assert.True(t, parsed.Validity.NotAfter.Equal(tc.validity.NotAfter), "notAfter")
		})
	}

	t.Run("fractions of a second are dropped", func(t *testing.T) {
		requested := time.Date(2026, 10, 26, 12, 0, 0, 999_000_000, time.UTC)
		der, err := marshalTemplate(t, CertTemplate{Validity: &OptionalValidity{NotAfter: requested}})
		require.NoError(t, err)
		parsed, err := parseTemplate(der)
		require.NoError(t, err)
		assert.True(t, parsed.Validity.NotAfter.Equal(requested.Truncate(time.Second)))
	})
}

// RFC 4211 §5: the CertTemplate fields follow their tag order.
func TestCertTemplateValidityFieldOrder(t *testing.T) {
	issuer, err := asn1.Marshal(pkix.Name{CommonName: "Issuer"}.ToRDNSequence())
	require.NoError(t, err)
	tmpl := CertTemplate{
		Issuer:    issuer,
		Validity:  &OptionalValidity{NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		Subject:   NewDirectoryName(pkix.Name{CommonName: "Subject"}),
		PublicKey: []byte{0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03},
	}
	der, err := marshalTemplate(t, tmpl)
	require.NoError(t, err)

	s := cryptobyte.String(der)
	var seq cryptobyte.String
	require.True(t, s.ReadASN1(&seq, cbasn1.SEQUENCE))
	var tags []cbasn1.Tag
	for !seq.Empty() {
		var field cryptobyte.String
		var tag cbasn1.Tag
		require.True(t, seq.ReadAnyASN1(&field, &tag))
		tags = append(tags, tag)
	}
	assert.Equal(t, []cbasn1.Tag{
		cbasn1.Tag(3).ContextSpecific().Constructed(),
		cbasn1.Tag(4).ContextSpecific().Constructed(),
		cbasn1.Tag(5).ContextSpecific().Constructed(),
		cbasn1.Tag(6).ContextSpecific().Constructed(),
	}, tags)
}

// RFC 4211 §5: at least one bound must be present, so an empty validity is refused both ways.
func TestCertTemplateValidityRefusesMalformed(t *testing.T) {
	_, err := marshalTemplate(t, CertTemplate{Validity: &OptionalValidity{}})
	require.ErrorContains(t, err, "neither notBefore nor notAfter")

	utc := "170d" + hex.EncodeToString([]byte("270124120000Z"))
	tests := map[string]string{
		"no bound":              "3002" + "a400",
		"two notBefore":         "3024" + "a422" + "a00f" + utc + "a00f" + utc,
		"bounds out of order":   "3024" + "a422" + "a10f" + utc + "a00f" + utc,
		"not a Time":            "3007" + "a405" + "a103" + "020101",
		"bad UTCTime":           "3013" + "a411" + "a10f" + "170d" + hex.EncodeToString([]byte("2701241200XXZ")),
		"data after the Time":   "3015" + "a413" + "a111" + utc + "0500",
		"data after the bounds": "3015" + "a413" + "a10f" + utc + "0500",
		"primitive tag":         "3013" + "8411" + "a10f" + utc,
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			der, err := hex.DecodeString(encoded)
			require.NoError(t, err)
			tmpl, err := parseTemplate(der)
			if name == "primitive tag" {
				// A primitive [4] is not the validity field, so it is skipped like other unknown fields.
				require.NoError(t, err)
				assert.Nil(t, tmpl.Validity)
				return
			}
			require.Error(t, err)
		})
	}
}

// receivedRequest sends a CertReqMsg in an ir and returns it as the recipient parses it.
func receivedRequest(t *testing.T, reqMsg CertReqMsg) CertReqMsg {
	t.Helper()
	msgs := CertReqMessages{reqMsg}
	der, err := NewPKIMessage(NewIRBody(&msgs), MessageOptions{}).MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	ir, err := parsed.Body.IR()
	require.NoError(t, err)
	require.Len(t, *ir, 1)
	return (*ir)[0]
}

// The signature proof of possession covers the requested validity.
func TestCertTemplateValidityInSignedRequest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	validity := &OptionalValidity{NotAfter: time.Date(2027, 1, 24, 12, 0, 0, 0, time.UTC)}
	reqMsg := CertReqMsg{CertReq: CertRequest{CertTemplate: CertTemplate{
		Subject:   NewDirectoryName(pkix.Name{CommonName: "device"}),
		PublicKey: publicKey,
		Validity:  validity,
	}}}
	require.NoError(t, reqMsg.GeneratePOP(key))

	received := receivedRequest(t, reqMsg)
	require.NotNil(t, received.CertReq.CertTemplate.Validity)
	assert.True(t, received.CertReq.CertTemplate.Validity.NotAfter.Equal(validity.NotAfter))
	assert.True(t, received.CertReq.CertTemplate.Validity.NotBefore.IsZero())
	require.NoError(t, VerifyPOP(&received))

	tampered := reqMsg
	tampered.CertReq.CertTemplate.Validity = &OptionalValidity{NotAfter: validity.NotAfter.Add(time.Hour)}
	received = receivedRequest(t, tampered)
	assert.Error(t, VerifyPOP(&received), "a changed validity breaks the proof of possession")
}
