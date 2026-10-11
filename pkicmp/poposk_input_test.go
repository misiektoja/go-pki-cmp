package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// poposkRequest describes how a test request encodes its poposkInput.
type poposkRequest struct {
	subject     bool         // the template carries a subject
	sender      *GeneralName // authInfo sender. A nil sender selects publicKeyMAC
	secret      []byte       // shared secret for publicKeyMAC
	iterations  int          // PBM iteration count, 1000 when zero
	macOverBits bool         // MAC the subjectPublicKey bits instead of the SPKI
	signTagged  bool         // sign the [0] element instead of the SEQUENCE
	otherKey    bool         // put a different public key in poposkInput
}

// newPoposkRequest builds and round-trips a CertReqMsg whose signature proof carries poposkInput.
func newPoposkRequest(t *testing.T, r poposkRequest) *CertReqMsg {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	template := CertTemplate{PublicKey: spki}
	if r.subject {
		template.Subject = NewDirectoryName(pkix.Name{CommonName: "device-1"})
	}
	input := &popoSigningKeyInput{PublicKey: spki, Sender: r.sender}
	if r.otherKey {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		input.PublicKey, err = x509.MarshalPKIXPublicKey(&other.PublicKey)
		require.NoError(t, err)
	}
	if r.sender == nil {
		input.PublicKeyMAC = testPublicKeyMAC(t, r, input.PublicKey)
	}

	var content cryptobyte.Builder
	input.marshalInner(&marshalContext{MinRequiredPVNO: PVNO2}, &content)
	tag := cbasn1.SEQUENCE
	if r.signTagged {
		tag = cbasn1.Tag(0).ContextSpecific().Constructed()
	}
	digest := sha256.Sum256(wrapASN1(tag, content.BytesOrPanic()))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	reqMsg := &CertReqMsg{
		CertReq: CertRequest{CertTemplate: template},
		Popo: &proofOfPossession{Signature: &popoSigningKey{
			PoposkInput: input,
			Algorithm:   AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
			Signature:   signature,
		}},
	}
	return roundTripCertReqMsg(t, reqMsg)
}

// testPublicKeyMAC computes a PasswordBasedMac publicKeyMAC over spki or over its key bits, as r selects.
func testPublicKeyMAC(t *testing.T, r poposkRequest, spki []byte) *pkMACValue {
	t.Helper()
	iterations := r.iterations
	if iterations == 0 {
		iterations = 1000
	}
	params := pbmParameter{
		Salt:           []byte("poposkInput-salt"),
		OWF:            AlgorithmIdentifier{Algorithm: oidSHA256},
		IterationCount: iterations,
		MAC:            AlgorithmIdentifier{Algorithm: oidHMACWithSHA256},
	}
	var b cryptobyte.Builder
	params.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	key, err := derivePBMKey(r.secret, params.Salt, iterations, crypto.SHA256, crypto.SHA256)
	require.NoError(t, err)
	data := spki
	if r.macOverBits {
		data, err = subjectPublicKeyBits(spki)
		require.NoError(t, err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return &pkMACValue{
		Algorithm: AlgorithmIdentifier{Algorithm: oidPasswordBasedMac, Parameters: b.BytesOrPanic()},
		Value:     mac.Sum(nil),
	}
}

// The RFC 4211 §4.1 poposkInput is verified. The encodings the Insta Certifier
// 10 cmpclient uses instead are accepted only with AllowPoposkInputVariants.
func TestVerifyPOPWithPoposkInput(t *testing.T) {
	secret := []byte("poposkInput-secret")
	subjectDER := mustMarshalName(t, pkix.Name{CommonName: "signer"})
	sender := NewDirectoryNameFromRawDER(subjectDER)
	bareSender := GeneralName{Raw: subjectDER}
	otherSender := NewDirectoryName(pkix.Name{CommonName: "someone-else"})

	tests := []struct {
		name    string
		request poposkRequest
		opts    POPOptions
		wantErr string // substring of the error, empty for success
		reason  InvalidReason
	}{
		{name: "SenderWithoutSubject", request: poposkRequest{sender: &sender}, opts: POPOptions{Sender: &sender}},
		{name: "SenderMismatch", request: poposkRequest{sender: &sender}, opts: POPOptions{Sender: &otherSender}, wantErr: "sender does not match"},
		{name: "SenderWithoutAuthenticatedName", request: poposkRequest{sender: &sender}, wantErr: "sender does not match"},
		{name: "PublicKeyMACWithoutSubject", request: poposkRequest{secret: secret}, opts: POPOptions{SharedSecret: secret}},
		{name: "PublicKeyMACWrongSecret", request: poposkRequest{secret: []byte("wrong")}, opts: POPOptions{SharedSecret: secret}, reason: ReasonBadMAC},
		{name: "PublicKeyMACWithoutSecret", request: poposkRequest{secret: secret}, reason: ReasonMissingSharedSecret},
		{name: "PublicKeyMACAboveMaximumIterations", request: poposkRequest{secret: secret, iterations: 2000}, opts: POPOptions{SharedSecret: secret, MaxMACIterationCount: 1000}, wantErr: "iterationCount too large"},
		{name: "KeyMismatch", request: poposkRequest{secret: secret, otherKey: true}, opts: POPOptions{SharedSecret: secret, AllowPoposkInputVariants: true}, wantErr: "public key does not match"},
		{name: "FullTemplateRefused", request: poposkRequest{subject: true, secret: secret}, opts: POPOptions{SharedSecret: secret}, wantErr: "poposkInput not allowed"},
		{name: "FullTemplateVariant", request: poposkRequest{subject: true, secret: secret}, opts: POPOptions{SharedSecret: secret, AllowPoposkInputVariants: true}},
		{name: "TaggedSignatureRefused", request: poposkRequest{secret: secret, signTagged: true}, opts: POPOptions{SharedSecret: secret}, wantErr: "verification"},
		{name: "TaggedSignatureVariant", request: poposkRequest{secret: secret, signTagged: true}, opts: POPOptions{SharedSecret: secret, AllowPoposkInputVariants: true}},
		{name: "MACOverKeyBitsRefused", request: poposkRequest{secret: secret, macOverBits: true}, opts: POPOptions{SharedSecret: secret}, reason: ReasonBadMAC},
		{name: "MACOverKeyBitsVariant", request: poposkRequest{secret: secret, macOverBits: true}, opts: POPOptions{SharedSecret: secret, AllowPoposkInputVariants: true}},
		{name: "BareNameSenderRefused", request: poposkRequest{sender: &bareSender}, opts: POPOptions{Sender: &sender}, wantErr: "sender does not match"},
		{name: "BareNameSenderVariant", request: poposkRequest{sender: &bareSender}, opts: POPOptions{Sender: &sender, AllowPoposkInputVariants: true}},
		{name: "BareNameSenderVariantMismatch", request: poposkRequest{sender: &bareSender}, opts: POPOptions{Sender: &otherSender, AllowPoposkInputVariants: true}, wantErr: "sender does not match"},
		{
			name:    "AllVariantsTogether",
			request: poposkRequest{subject: true, secret: secret, macOverBits: true, signTagged: true},
			opts:    POPOptions{SharedSecret: secret, AllowPoposkInputVariants: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPOPWithOptions(newPoposkRequest(t, tt.request), tt.opts)
			switch {
			case tt.reason != 0:
				var verr *VerificationError
				require.True(t, errors.As(err, &verr), "want VerificationError, got %v", err)
				assert.Equal(t, tt.reason, verr.Reason)
			case tt.wantErr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			default:
				assert.NoError(t, err)
			}
		})
	}
}

// mustMarshalName returns the DER encoding of name.
func mustMarshalName(t *testing.T, name pkix.Name) []byte {
	t.Helper()
	gn := NewDirectoryName(name)
	der := generalNameDER(&gn)
	s := cryptobyte.String(der)
	var inner cryptobyte.String
	require.True(t, s.ReadASN1(&inner, cbasn1.Tag(4).ContextSpecific().Constructed()))
	return inner
}

// A poposkInput must hold exactly one authInfo and one public key.
func TestPoposkInputMalformed(t *testing.T) {
	spki := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	tests := map[string]func(b *cryptobyte.Builder){
		"MissingAuthInfo": func(b *cryptobyte.Builder) {
			b.AddBytes(spki)
		},
		"TrailingDataAfterKey": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(mustMarshalName(t, pkix.Name{CommonName: "a"}))
			})
			b.AddBytes(spki)
			b.AddASN1Int64(1)
		},
		"TwoSenderNames": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(mustMarshalName(t, pkix.Name{CommonName: "a"}))
				b.AddBytes(mustMarshalName(t, pkix.Name{CommonName: "b"}))
			})
			b.AddBytes(spki)
		},
		"MACWithUnusedBits": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				alg := AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}
				alg.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x01, 0xfe}) })
			})
			b.AddBytes(spki)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			var b cryptobyte.Builder
			build(&b)
			s := cryptobyte.String(b.BytesOrPanic())
			var input popoSigningKeyInput
			assert.Error(t, input.unmarshalInner(&s))
		})
	}
}
