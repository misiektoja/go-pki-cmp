package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidPBM             = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHMACWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
)

// poposkAuthInfo writes the authInfo of a test poposkInput.
type poposkAuthInfo func(b *cryptobyte.Builder, spki []byte)

// bareNameSender writes the sender as a bare Name inside [0], as the Insta
// Certifier 10 cmpclient does, instead of a GeneralName directoryName.
func bareNameSender(name []byte) poposkAuthInfo {
	return func(b *cryptobyte.Builder, _ []byte) {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddBytes(name) })
	}
}

// keyBitsMAC writes a PasswordBasedMac publicKeyMAC over the subjectPublicKey
// bits, as the Insta Certifier 10 cmpclient does, instead of the DER SubjectPublicKeyInfo.
func keyBitsMAC(t *testing.T, secret []byte) poposkAuthInfo {
	return func(b *cryptobyte.Builder, spki []byte) {
		salt := []byte("poposkInput-salt")
		const iterations = 1000
		k := sha256.Sum256(append(append([]byte(nil), secret...), salt...))
		for i := 1; i < iterations; i++ {
			k = sha256.Sum256(k[:])
		}
		var info struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		_, err := asn1.Unmarshal(spki, &info)
		require.NoError(t, err)
		mac := hmac.New(sha256.New, k[:])
		mac.Write(info.PublicKey.Bytes)

		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPBM)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(salt)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidSHA256) })
					b.AddASN1Int64(iterations)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidHMACWithSHA256) })
				})
			})
			b.AddASN1BitString(mac.Sum(nil))
		})
	}
}

// poposkRequest returns an unprotected ir or cr for subject whose signature
// proof carries a poposkInput with authInfo, signed over its [0] element as
// the Insta Certifier 10 cmpclient does.
func poposkRequest(t *testing.T, bodyType pkicmp.BodyType, subject pkix.Name, opts pkicmp.MessageOptions, authInfo poposkAuthInfo) *pkicmp.PKIMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// Take the CertRequest encoding from a request the library builds.
	request := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
		Subject:   pkicmp.NewDirectoryName(subject),
		PublicKey: spki,
	}}}
	template := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{request}), opts)
	der, err := template.MarshalBinary()
	require.NoError(t, err)
	var message, header, body, msgs, reqMsg, certReq cryptobyte.String
	in := cryptobyte.String(der)
	require.True(t, in.ReadASN1(&message, cbasn1.SEQUENCE))
	require.True(t, message.ReadASN1Element(&header, cbasn1.SEQUENCE))
	require.True(t, message.ReadASN1(&body, cbasn1.Tag(0).ContextSpecific().Constructed()))
	require.True(t, body.ReadASN1(&msgs, cbasn1.SEQUENCE))
	require.True(t, msgs.ReadASN1(&reqMsg, cbasn1.SEQUENCE))
	require.True(t, reqMsg.ReadASN1Element(&certReq, cbasn1.SEQUENCE))

	var input cryptobyte.Builder
	authInfo(&input, spki)
	input.AddBytes(spki)
	content := input.BytesOrPanic()
	var signed cryptobyte.Builder
	signed.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddBytes(content) })
	digest := sha256.Sum256(signed.BytesOrPanic())
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	tag := cbasn1.Tag(0).ContextSpecific().Constructed()
	if bodyType == pkicmp.BodyTypeCR {
		tag = cbasn1.Tag(2).ContextSpecific().Constructed()
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(header)
		b.AddASN1(tag, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(certReq)
					b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddBytes(content) })
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidECDSAWithSHA256) })
						b.AddASN1BitString(signature)
					})
				})
			})
		})
	})
	msg, err := pkicmp.ParsePKIMessage(b.BytesOrPanic())
	require.NoError(t, err)
	return msg
}

// A MAC-protected ir with the poposkInput the Insta Certifier 10 cmpclient
// sends is refused unless WithPoposkInputVariants is set.
// WithStrictProfileValidation always refuses it.
func TestPoposkInputVariantsWithMAC(t *testing.T) {
	secret := []byte("poposkInput-secret")
	newRequest := func(t *testing.T, macSecret []byte) *pkicmp.PKIMessage {
		msg := poposkRequest(t, pkicmp.BodyTypeIR, pkix.Name{CommonName: "device-1"}, macMessageOpts(), keyBitsMAC(t, macSecret))
		protectMAC(msg, secret)
		return msg
	}

	tests := []struct {
		name      string
		opts      []server.Option
		macSecret []byte
		wantText  string // status text of a badPOP refusal, empty for issuance
	}{
		{name: "RefusedByDefault", wantText: "poposkInput not allowed when the template contains the subject and public key"},
		{name: "AcceptedWithOption", opts: []server.Option{server.WithPoposkInputVariants()}},
		{name: "WrongSecretInPublicKeyMAC", opts: []server.Option{server.WithPoposkInputVariants()}, macSecret: []byte("other-secret"), wantText: "poposkInput publicKeyMAC does not verify"},
		{name: "RefusedUnderStrictProfile", opts: []server.Option{server.WithPoposkInputVariants(), server.WithStrictProfileValidation()}, wantText: "poposkInput is not allowed in the proof of possession"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, ca := newConfirmingServer(t, secret, tt.opts...)
			macSecret := secret
			if tt.macSecret != nil {
				macSecret = tt.macSecret
			}
			si := statusInfoOf(t, postCMP(t, ts, newRequest(t, macSecret)))
			if tt.wantText == "" {
				require.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
				assert.Equal(t, "device-1", ca.template.Subject.CommonName)
				return
			}
			assert.Equal(t, pkicmp.StatusRejection, si.Status)
			assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
			require.NotEmpty(t, si.StatusString)
			assert.Contains(t, si.StatusString[0], tt.wantText)
		})
	}

	// A MAC-protected request has no authenticated name for a sender authInfo.
	t.Run("SenderWithoutCertificate", func(t *testing.T) {
		ts, _ := newConfirmingServer(t, secret, server.WithPoposkInputVariants())
		name, err := asn1.Marshal(pkix.Name{CommonName: "test"}.ToRDNSequence())
		require.NoError(t, err)
		msg := poposkRequest(t, pkicmp.BodyTypeIR, pkix.Name{CommonName: "device-1"}, macMessageOpts(), bareNameSender(name))
		protectMAC(msg, secret)
		si := statusInfoOf(t, postCMP(t, ts, msg))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
	})
}

// In a signed cr the poposkInput sender must name the certificate that signed the request.
func TestPoposkInputVariantsWithSignature(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	device := &certyaml.Certificate{Subject: "CN=device-old", Issuer: ca}
	deviceCert, err := device.X509Certificate()
	require.NoError(t, err)
	deviceKey, err := device.PrivateKey()
	require.NoError(t, err)

	newServer := func(t *testing.T, opts ...server.Option) *httptest.Server {
		opts = append(opts, server.WithCertificateLookup(&staticCertLookup{cert: &deviceCert}))
		ts := httptest.NewServer(server.NewCAServer(&recordingCA{ca: ca}, server.LightweightPolicy(), opts...))
		t.Cleanup(ts.Close)
		return ts
	}
	newRequest := func(t *testing.T, senderName []byte) *pkicmp.PKIMessage {
		opts := pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(deviceCert.RawSubject)}
		msg := poposkRequest(t, pkicmp.BodyTypeCR, pkix.Name{CommonName: "device-new"}, opts, bareNameSender(senderName))
		creds, err := pkicmp.NewSignatureCredentials(deviceKey, &deviceCert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		return msg
	}
	other, err := asn1.Marshal(pkix.Name{CommonName: "someone-else"}.ToRDNSequence())
	require.NoError(t, err)

	t.Run("RefusedByDefault", func(t *testing.T) {
		si := statusInfoOf(t, postCMP(t, newServer(t), newRequest(t, deviceCert.RawSubject)))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
	})
	t.Run("SignerSubjectAccepted", func(t *testing.T) {
		si := statusInfoOf(t, postCMP(t, newServer(t, server.WithPoposkInputVariants()), newRequest(t, deviceCert.RawSubject)))
		assert.Equal(t, pkicmp.StatusAccepted, si.Status, "status text %v", si.StatusString)
	})
	t.Run("OtherSenderRefused", func(t *testing.T) {
		si := statusInfoOf(t, postCMP(t, newServer(t, server.WithPoposkInputVariants()), newRequest(t, other)))
		assert.Equal(t, pkicmp.FailBadPOP, si.FailInfo)
		require.NotEmpty(t, si.StatusString)
		assert.Contains(t, si.StatusString[0], "poposkInput sender does not match the authenticated sender")
	})
}
