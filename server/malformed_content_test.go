package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// postRaw posts der and returns the HTTP status and, for a 200 answer, the parsed response.
func postRaw(t *testing.T, ts *httptest.Server, der []byte) (int, *pkicmp.PKIMessage) {
	t.Helper()
	resp, err := http.Post(ts.URL, "application/pkixcmp", bytes.NewReader(der))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	parsed, err := pkicmp.ParsePKIMessage(body)
	require.NoError(t, err)
	return resp.StatusCode, parsed
}

// appendInsideMessage adds extra to the end of the outer PKIMessage SEQUENCE of der.
func appendInsideMessage(t *testing.T, der, extra []byte) []byte {
	t.Helper()
	s := cryptobyte.String(der)
	var content cryptobyte.String
	require.True(t, s.ReadASN1(&content, cbasn1.SEQUENCE))
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(content)
		b.AddBytes(extra)
	})
	out, err := b.Bytes()
	require.NoError(t, err)
	return out
}

// assertBadDataFormat checks that resp refuses req with badDataFormat in the same transaction.
// An error message and a certificate response with status rejection are both negative answers.
func assertBadDataFormat(t *testing.T, req, resp *pkicmp.PKIMessage) {
	t.Helper()
	require.NotNil(t, resp)
	si := statusInfoOf(t, resp)
	assert.Equal(t, pkicmp.StatusRejection, si.Status)
	assert.Equal(t, pkicmp.FailBadDataFormat, si.FailInfo, "status text %v", si.StatusString)
	assert.Equal(t, req.Header.TransactionID, resp.Header.TransactionID)
	assert.Equal(t, req.Header.SenderNonce, resp.Header.RecipNonce)
}

// An infoValue that is not exactly one DER element is malformed (RFC 9483 section 3.5), so the
// general message is refused with badDataFormat instead of being answered.
func TestGeneralMessageMalformedInfoValue(t *testing.T) {
	f := newRevocationFixture(t)
	signKeyPairTypes := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 2}
	for _, profile := range []struct {
		name string
		opts []server.Option
	}{
		{name: "Default"},
		{name: "Strict", opts: []server.Option{server.WithStrictProfileValidation()}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			ts := f.serve(t, &generalCA{}, server.LightweightPolicy(), profile.opts...)
			for name, value := range map[string][]byte{
				// The ASCII text True, as the Siemens suite sends it. As a TLV it claims more content than follows.
				"NotDER":       []byte("True"),
				"TwoElements":  {0x05, 0x00, 0x05, 0x00},
				"TruncatedTLV": {0x04, 0x05, 0x01},
			} {
				t.Run(name, func(t *testing.T) {
					req := signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.InfoTypeAndValue{InfoType: signKeyPairTypes, InfoValue: value})
					assertBadDataFormat(t, req, postCMP(t, ts, req))
				})
			}
		})
	}
}

// A certificate request that cannot be decoded is refused with badDataFormat.
func TestMalformedCertificateRequest(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, &generalCA{}, server.LightweightPolicy())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// signed protects body for the end entity of the fixture.
	signed := func(t *testing.T, body *pkicmp.PKIBody) *pkicmp.PKIMessage {
		req := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(f.ee.cert.RawSubject)})
		creds, err := pkicmp.NewSignatureCredentials(f.ee.key, f.ee.cert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(req))
		return req
	}

	t.Run("Body", func(t *testing.T) {
		// cr [2] holding an INTEGER where CertReqMessages belongs.
		req := signed(t, &pkicmp.PKIBody{Type: pkicmp.BodyTypeCR, Raw: []byte{0xa2, 0x03, 0x02, 0x01, 0x00}})
		assertBadDataFormat(t, req, postCMP(t, ts, req))
	})
	t.Run("TemplateExtensions", func(t *testing.T) {
		reqMsg := newCertReqMsg(t, key, "device-1")
		// A SEQUENCE holding an INTEGER where Extension SEQUENCEs belong.
		reqMsg.CertReq.CertTemplate.Extensions = []byte{0x30, 0x03, 0x02, 0x01, 0x00}
		req := signed(t, pkicmp.NewCRBody(&pkicmp.CertReqMessages{reqMsg}))
		assertBadDataFormat(t, req, postCMP(t, ts, req))
	})
	t.Run("TemplateValidity", func(t *testing.T) {
		reqMsg := newCertReqMsg(t, key, "device-1")
		reqMsg.CertReq.CertTemplate.Validity = &pkicmp.OptionalValidity{NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
		der, err := pkicmp.NewPKIMessage(pkicmp.NewCRBody(&pkicmp.CertReqMessages{reqMsg}), pkicmp.MessageOptions{}).MarshalBinary()
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePKIMessage(der)
		require.NoError(t, err)
		// notAfter [1] holding an INTEGER of the same length where a Time belongs.
		notAfter := []byte{0xa1, 0x0f, 0x17, 0x0d}
		require.Equal(t, 1, bytes.Count(parsed.Body.Raw, notAfter))
		raw := bytes.Replace(parsed.Body.Raw, notAfter, []byte{0xa1, 0x0f, 0x02, 0x0d}, 1)
		req := signed(t, &pkicmp.PKIBody{Type: pkicmp.BodyTypeCR, Raw: raw})
		assertBadDataFormat(t, req, postCMP(t, ts, req))
	})
}

// A message whose header can be read but whose structure after it is malformed gets a CMP error,
// so the client learns why. Input with no readable header keeps HTTP 400.
func TestMalformedMessageStructure(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, &generalCA{}, server.LightweightPolicy())
	caCerts := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}

	t.Run("TrailingDataInsideMessage", func(t *testing.T) {
		req := signedGenM(t, f.ee, pkicmp.MessageOptions{}, caCerts)
		der, err := req.MarshalBinary()
		require.NoError(t, err)
		status, resp := postRaw(t, ts, appendInsideMessage(t, der, []byte{0x05, 0x00}))
		require.Equal(t, http.StatusOK, status)
		assertBadDataFormat(t, req, resp)
	})

	t.Run("MalformedProtection", func(t *testing.T) {
		req := pkicmp.NewPKIMessage(pkicmp.NewGenMBody(caCerts), pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(f.ee.cert.RawSubject)})
		der, err := req.MarshalBinary()
		require.NoError(t, err)
		// protection [0] holding a NULL where the BIT STRING belongs.
		status, resp := postRaw(t, ts, appendInsideMessage(t, der, []byte{0xa0, 0x02, 0x05, 0x00}))
		require.Equal(t, http.StatusOK, status)
		assertBadDataFormat(t, req, resp)
	})

	t.Run("NotCMP", func(t *testing.T) {
		status, _ := postRaw(t, ts, []byte("this dummy input is not a valid PKIMessage"))
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("MalformedHeader", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		req := pkicmp.NewPKIMessage(pkicmp.NewCRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "device-1")}), pkicmp.MessageOptions{})
		req.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{{InfoType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}, InfoValue: []byte("True")}}
		der, err := req.MarshalBinary()
		require.NoError(t, err)
		status, _ := postRaw(t, ts, der)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
