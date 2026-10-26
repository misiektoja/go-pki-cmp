package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// A message type the server does not handle, such as pkiConf from a client,
// is refused with a status text naming the reason.
func TestUnsupportedMessageTypeStatusText(t *testing.T) {
	secret := []byte("unsupported-secret")
	ts, _ := newConfirmingServer(t, secret)
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), macMessageOpts())
	protectMAC(msg, secret)
	si := statusInfoOf(t, postCMP(t, ts, msg))
	assert.Equal(t, pkicmp.FailBadRequest, si.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"message type not supported"}, si.StatusString)
}

// RFC 9810 §7: an unsupported pvno is refused with unsupportedVersion and a
// status text that names the value.
func TestUnsupportedPVNOStatusText(t *testing.T) {
	secret := []byte("pvno-secret")
	ts, _ := newConfirmingServer(t, secret)
	subject, subjectDER := requestedSubject(t)
	der, err := rawSubjectRequest(t, secret, subject, subjectDER, false).MarshalBinary()
	require.NoError(t, err)
	// The encoder always writes pvno 2 or higher, so patch the INTEGER that
	// opens the header, right after the message and header SEQUENCE tags.
	pvno := bytes.Index(der, []byte{0x02, 0x01, 0x02})
	require.Positive(t, pvno)
	require.Less(t, pvno, 16, "pvno is the first header field")
	der[pvno+2] = 0

	resp, err := http.Post(ts.URL, "application/pkixcmp", bytes.NewReader(der))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(body)
	require.NoError(t, err)
	si := statusInfoOf(t, parsed)
	assert.Equal(t, pkicmp.FailUnsupportedVersion, si.FailInfo)
	assert.Equal(t, pkicmp.PKIFreeText{"unsupported pvno 0"}, si.StatusString)
}

// A refused protection or recipient tells the peer the reason alone in the
// statusString, without the "server: status ..." text of the Go error.
func TestRefusalStatusStringIsTheReason(t *testing.T) {
	secret := []byte("status-text-secret")
	ca := &confirmingCA{ca: &certyaml.Certificate{Subject: "CN=Test CA"}}
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithSender(pkix.Name{CommonName: "Test CA"})))
	t.Cleanup(ts.Close)

	newIR := func(t *testing.T) *pkicmp.PKIMessage {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "status-text")}), macMessageOpts())
	}
	tests := []struct {
		name     string
		build    func(t *testing.T) *pkicmp.PKIMessage
		failInfo pkicmp.PKIFailureInfo
		text     string
	}{
		{
			name:     "unprotected",
			build:    newIR,
			failInfo: pkicmp.FailBadMessageCheck,
			text:     "message not protected",
		},
		{
			name: "wrong secret",
			build: func(t *testing.T) *pkicmp.PKIMessage {
				msg := newIR(t)
				protectMAC(msg, []byte("another-secret"))
				return msg
			},
			failInfo: pkicmp.FailBadMessageCheck,
			text:     "MAC verification failed",
		},
		{
			name: "wrong recipient",
			build: func(t *testing.T) *pkicmp.PKIMessage {
				msg := newIR(t)
				msg.Header.Recipient = pkicmp.NewDirectoryName(pkix.Name{CommonName: "Another CA"})
				protectMAC(msg, secret)
				return msg
			},
			failInfo: pkicmp.FailBadRequest,
			text:     "recipient does not match server identity",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := errorStatus(t, postCMP(t, ts, tc.build(t)))
			assert.Equal(t, tc.failInfo, status.FailInfo)
			assert.Equal(t, pkicmp.PKIFreeText{tc.text}, status.StatusString)
		})
	}
}
