package server_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
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
