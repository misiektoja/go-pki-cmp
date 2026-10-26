//go:build integration

package openssl

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// validityRecorder records the template validity of every ir a CMP server receives.
type validityRecorder struct {
	next     http.Handler
	mu       sync.Mutex
	validity []*pkicmp.OptionalValidity
}

// ServeHTTP parses an ir before passing the request on unchanged.
func (r *validityRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if msg, err := pkicmp.ParsePKIMessage(body); err == nil && msg.Body.Type == pkicmp.BodyTypeIR {
		if msgs, err := msg.Body.IR(); err == nil && len(*msgs) == 1 {
			r.mu.Lock()
			r.validity = append(r.validity, (*msgs)[0].CertReq.CertTemplate.Validity)
			r.mu.Unlock()
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	r.next.ServeHTTP(w, req)
}

// RFC 4211 §5: the template validity OpenSSL sends for -days parses with both bounds.
func TestOpenSSLClientRequestsValidity(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping OpenSSL integration test")
	}
	ca, err := mockserver.New(map[string][]byte{"test-ref": []byte("enrollment-secret")}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	srv := server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithSecretLookup(ca),
	)
	require.NoError(t, srv.Err())
	recorder := &validityRecorder{next: srv}
	ts := httptest.NewServer(recorder)
	defer ts.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", ca.Cert().Raw)
	sent := time.Now()
	_, err = runOpenSSLCMPClient(t,
		"-cmd", "ir",
		"-server", strings.TrimPrefix(ts.URL, "http://"),
		"-path", "/",
		"-ref", "test-ref",
		"-secret", "pass:enrollment-secret",
		"-trusted", caFile,
		"-newkey", writeNewKey(t, dir),
		"-subject", "/CN=openssl-validity",
		"-days", "30",
		"-certout", filepath.Join(dir, "issued.pem"),
	)
	require.NoError(t, err, "openssl cmp ir -days")

	require.Len(t, recorder.validity, 1)
	validity := recorder.validity[0]
	require.NotNil(t, validity, "the ir carries a validity")
	assert.WithinDuration(t, sent, validity.NotBefore, time.Minute, "notBefore is the request time")
	assert.WithinDuration(t, sent.Add(30*24*time.Hour), validity.NotAfter, time.Minute, "notAfter is 30 days later")
}

// RFC 4211 §5: the OpenSSL mock server accepts an ir whose template asks for a validity.
func TestOpenSSLInitializeWithValidity(t *testing.T) {
	srv := newOpenSSLCMPServer(t, opensslCMPServerOpts{
		SrvRef:    "test-ref",
		SrvSecret: "enrollment-secret",
	})
	creds, err := pkicmp.NewMACCredentials([]byte("enrollment-secret"), pkicmp.WithPBM())
	require.NoError(t, err)
	// The mock server always returns its pre-configured rsp_cert, which certifies this key.
	key := srv.RspKey

	c := client.NewClient(srv.Endpoint,
		client.WithRecipient(srv.CACert.Subject),
		client.WithTrustedCAs(srv.TrustedCAs()),
	)
	now := time.Now()
	for name, opt := range map[string]client.RequestOption{
		"both bounds":   client.WithTemplateValidity(now, now.Add(30*24*time.Hour)),
		"notAfter only": client.WithTemplateValidity(time.Time{}, now.Add(30*24*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := c.SendIR(context.Background(), key, creds,
				client.WithTemplateSubject(pkix.Name{CommonName: "openssl-validity"}),
				opt,
			)
			require.NoError(t, err, "SendIR with a template validity")
			require.NotNil(t, result.Certificate)
		})
	}
}
