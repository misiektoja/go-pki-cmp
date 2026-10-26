package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewClient uses its own HTTP client with DefaultHTTPTimeout, so a CA that
// accepts the connection and never answers does not hold the call forever.
func TestDefaultHTTPTimeout(t *testing.T) {
	c := NewClient("http://cmp.example")
	require.NotSame(t, http.DefaultClient, c.httpClient)
	assert.Equal(t, DefaultHTTPTimeout, c.httpClient.Timeout)
	assert.Nil(t, c.httpClient.Transport, "the default transport keeps the proxy settings")

	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	c = NewClient(ts.URL)
	c.httpClient.Timeout = 50 * time.Millisecond
	_, err := c.sendHTTP(context.Background(), []byte{0x30, 0x00})
	require.Error(t, err)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
}

// WithHTTPClient replaces the default client together with its timeout.
func TestWithHTTPClientReplacesDefault(t *testing.T) {
	hc := &http.Client{}
	c := NewClient("http://cmp.example", WithHTTPClient(hc))
	assert.Same(t, hc, c.httpClient)
}
