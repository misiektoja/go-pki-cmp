//go:build integration

package certifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/examples/mockserver"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
)

const (
	defaultImage = "go-pkicmp-certifier-clients"
	pskReference = "00112233445566778899aabbccddeeff"
	pskSecret    = "certifier-integration-secret"
	// caName is the subject mockserver gives its CA, which the clients name as recipient.
	caName      = "CN=Test CA"
	execTimeout = 3 * time.Minute
	// exitSIGSEGV is the status docker exec reports for a client killed by SIGSEGV.
	exitSIGSEGV = 128 + 11
)

// shared holds the one client container the tests in this package use.
var shared struct {
	once sync.Once
	c    *clientContainer
	skip string
	err  error
}

// TestMain stops the shared client container after the tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if shared.c != nil {
		shared.c.stop()
	}
	os.Exit(code)
}

// clientContainer is a running container of the client image that the tests exec into.
type clientContainer struct {
	id string
	// serverHost is how the container reaches a listener on the host loopback interface.
	serverHost   string
	hasSSHClient bool
}

// clients returns the shared client container, starting it on first use. It skips the test when Docker or the image is missing.
func clients(t *testing.T) *clientContainer {
	t.Helper()
	shared.once.Do(func() { shared.c, shared.skip, shared.err = startContainer() })
	if shared.skip != "" {
		t.Skip(shared.skip)
	}
	require.NoError(t, shared.err)
	return shared.c
}

// startContainer starts the client image. It returns a skip reason when the image cannot be used on this host.
func startContainer() (*clientContainer, string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, "docker not found in PATH", nil
	}
	image := os.Getenv("CERTIFIER_CLIENT_IMAGE")
	if image == "" {
		image = defaultImage
	}
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		return nil, fmt.Sprintf("image %s not found, see test/integration/certifier/README.md", image), nil
	}
	c := &clientContainer{serverHost: "host.docker.internal"}
	args := []string{"run", "--rm", "-d", "--platform", "linux/amd64", "--entrypoint", "sleep"}
	// Docker on Linux can share the host network. Docker Desktop and Colima
	// forward host.docker.internal to the host loopback interface instead.
	if runtime.GOOS == "linux" {
		args = append(args, "--network", "host")
		c.serverHost = "127.0.0.1"
	} else {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	args = append(args, image, "infinity")
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, "", fmt.Errorf("start %s: %w", image, commandError(err))
	}
	c.id = strings.TrimSpace(string(out))
	c.hasSSHClient = exec.Command("docker", "exec", c.id, "test", "-x", "/usr/local/certifier/bin/ssh-cmpclient").Run() == nil
	return c, "", nil
}

// commandError adds the standard error output of a failed command to its error.
func commandError(err error) error {
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(exitErr.Stderr))
	}
	return err
}

// stop kills the container, which --rm then removes.
func (c *clientContainer) stop() {
	_ = exec.Command("docker", "kill", c.id).Run()
}

// docker runs a docker command that must succeed.
func (c *clientContainer) docker(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	require.NoError(t, err, "docker %s: %s", strings.Join(args, " "), out)
}

// workdir creates an empty directory in the container for the running test and returns its path.
func (c *clientContainer) workdir(t *testing.T) string {
	t.Helper()
	dir := path.Join("/work", strings.NewReplacer("/", "-", " ", "_").Replace(t.Name()))
	c.docker(t, "exec", c.id, "mkdir", "-p", dir)
	return dir
}

// put writes data to dir/name in the container.
func (c *clientContainer) put(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	local := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(local, data, 0o600))
	c.docker(t, "cp", local, c.id+":"+path.Join(dir, name))
}

// get returns the contents of dir/name in the container. It returns nil when the file does not exist.
func (c *clientContainer) get(t *testing.T, dir, name string) []byte {
	t.Helper()
	out, err := exec.Command("docker", "exec", c.id, "cat", path.Join(dir, name)).Output()
	if err != nil {
		return nil
	}
	return out
}

// run executes a client in dir and returns its combined output. Both clients
// exit with status 0 after the server rejects a request, so callers judge the
// result by the output and by what the server recorded.
func (c *clientContainer) run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), execTimeout)
	defer cancel()
	// Under qemu amd64 emulation cmpclient computes wrong PasswordBasedMac
	// values when its Go runtime uses several threads. One thread keeps the
	// iteration counts used here reliable.
	full := append([]string{"exec", "-e", "GOMAXPROCS=1", "-w", dir, c.id}, args...)
	// ssh-cmpclient sometimes exits with SIGSEGV under amd64 emulation, so
	// one crash is retried and only a repeated crash fails the test.
	for attempt := 1; ; attempt++ {
		out, err := exec.CommandContext(ctx, "docker", full...).CombinedOutput()
		t.Logf("%s (exit: %v)\n%s", strings.Join(args, " "), err, out)
		require.NoError(t, ctx.Err(), "%s did not finish", args[0])
		if exitErr, ok := errors.AsType[*exec.ExitError](err); attempt == 1 && ok && exitErr.ExitCode() == exitSIGSEGV {
			t.Logf("%s crashed, retrying", args[0])
			continue
		}
		return string(out)
	}
}

// recordingCA is the mockserver CA that also records what the server reported to it.
type recordingCA struct {
	*mockserver.MockCA
	mu        sync.Mutex
	confirmed map[string]server.ConfirmStatus
	revoked   map[string]pkicmp.CRLReason
}

// ConfirmCertificate records the confirmation status of a certificate by serial number.
func (c *recordingCA) ConfirmCertificate(ctx context.Context, cert *x509.Certificate, status server.ConfirmStatus, issueRef any) error {
	c.mu.Lock()
	c.confirmed[cert.SerialNumber.String()] = status
	c.mu.Unlock()
	return c.MockCA.ConfirmCertificate(ctx, cert, status, issueRef)
}

// RevokeCertificate records each revocation the mockserver CA accepts.
func (c *recordingCA) RevokeCertificate(ctx context.Context, req *server.RevocationRequest, sender *server.SenderIdentity) error {
	if err := c.MockCA.RevokeCertificate(ctx, req, sender); err != nil {
		return err
	}
	c.mu.Lock()
	c.revoked[req.SerialNumber.String()] = req.Reason
	c.mu.Unlock()
	return nil
}

// confirmation returns the recorded confirmation status of cert.
func (c *recordingCA) confirmation(cert *x509.Certificate) (server.ConfirmStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	status, ok := c.confirmed[cert.SerialNumber.String()]
	return status, ok
}

// revocation returns the recorded revocation reason of cert.
func (c *recordingCA) revocation(cert *x509.Certificate) (pkicmp.CRLReason, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reason, ok := c.revoked[cert.SerialNumber.String()]
	return reason, ok
}

// issuedCount returns how many certificates the server confirmed or reported as expired.
func (c *recordingCA) issuedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.confirmed)
}

// testServer is this repository's CMP server listening for the client container.
type testServer struct {
	url string
	ca  *recordingCA
}

// newCA returns a mockserver CA that knows the shared secret. The mockserver
// finds a signer certificate by its key identifier, so every certificate
// needs its own key.
func newCA(t *testing.T) *recordingCA {
	t.Helper()
	log := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	mock, err := mockserver.New(map[string][]byte{pskReference: []byte(pskSecret)}, log)
	require.NoError(t, err)
	return &recordingCA{MockCA: mock, confirmed: map[string]server.ConfirmStatus{}, revoked: map[string]pkicmp.CRLReason{}}
}

// startServer starts a server for ca with opts on the host loopback interface.
// Servers that share a CA see the same certificates.
func startServer(t *testing.T, c *clientContainer, ca *recordingCA, opts ...server.Option) *testServer {
	t.Helper()
	base := []server.Option{
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
	}
	srv := server.NewCAServer(ca, server.LightweightPolicy(), slices.Concat(base, opts)...)
	require.NoError(t, srv.Err())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpSrv := &http.Server{Handler: srv, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	return &testServer{url: fmt.Sprintf("http://%s:%d/pkix/", c.serverHost, port), ca: ca}
}

// newECKey returns a P-256 key and its PKCS #8 PEM encoding.
func newECKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, pkcs8PEM(t, key)
}

// newRSAKey returns a 2048-bit RSA key and its PKCS #8 PEM encoding.
func newRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, pkcs8PEM(t, key)
}

// pkcs8PEM encodes key as a PEM PRIVATE KEY block.
func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// csrPEM returns a PEM certificate request for key with the given common name.
func csrPEM(t *testing.T, key crypto.Signer, commonName string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// parseCertificate decodes a certificate written by either client, which use PEM and DER respectively.
func parseCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	cert, err := x509.ParseCertificate(data)
	require.NoError(t, err)
	return cert
}

// samePublicKey reports whether cert certifies key.
func samePublicKey(t *testing.T, cert *x509.Certificate, key crypto.Signer) bool {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return bytes.Equal(der, cert.RawSubjectPublicKeyInfo)
}
