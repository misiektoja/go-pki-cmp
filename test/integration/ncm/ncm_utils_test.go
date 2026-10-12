//go:build integration

// Package ncm runs the client against a Nokia NCM instance described by NCM_CMP_* environment
// variables. A test skips when the configuration it needs is absent, so the package passes without an
// NCM instance. README.md lists the variables.
package ncm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

const (
	// operationTimeout bounds one CMP operation, including certConf and pkiConf.
	operationTimeout = 2 * time.Minute

	// requestInterval spaces requests to NCM, which limits requests per source host and counts every
	// CMP message, certConf included.
	requestInterval = 1500 * time.Millisecond

	// rateLimitRetries is how often a request NCM refused under its rate limit is sent again.
	rateLimitRetries = 4
)

// pacer spaces the requests of every test in the package, because the rate limit applies per host.
var pacer requestPacer

// requestPacer hands out request slots at least requestInterval apart.
type requestPacer struct {
	mu   sync.Mutex
	next time.Time
}

// wait blocks until the next free request slot or until ctx ends.
func (p *requestPacer) wait(ctx context.Context) error {
	p.mu.Lock()
	slot := time.Now()
	if p.next.After(slot) {
		slot = p.next
	}
	p.next = slot.Add(requestInterval)
	p.mu.Unlock()
	return sleepContext(ctx, time.Until(slot))
}

// pacedTransport spaces requests to NCM and sends a request again when NCM refused it under its rate limit.
type pacedTransport struct {
	base http.RoundTripper
}

// RoundTrip sends req in the next free slot and sends it again while NCM refuses it under its rate limit.
func (p pacedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			// NCM refuses such a request before it parses it, so sending the same bytes again does
			// not repeat a transaction.
			if err := sleepContext(req.Context(), time.Duration(attempt)*3*time.Second); err != nil {
				return nil, err
			}
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
		if err := pacer.wait(req.Context()); err != nil {
			return nil, err
		}
		resp, err := p.base.RoundTrip(req)
		if err != nil || !rateLimited(resp) || attempt == rateLimitRetries {
			return resp, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// rateLimited reports whether resp is the HTTP 503 without a CMP message that NCM sends under its rate limit.
func rateLimited(resp *http.Response) bool {
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return resp.StatusCode == http.StatusServiceUnavailable && mediaType != "application/pkixcmp"
}

// sleepContext waits for d or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// transport is one configured CMP endpoint.
type transport struct {
	name     string
	endpoint string
}

// ncmConfig is the NCM instance and credentials the tests enroll against.
type ncmConfig struct {
	transports     []transport
	recipient      pkix.Name
	anchors        []*x509.Certificate
	trust          *x509.CertPool
	httpsTrust     *x509.CertPool
	pbmReference   []byte
	pbmSecret      []byte
	bootstrapKey   crypto.Signer
	bootstrapCert  *x509.Certificate
	bootstrapChain []*x509.Certificate
	commonName     string
	country        string
	organization   string
	kur            bool
	kurSameKey     bool
	reenroll       bool
	revoke         bool
}

// loadConfig reads the NCM configuration from the environment and skips the test when no endpoint is set.
func loadConfig(t *testing.T) *ncmConfig {
	t.Helper()

	cfg := &ncmConfig{
		commonName:   os.Getenv("NCM_CMP_COMMON_NAME"),
		country:      os.Getenv("NCM_CMP_COUNTRY"),
		organization: os.Getenv("NCM_CMP_ORGANIZATION"),
		kur:          os.Getenv("NCM_CMP_KUR") != "false",
		reenroll:     os.Getenv("NCM_CMP_REENROLL") != "false",
		revoke:       os.Getenv("NCM_CMP_RR") != "false",
	}
	cfg.kurSameKey = cfg.kur && os.Getenv("NCM_CMP_KUR_SAME_KEY") != "false"

	for _, tr := range []transport{{name: "HTTP", endpoint: os.Getenv("NCM_CMP_HTTP_URL")}, {name: "HTTPS", endpoint: os.Getenv("NCM_CMP_HTTPS_URL")}} {
		if tr.endpoint != "" {
			cfg.transports = append(cfg.transports, tr)
		}
	}
	if len(cfg.transports) == 0 {
		t.Skip("NCM_CMP_HTTP_URL and NCM_CMP_HTTPS_URL are not set")
	}

	// Values are never logged, so a failure names the variable rather than its content.
	recipient := os.Getenv("NCM_CMP_RECIPIENT_DN")
	require.NotEmpty(t, recipient, "NCM_CMP_RECIPIENT_DN is not set")
	var err error
	cfg.recipient, err = parseDN(recipient)
	require.NoError(t, err, "parse NCM_CMP_RECIPIENT_DN")

	trust, err := parseCertificates(os.Getenv("NCM_CMP_RESPONSE_TRUST"))
	require.NoError(t, err, "parse NCM_CMP_RESPONSE_TRUST")
	cfg.anchors = trust
	cfg.trust = certPool(trust)

	if value := os.Getenv("NCM_CMP_HTTPS_TRUST"); value != "" {
		httpsTrust, err := parseCertificates(value)
		require.NoError(t, err, "parse NCM_CMP_HTTPS_TRUST")
		cfg.httpsTrust = certPool(httpsTrust)
	}

	if reference, secret := os.Getenv("NCM_CMP_PBM_REFERENCE"), os.Getenv("NCM_CMP_PBM_SECRET"); reference != "" && secret != "" {
		cfg.pbmReference = []byte(reference)
		cfg.pbmSecret = []byte(secret)
	}

	if certPEM, keyPEM := os.Getenv("NCM_CMP_BOOTSTRAP_CERT"), os.Getenv("NCM_CMP_BOOTSTRAP_KEY"); certPEM != "" && keyPEM != "" {
		certs, err := parseCertificates(certPEM)
		require.NoError(t, err, "parse NCM_CMP_BOOTSTRAP_CERT")
		cfg.bootstrapCert = certs[0]
		cfg.bootstrapKey, err = parsePrivateKey(keyPEM)
		require.NoError(t, err, "parse NCM_CMP_BOOTSTRAP_KEY")
		if chainPEM := os.Getenv("NCM_CMP_BOOTSTRAP_CHAIN"); chainPEM != "" {
			cfg.bootstrapChain, err = parseCertificates(chainPEM)
			require.NoError(t, err, "parse NCM_CMP_BOOTSTRAP_CHAIN")
		}
	}

	return cfg
}

// forEachTransport runs fn as a subtest for every configured endpoint.
func (c *ncmConfig) forEachTransport(t *testing.T, fn func(t *testing.T, cl *client.Client)) {
	t.Helper()

	c.forEachEndpoint(t, func(t *testing.T, connect func(opts ...client.Option) *client.Client) {
		fn(t, connect())
	})
}

// forEachEndpoint runs fn as a subtest for every configured endpoint and lets it create clients with further options.
func (c *ncmConfig) forEachEndpoint(t *testing.T, fn func(t *testing.T, connect func(opts ...client.Option) *client.Client)) {
	t.Helper()

	for _, tr := range c.transports {
		t.Run(tr.name, func(t *testing.T) {
			// A misplaced secret would otherwise let the HTTPS run repeat the HTTP one.
			u, err := url.Parse(tr.endpoint)
			require.NoError(t, err, "parse NCM_CMP_%s_URL", tr.name)
			require.True(t, strings.EqualFold(u.Scheme, tr.name), "NCM_CMP_%s_URL has the scheme %q", tr.name, u.Scheme)

			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.httpsTrust}
			hc := &http.Client{Transport: pacedTransport{base: &http.Transport{TLSClientConfig: tlsConfig}}}
			fn(t, func(opts ...client.Option) *client.Client {
				return client.NewClient(tr.endpoint, append([]client.Option{
					client.WithHTTPClient(hc),
					client.WithRecipient(c.recipient),
					client.WithTrustedCAs(c.trust),
				}, opts...)...)
			})
		})
	}
}

// macCredentials returns the PasswordBasedMac credentials and skips the test when they are not configured.
func (c *ncmConfig) macCredentials(t *testing.T) (pkicmp.Credentials, []client.RequestOption) {
	t.Helper()

	if c.pbmSecret == nil {
		t.Skip("NCM_CMP_PBM_REFERENCE and NCM_CMP_PBM_SECRET are not set")
	}
	creds, err := pkicmp.NewMACCredentials(c.pbmSecret, pkicmp.WithPBMAlgorithms(crypto.SHA256, crypto.SHA256), pkicmp.WithMACIterationCount(1024))
	require.NoError(t, err)
	return creds, []client.RequestOption{client.WithSenderKID(c.pbmReference)}
}

// signatureCredentials returns the bootstrap signature credentials and skips the test when they are not configured.
func (c *ncmConfig) signatureCredentials(t *testing.T) pkicmp.Credentials {
	t.Helper()

	if c.bootstrapKey == nil {
		t.Skip("NCM_CMP_BOOTSTRAP_CERT and NCM_CMP_BOOTSTRAP_KEY are not set")
	}
	creds, err := pkicmp.NewSignatureCredentials(c.bootstrapKey, c.bootstrapCert, c.bootstrapChain...)
	require.NoError(t, err)
	return creds
}

// enrollmentCredentials returns the PasswordBasedMac credentials when configured and the signature credentials otherwise.
func (c *ncmConfig) enrollmentCredentials(t *testing.T) (pkicmp.Credentials, []client.RequestOption) {
	t.Helper()

	if c.pbmSecret != nil {
		return c.macCredentials(t)
	}
	return c.signatureCredentials(t), nil
}

// subject returns the requested subject for the common name cn.
func (c *ncmConfig) subject(cn string) pkix.Name {
	// Country and organization are requested only when set, because a CA that enforces its own
	// subject would otherwise answer grantedWithMods.
	name := pkix.Name{CommonName: cn}
	if c.country != "" {
		name.Country = []string{c.country}
	}
	if c.organization != "" {
		name.Organization = []string{c.organization}
	}
	return name
}

// enrollmentName returns NCM_CMP_COMMON_NAME when set and a generated name otherwise.
func (c *ncmConfig) enrollmentName(purpose string) string {
	if c.commonName != "" {
		return c.commonName
	}
	return generatedName(purpose)
}

// generatedName returns a common name that is unique per run and per purpose.
func generatedName(purpose string) string {
	// A profile that certifies an identity only once would refuse every run after the first
	// if the name repeated.
	return fmt.Sprintf("go-pki-cmp-test-%s-%s", time.Now().UTC().Format("060102-150405"), purpose)
}

// enrollP10CR generates an RSA key, enrolls it for subject through P10CR and returns the key and the issued certificate's chain.
func enrollP10CR(t *testing.T, cfg *ncmConfig, cl *client.Client, subject pkix.Name, creds pkicmp.Credentials, opts ...client.RequestOption) (*rsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), operationTimeout)
	defer cancel()
	result, err := cl.SendP10CR(ctx, csr, creds, opts...)
	require.NoError(t, err, "SendP10CR")

	return key, verifyIssued(t, cfg, result, key.Public())
}

// verifyIssued checks that the issued certificate certifies key and chains to the response trust and returns that chain.
func verifyIssued(t *testing.T, cfg *ncmConfig, result *client.EnrollResult, key crypto.PublicKey) []*x509.Certificate {
	t.Helper()

	cert := result.Certificate
	require.NotNil(t, cert, "no certificate returned")
	requested, ok := key.(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok, "requested key %T cannot be compared", key)
	assert.True(t, requested.Equal(cert.PublicKey), "certificate public key does not match the requested key")

	intermediates := certPool(append(append([]*x509.Certificate{}, result.ExtraCertificates...), result.CAPubs...))
	chains, err := cert.Verify(x509.VerifyOptions{Roots: cfg.trust, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "certificate verification against NCM_CMP_RESPONSE_TRUST")

	t.Logf("Issued certificate: %s (serial: %s, issuer: %s)", cert.Subject, cert.SerialNumber, cert.Issuer)
	// The first chain runs from the certificate to an anchor.
	return chains[0]
}

// intermediates returns the certificates between the certificate and the anchor of chain, which are
// sent along with the certificate when it protects a request.
func intermediates(chain []*x509.Certificate) []*x509.Certificate {
	return chain[1 : len(chain)-1]
}

// certPool returns a pool holding certs.
func certPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// parseCertificates parses every CERTIFICATE block in a PEM value.
func parseCertificates(value string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(value)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

// parsePrivateKey parses a PKCS #8, PKCS #1 or SEC 1 private key from a PEM value.
func parsePrivateKey(value string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%T is not a signing key", key)
	}
	return signer, nil
}

// parseDN parses a comma-separated distinguished name such as "C=DE,O=Example,CN=Issuing CA".
func parseDN(value string) (pkix.Name, error) {
	// pkix.Name encodes its attributes in a fixed order, so the order in value does not matter.
	// A backslash escapes the next character, which allows a comma inside a value.
	var name pkix.Name
	var parts []string
	var current strings.Builder
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	parts = append(parts, current.String())

	for _, part := range parts {
		key, val, found := strings.Cut(part, "=")
		key, val = strings.ToUpper(strings.TrimSpace(key)), strings.TrimSpace(val)
		if !found || val == "" {
			return pkix.Name{}, fmt.Errorf("component %q is not an attribute=value pair", key)
		}
		switch key {
		case "C":
			name.Country = append(name.Country, val)
		case "ST":
			name.Province = append(name.Province, val)
		case "L":
			name.Locality = append(name.Locality, val)
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, val)
		case "POSTALCODE":
			name.PostalCode = append(name.PostalCode, val)
		case "O":
			name.Organization = append(name.Organization, val)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, val)
		case "CN":
			name.CommonName = val
		case "SERIALNUMBER":
			name.SerialNumber = val
		default:
			return pkix.Name{}, fmt.Errorf("unsupported attribute %q", key)
		}
	}
	return name, nil
}
