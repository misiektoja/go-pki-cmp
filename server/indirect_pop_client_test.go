package server_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// The client of this module enrolls every key the server can encrypt for with both indirect methods.
func TestClientIndirectPOP(t *testing.T) {
	secret := []byte("client-indirect-pop")
	keys := popKeys(t)
	// An *ecdh.PrivateKey on a NIST curve is accepted as well as an *ecdsa.PrivateKey.
	p256 := keys[3].priv.(*ecdsa.PrivateKey)
	exchanger, err := p256.ECDH()
	require.NoError(t, err)
	keys = append(keys, popKey{name: "ecdh.PrivateKey P-256", pub: keys[3].pub, priv: exchanger, agreement: true})

	for _, method := range []client.IndirectPOP{client.EncryptedCertificate, client.ChallengeResponse} {
		for _, key := range keys {
			t.Run(method.String()+"/"+key.name, func(t *testing.T) {
				ca := newPOPCA(t)
				ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
					server.WithSecretLookup(&staticMACLookup{secret: secret}),
					server.WithEncryptedCertificatePOP(),
					server.WithChallengeResponsePOP(),
				))
				defer ts.Close()

				creds, err := pkicmp.NewMACCredentials(secret)
				require.NoError(t, err)
				c := client.NewClient(ts.URL)
				result, err := c.SendIRWithIndirectPOP(context.Background(), key.priv, method, creds,
					client.WithSender(testSender),
					client.WithSenderKID([]byte(testSender.String())),
					client.WithTemplateSubject(pkix.Name{CommonName: "client " + key.name}),
				)
				require.NoError(t, err)
				pub, err := pkicmp.ParsePublicKey(result.Certificate.RawSubjectPublicKeyInfo)
				require.NoError(t, err)
				assert.True(t, pkicmp.PublicKeysEqual(pub, key.pub))

				want := server.POPEncryptedCertificate
				if method == client.ChallengeResponse {
					want = server.POPChallengeResponse
				}
				methods, confirmations := ca.recorded()
				assert.Equal(t, []server.POPMethod{want}, methods)
				assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, want}}, confirmations)
			})
		}
	}
}

// Polling continues a challenged request from the popdecr.
func TestClientChallengeResponseAfterPolling(t *testing.T) {
	secret := []byte("client-challenge-poll")
	key := popKeys(t)[0]
	ca := newPOPCA(t)
	ca.delay = true
	ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
		server.WithChallengeResponsePOP(),
	))
	defer ts.Close()

	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	c := client.NewClient(ts.URL)
	result, err := c.SendIRWithIndirectPOP(context.Background(), key.priv, client.ChallengeResponse, creds,
		client.WithSender(testSender),
		client.WithSenderKID([]byte(testSender.String())),
		client.WithTemplateSubject(pkix.Name{CommonName: "client polling"}),
	)
	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	_, confirmations := ca.recorded()
	assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPChallengeResponse}}, confirmations)
}

// The client refuses keys the cms package cannot decrypt with before it sends anything.
func TestClientIndirectPOPUnsupportedKey(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(nil)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("unused"))
	require.NoError(t, err)
	c := client.NewClient("http://127.0.0.1:1")
	for name, key := range map[string]any{"X25519": x25519, "string": "not a key"} {
		_, err := c.SendIRWithIndirectPOP(context.Background(), key, client.EncryptedCertificate, creds)
		assert.ErrorContains(t, err, "indirect proof of possession", name)
	}
	_, err = c.SendIRWithIndirectPOP(context.Background(), popKeys(t)[0].priv, client.IndirectPOP(9), creds)
	assert.ErrorContains(t, err, "unknown indirect proof of possession")
}

// versionRecorder passes requests to next and records the body type and pvno of each.
type versionRecorder struct {
	next http.Handler
	mu   sync.Mutex
	seen []string
}

// ServeHTTP records the request and passes it on unchanged.
func (v *versionRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		if msg, err := pkicmp.ParsePKIMessage(body); err == nil {
			v.mu.Lock()
			v.seen = append(v.seen, fmt.Sprintf("%s v%d", msg.Body.Type, msg.Header.PVNO))
			v.mu.Unlock()
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	v.next.ServeHTTP(w, r)
}

// requests returns the recorded requests in the order they arrived.
func (v *versionRecorder) requests() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.seen)
}

// An indirect proof of possession expects cmp2021 syntax back, so every message
// of its transaction is pvno 3 (RFC 9810 §7). A signature proof stays at pvno 2.
func TestClientIndirectPOPVersion(t *testing.T) {
	secret := []byte("client-indirect-version")
	kem := popKeys(t)[0]
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	opts := []client.RequestOption{
		client.WithSender(testSender),
		client.WithSenderKID([]byte(testSender.String())),
		client.WithTemplateSubject(pkix.Name{CommonName: "client version"}),
	}
	for _, tc := range []struct {
		name  string
		delay bool
		send  func(c *client.Client, creds pkicmp.Credentials) error
		want  []string
	}{
		{"encrCert", false, func(c *client.Client, creds pkicmp.Credentials) error {
			_, err := c.SendIRWithIndirectPOP(context.Background(), kem.priv, client.EncryptedCertificate, creds, opts...)
			return err
		}, []string{"ir v3", "certConf v3"}},
		{"challengeResp", false, func(c *client.Client, creds pkicmp.Credentials) error {
			_, err := c.SendIRWithIndirectPOP(context.Background(), kem.priv, client.ChallengeResponse, creds, opts...)
			return err
		}, []string{"ir v3", "popdecr v3", "certConf v3"}},
		{"challengeResp polled", true, func(c *client.Client, creds pkicmp.Credentials) error {
			_, err := c.SendIRWithIndirectPOP(context.Background(), kem.priv, client.ChallengeResponse, creds, opts...)
			return err
		}, []string{"ir v3", "popdecr v3", "pollReq v3", "certConf v3"}},
		{"signature", false, func(c *client.Client, creds pkicmp.Credentials) error {
			_, err := c.SendIR(context.Background(), signer, creds, opts...)
			return err
		}, []string{"ir v2", "certConf v2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newPOPCA(t)
			ca.delay = tc.delay
			recorder := &versionRecorder{next: server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithEncryptedCertificatePOP(),
				server.WithChallengeResponsePOP(),
			)}
			ts := httptest.NewServer(recorder)
			defer ts.Close()

			creds, err := pkicmp.NewMACCredentials(secret)
			require.NoError(t, err)
			c := client.NewClient(ts.URL)
			require.NoError(t, tc.send(c, creds))
			assert.Equal(t, tc.want, slices.Compact(recorder.requests()))
		})
	}
}

// A deferred indirect proof resumes in a new client. An encrypted certificate needs the
// key to decrypt it, while a challenge answered before the wait needs nothing more.
func TestClientResumeIndirectPOP(t *testing.T) {
	secret := []byte("client-resume-indirect-pop")
	keys := popKeys(t)
	key, other := keys[0], keys[1]
	for _, method := range []client.IndirectPOP{client.EncryptedCertificate, client.ChallengeResponse} {
		t.Run(method.String(), func(t *testing.T) {
			ca := newPOPCA(t)
			ca.delay = true
			ts := httptest.NewServer(server.NewCAServer(ca, server.LightweightPolicy(),
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithEncryptedCertificatePOP(),
				server.WithChallengeResponsePOP(),
			))
			defer ts.Close()

			creds, err := pkicmp.NewMACCredentials(secret)
			require.NoError(t, err)
			result, err := client.NewClient(ts.URL).SendIRWithIndirectPOP(context.Background(), key.priv, method, creds,
				client.WithSender(testSender),
				client.WithSenderKID([]byte(testSender.String())),
				client.WithTemplateSubject(pkix.Name{CommonName: "resumed " + key.name}),
				client.WithDeferredPolling(),
			)
			require.NoError(t, err)
			pending := result.Pending
			require.NotNil(t, pending)
			assert.Equal(t, method, pending.IndirectPOP)
			assert.Equal(t, pkicmp.PVNO3, pending.PVNO, "an indirect proof keeps CMP version 3")

			c := client.NewClient(ts.URL)
			var resumed *client.EnrollResult
			want := server.POPChallengeResponse
			if method == client.EncryptedCertificate {
				want = server.POPEncryptedCertificate
				_, err = c.ResumeEnrollment(context.Background(), pending, creds)
				assert.ErrorContains(t, err, "ResumeEnrollmentWithIndirectPOP")
				_, err = c.ResumeEnrollmentWithIndirectPOP(context.Background(), pending, other.priv, creds)
				assert.ErrorContains(t, err, "the key does not match the public key of the request")
				resumed, err = c.ResumeEnrollmentWithIndirectPOP(context.Background(), pending, key.priv, creds)
			} else {
				resumed, err = c.ResumeEnrollment(context.Background(), pending, creds)
			}
			require.NoError(t, err)
			pub, err := pkicmp.ParsePublicKey(resumed.Certificate.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			assert.True(t, pkicmp.PublicKeysEqual(pub, key.pub))
			_, confirmations := ca.recorded()
			assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, want}}, confirmations)
		})
	}
}
