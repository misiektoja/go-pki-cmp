package mockserver_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// reference and iak are the shared secret cmd/main.go registers for MAC-protected enrollment.
var (
	reference = []byte("my-device")
	iak       = []byte("test-shared-secret")
)

// confirmingCA is the mock CA that also records the certConf outcome of each issued certificate.
type confirmingCA struct {
	*mockserver.MockCA

	mu        sync.Mutex
	confirmed map[string]server.ConfirmStatus // serial number -> confirmation status
}

// ConfirmCertificate records status and passes the confirmation on to the mock CA.
func (c *confirmingCA) ConfirmCertificate(ctx context.Context, cert *x509.Certificate, status server.ConfirmStatus, issueRef any) error {
	c.mu.Lock()
	c.confirmed[cert.SerialNumber.String()] = status
	c.mu.Unlock()
	return c.MockCA.ConfirmCertificate(ctx, cert, status, issueRef)
}

// requireAccepted checks that the client confirmed cert with certConf.
func (c *confirmingCA) requireAccepted(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	status, ok := c.confirmed[cert.SerialNumber.String()]
	require.True(t, ok, "no certConf for serial %s", cert.SerialNumber)
	require.Equal(t, server.ConfirmAccepted, status)
}

// newServer serves the mock CA as cmd/main.go does, with the server options in extra, and returns a
// client that trusts it.
func newServer(t *testing.T, extra ...server.Option) (*confirmingCA, *client.Client) {
	t.Helper()
	mock, err := mockserver.New(map[string][]byte{string(reference): iak}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	ca := &confirmingCA{MockCA: mock, confirmed: map[string]server.ConfirmStatus{}}
	opts := slices.Concat([]server.Option{
		server.WithSigner(mock.Key(), mock.Cert()),
		server.WithExtraCerts([]*x509.Certificate{mock.Cert()}),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
		mock.CentralKeyGeneration(),
	}, extra)
	srv := server.NewCAServer(ca, server.LightweightPolicy(), opts...)
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	pool := x509.NewCertPool()
	pool.AddCert(mock.Cert())
	return ca, client.NewClient(ts.URL, client.WithTrustedCAs(pool))
}

// requireCertifies checks that crypto/x509 parses cert and that cert carries the public key of key under a signature from ca.
func requireCertifies(t *testing.T, ca, cert *x509.Certificate, key crypto.Signer) {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Raw)
	require.NoError(t, err)
	pub, err := compositex509.ParsePKIXPublicKey(parsed.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	want, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok)
	require.True(t, want.Equal(pub), "certificate carries another public key")
	require.NoError(t, compositex509.CheckSignatureFrom(parsed, ca))
}

// TestKeyLifecycle enrolls a key with ir, replaces it with kur and revokes the result with rr,
// for a classical key and for composite ML-DSA keys. The kur, its certConf and the rr are
// signed with certificates the mock CA issued, so each is authenticated through LookupCertificate.
func TestKeyLifecycle(t *testing.T) {
	type keyType struct {
		name     string
		generate func() (crypto.Signer, error)
	}
	compositeAlgs := []compositemldsa.Algorithm{
		compositemldsa.MLDSA44ECDSAP256SHA256,
		compositemldsa.MLDSA65Ed25519SHA512,
		compositemldsa.MLDSA87ECDSAP384SHA512,
	}
	keyTypes := make([]keyType, 0, 1+len(compositeAlgs))
	keyTypes = append(keyTypes, keyType{
		name:     "ECDSA P-256",
		generate: func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	})
	for _, alg := range compositeAlgs {
		keyTypes = append(keyTypes, keyType{
			name:     alg.String(),
			generate: func() (crypto.Signer, error) { return compositemldsa.GenerateKey(alg) },
		})
	}

	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			ctx := context.Background()
			ca, c := newServer(t)
			subject := pkix.Name{CommonName: "device"}

			irKey, err := kt.generate()
			require.NoError(t, err)
			macCreds, err := pkicmp.NewMACCredentials(iak)
			require.NoError(t, err)
			ir, err := c.SendIR(ctx, irKey, macCreds,
				client.WithSenderKID(reference),
				client.WithSender(subject),
				client.WithTemplateSubject(subject),
			)
			require.NoError(t, err)
			requireCertifies(t, ca.Cert(), ir.Certificate, irKey)
			ca.requireAccepted(t, ir.Certificate)

			found, err := ca.LookupCertificate(pkix.Name{}, subject, ir.Certificate.SubjectKeyId)
			require.NoError(t, err)
			require.True(t, found.Equal(ir.Certificate))

			kurKey, err := kt.generate()
			require.NoError(t, err)
			irCreds, err := pkicmp.NewSignatureCredentials(irKey, ir.Certificate, ca.Cert())
			require.NoError(t, err)
			kur, err := c.SendKUR(ctx, kurKey, irCreds, client.WithSender(subject), client.WithTemplateSubject(subject))
			require.NoError(t, err)
			requireCertifies(t, ca.Cert(), kur.Certificate, kurKey)
			ca.requireAccepted(t, kur.Certificate)

			kurCreds, err := pkicmp.NewSignatureCredentials(kurKey, kur.Certificate, ca.Cert())
			require.NoError(t, err)
			require.NoError(t, c.SendRR(ctx, kur.Certificate, pkicmp.CRLReasonKeyCompromise, kurCreds))

			crl, err := ca.LatestCRL(ctx, pkicmp.CRLSource{}, nil)
			require.NoError(t, err)
			require.Len(t, crl.RevokedCertificateEntries, 1)
			require.Zero(t, crl.RevokedCertificateEntries[0].SerialNumber.Cmp(kur.Certificate.SerialNumber))

			// The revoked certificate no longer authenticates requests. The server
			// reports a failed protection check as badMessageCheck.
			_, err = ca.LookupCertificate(pkix.Name{}, subject, kur.Certificate.SubjectKeyId)
			require.Error(t, err)
			nextKey, err := kt.generate()
			require.NoError(t, err)
			_, err = c.SendKUR(ctx, nextKey, kurCreds, client.WithSender(subject), client.WithTemplateSubject(subject))
			require.True(t, pkicmp.HasFailure(err, pkicmp.FailBadMessageCheck), "got %v", err)
		})
	}
}

// TestRevocationInvalidityDate revokes a certificate by issuer and serial number with an
// invalidityDate, which the CRL entry then carries (RFC 5280 §5.3.2).
func TestRevocationInvalidityDate(t *testing.T) {
	ctx := context.Background()
	ca, c := newServer(t)
	subject := pkix.Name{CommonName: "device"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	macCreds, err := pkicmp.NewMACCredentials(iak)
	require.NoError(t, err)
	ir, err := c.SendIR(ctx, key, macCreds,
		client.WithSenderKID(reference),
		client.WithSender(subject),
		client.WithTemplateSubject(subject),
	)
	require.NoError(t, err)

	// The holder names its own certificate by issuer and serial number, which needs no authorizer.
	creds, err := pkicmp.NewSignatureCredentials(key, ir.Certificate, ca.Cert())
	require.NoError(t, err)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	err = c.SendRRBySerial(ctx, ca.Cert().Subject, ir.Certificate.SerialNumber, pkicmp.CRLReasonKeyCompromise, creds,
		client.WithInvalidityDate(at))
	require.NoError(t, err)

	crl, err := ca.LatestCRL(ctx, pkicmp.CRLSource{}, nil)
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
	entry := crl.RevokedCertificateEntries[0]
	require.Zero(t, entry.SerialNumber.Cmp(ir.Certificate.SerialNumber))
	require.Equal(t, int(pkicmp.CRLReasonKeyCompromise), entry.ReasonCode)
	var found bool
	for _, ext := range entry.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 24}) {
			continue
		}
		found = true
		var got time.Time
		_, err := asn1.UnmarshalWithParams(ext.Value, &got, "generalized")
		require.NoError(t, err)
		require.True(t, got.Equal(at), "invalidityDate %v", got)
	}
	require.True(t, found, "the CRL entry lacks the invalidityDate extension")
}

// TestMLKEMEnrollment enrolls ML-KEM keys, which prove possession by decryption, with both
// indirect methods. The certificate carries the key with keyEncipherment as its only key usage.
func TestMLKEMEnrollment(t *testing.T) {
	type kemKey struct {
		name     string
		generate func() (any, crypto.PublicKey, error)
	}
	kemKeys := []kemKey{
		{"ML-KEM-768", func() (any, crypto.PublicKey, error) {
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, err
			}
			return dk, dk.EncapsulationKey(), nil
		}},
		{"ML-KEM-1024", func() (any, crypto.PublicKey, error) {
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, nil, err
			}
			return dk, dk.EncapsulationKey(), nil
		}},
	}
	methods := []client.IndirectPOP{client.EncryptedCertificate, client.ChallengeResponse}
	for _, kk := range kemKeys {
		for _, method := range methods {
			t.Run(kk.name+"/"+method.String(), func(t *testing.T) {
				ca, c := newServer(t, server.WithEncryptedCertificatePOP(), server.WithChallengeResponsePOP())
				key, pub, err := kk.generate()
				require.NoError(t, err)
				macCreds, err := pkicmp.NewMACCredentials(iak)
				require.NoError(t, err)
				subject := pkix.Name{CommonName: "kem-device"}
				ir, err := c.SendIRWithIndirectPOP(context.Background(), key, method, macCreds,
					client.WithSenderKID(reference),
					client.WithSender(subject),
					client.WithTemplateSubject(subject),
				)
				require.NoError(t, err)
				ca.requireAccepted(t, ir.Certificate)

				require.Equal(t, x509.KeyUsageKeyEncipherment, ir.Certificate.KeyUsage)
				certified, err := pkicmp.ParsePublicKey(ir.Certificate.RawSubjectPublicKeyInfo)
				require.NoError(t, err)
				want, err := pkicmp.MarshalPublicKey(pub)
				require.NoError(t, err)
				got, err := pkicmp.MarshalPublicKey(certified)
				require.NoError(t, err)
				require.Equal(t, want, got, "certificate carries another public key")
				require.NoError(t, ir.Certificate.CheckSignatureFrom(ca.Cert()))
			})
		}
	}
}

// TestCentralKeyGeneration has the mock CA generate key pairs for MAC- and
// signature-protected requests and checks that each private key arrives
// signed by the key generation authority and matches its certificate.
func TestCentralKeyGeneration(t *testing.T) {
	ecAlgorithm := func(curve asn1.ObjectIdentifier) *pkicmp.AlgorithmIdentifier {
		params, err := asn1.Marshal(curve)
		require.NoError(t, err)
		return &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: params}
	}
	mlDSA44 := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}}
	ed25519Algorithm := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}
	subject := pkix.Name{CommonName: "keygen-device"}
	ctx := context.Background()

	// checkGenerated checks the generated key of res and returns it as a signer.
	checkGenerated := func(t *testing.T, ca *confirmingCA, res *client.EnrollResult) crypto.Signer {
		t.Helper()
		require.NotNil(t, res.GeneratedKey)
		require.True(t, res.GeneratedKey.Signer.Equal(ca.KGACert()))
		key, ok := res.GeneratedKey.PrivateKey.(crypto.Signer)
		require.True(t, ok, "unexpected key type %T", res.GeneratedKey.PrivateKey)
		requireCertifies(t, ca.Cert(), res.Certificate, key)
		parsed, err := x509.ParsePKCS8PrivateKey(res.GeneratedKey.PKCS8)
		require.NoError(t, err)
		require.True(t, parsed.(interface{ Equal(crypto.PrivateKey) bool }).Equal(key))
		ca.requireAccepted(t, res.Certificate)
		return key
	}

	t.Run("MAC", func(t *testing.T) {
		cases := []struct {
			name      string
			algorithm *pkicmp.AlgorithmIdentifier
			options   []server.Option
			check     func(t *testing.T, key crypto.Signer)
		}{
			{"CA choice", nil, nil, func(t *testing.T, key crypto.Signer) {
				require.Equal(t, elliptic.P256(), key.(*ecdsa.PrivateKey).Curve)
			}},
			{"P-384", ecAlgorithm(asn1.ObjectIdentifier{1, 3, 132, 0, 34}), nil, func(t *testing.T, key crypto.Signer) {
				require.Equal(t, elliptic.P384(), key.(*ecdsa.PrivateKey).Curve)
			}},
			{"ML-DSA-44 with AES key wrap", mlDSA44, []server.Option{server.WithCentralKeyGenerationAESKeyWrap()}, func(t *testing.T, key crypto.Signer) {
				require.IsType(t, &mldsa.PrivateKey{}, key)
			}},
			{"P-256 as AsymmetricKeyPackage", ecAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}), []server.Option{server.WithCentralKeyGenerationAsymmetricKeyPackage()}, func(t *testing.T, key crypto.Signer) {
				require.Equal(t, elliptic.P256(), key.(*ecdsa.PrivateKey).Curve)
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ca, c := newServer(t, tc.options...)
				macCreds, err := pkicmp.NewMACCredentials(iak)
				require.NoError(t, err)
				res, err := c.SendIRWithCentralKeyGeneration(ctx, tc.algorithm, macCreds,
					client.WithSenderKID(reference), client.WithSender(subject), client.WithTemplateSubject(subject))
				require.NoError(t, err)
				tc.check(t, checkGenerated(t, ca, res))
			})
		}
	})

	t.Run("signature", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		// KARI for the ECDSA protection key and KTRI for the RSA one (RFC 9483 §4.1.6.1 and §4.1.6.2).
		for _, protection := range []crypto.Signer{ecKey, rsaKey} {
			t.Run(fmt.Sprintf("%T", protection), func(t *testing.T) {
				ca, c := newServer(t)
				macCreds, err := pkicmp.NewMACCredentials(iak)
				require.NoError(t, err)
				ir, err := c.SendIR(ctx, protection, macCreds,
					client.WithSenderKID(reference), client.WithSender(subject), client.WithTemplateSubject(subject))
				require.NoError(t, err)
				sigCreds, err := pkicmp.NewSignatureCredentials(protection, ir.Certificate)
				require.NoError(t, err)

				res, err := c.SendCRWithCentralKeyGeneration(ctx, ed25519Algorithm, sigCreds, client.WithTemplateSubject(subject))
				require.NoError(t, err)
				require.IsType(t, ed25519.PrivateKey{}, checkGenerated(t, ca, res))
			})
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, c := newServer(t)
		macCreds, err := pkicmp.NewMACCredentials(iak)
		require.NoError(t, err)
		_, err = c.SendIRWithCentralKeyGeneration(ctx, &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, macCreds,
			client.WithSenderKID(reference), client.WithSender(subject), client.WithTemplateSubject(subject))
		require.True(t, pkicmp.HasFailure(err, pkicmp.FailBadAlg), "got %v", err)
	})
}
