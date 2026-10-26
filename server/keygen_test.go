package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
)

// newKGA returns a key generation authority key and a self-signed certificate for it with the given extended key usages.
func newKGA(t *testing.T, ekus ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(7),
		Subject:            pkix.Name{CommonName: "test KGA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: ekus,
		SubjectKeyId:       []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// p256Generator generates ECDSA P-256 keys and records the algorithms it was asked for.
type p256Generator struct {
	requested []*pkicmp.AlgorithmIdentifier
}

// GenerateKey returns a new P-256 key as PKCS #8.
func (g *p256Generator) GenerateKey(_ context.Context, algorithm *pkicmp.AlgorithmIdentifier, _ *server.SenderIdentity) (*server.GeneratedKey, error) {
	g.requested = append(g.requested, algorithm)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &server.GeneratedKey{PrivateKey: der, PublicKey: &key.PublicKey}, nil
}

// centralKeyRequest builds an ir that asks for central key generation, with an algorithm preference when algorithm is set.
func centralKeyRequest(t *testing.T, algorithm *pkicmp.AlgorithmIdentifier) *pkicmp.PKIMessage {
	t.Helper()
	tmpl := pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(pkix.Name{CommonName: "central keygen"})}
	if algorithm != nil {
		tmpl.PublicKey = pkicmp.CentralKeyGenerationPublicKey(*algorithm)
	}
	req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: tmpl}}
	return pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), macMessageOpts())
}

// p256Algorithm is the id-ecPublicKey algorithm with the P-256 curve.
func p256Algorithm(t *testing.T) *pkicmp.AlgorithmIdentifier {
	t.Helper()
	params, err := asn1.Marshal(oidP256)
	require.NoError(t, err)
	return &pkicmp.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: params}
}

// openPrivateKey decrypts the private key of the ip resp with secret, checks
// the key package signature and content form and returns the issued
// certificate and the key.
func openPrivateKey(t *testing.T, resp *pkicmp.PKIMessage, secret []byte, kga *x509.Certificate, form pkicmp.KeyPackageContent) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeIP, resp.Body.Type, "%+v", statusInfoOf(t, resp))
	assert.Equal(t, pkicmp.PVNO3, resp.Header.PVNO, "EnvelopedData needs cmp2021")
	rep, err := resp.Body.IP()
	require.NoError(t, err)
	require.Equal(t, pkicmp.StatusAccepted, rep.Response[0].Status.Status, "%+v", rep.Response[0].Status)
	ckp := rep.Response[0].CertifiedKeyPair
	require.NotNil(t, ckp)
	cert, err := ckp.CertOrEncCert.Certificate.Parse()
	require.NoError(t, err)
	envelope := ckp.EncryptedPrivateKey()
	require.NotNil(t, envelope)

	signed, err := cms.Decrypt(envelope, cms.Password(secret))
	require.NoError(t, err)
	pkg, err := pkicmp.ParseKeyPackage(signed, pkicmp.KeyPackageOptions{})
	require.NoError(t, err)
	assert.True(t, pkg.Signer.Equal(kga))
	assert.Equal(t, form, pkg.Content)
	parsed, err := x509.ParsePKCS8PrivateKey(pkg.PrivateKey)
	require.NoError(t, err)
	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the key belongs to the certificate")
	return cert, key
}

// The server generates the key pair, the CA certifies it and the ip returns
// the private key encrypted to the shared secret, signed as id-data or, when
// configured, as an AsymmetricKeyPackage.
func TestCentralKeyGeneration(t *testing.T) {
	secret := []byte("central-key-generation")
	for _, tc := range []struct {
		name      string
		algorithm *pkicmp.AlgorithmIdentifier
		opts      []server.Option
		form      pkicmp.KeyPackageContent
	}{
		{"CA choice", nil, nil, pkicmp.KeyPackageData},
		{"P-256", p256Algorithm(t), nil, pkicmp.KeyPackageData},
		{"AsymmetricKeyPackage", p256Algorithm(t), []server.Option{server.WithCentralKeyGenerationAsymmetricKeyPackage()}, pkicmp.KeyPackageAsymmetricKeyPackage},
	} {
		algorithm := tc.algorithm
		t.Run(tc.name, func(t *testing.T) {
			ca := newPOPCA(t)
			gen := &p256Generator{}
			kgaKey, kgaCert := newKGA(t, pkicmp.OIDExtKeyUsageCMKGA)
			srv := server.NewCAServer(ca, server.LightweightPolicy(), append([]server.Option{
				server.WithSecretLookup(&staticMACLookup{secret: secret}),
				server.WithCentralKeyGeneration(gen, kgaKey, kgaCert),
			}, tc.opts...)...)
			require.NoError(t, srv.Err())
			ts := httptest.NewServer(srv)
			defer ts.Close()

			// OpenSSL asks with pvno 2. The response is raised to 3.
			ir := centralKeyRequest(t, algorithm)
			ir.Header.PVNO = pkicmp.PVNO2
			ip := exchange(t, ts, ir, secret)
			cert, _ := openPrivateKey(t, ip, secret, kgaCert, tc.form)
			require.Len(t, gen.requested, 1)
			if algorithm == nil {
				assert.Nil(t, gen.requested[0])
			} else {
				assert.Equal(t, algorithm.Parameters, gen.requested[0].Parameters)
			}

			conf := exchange(t, ts, popCertConf(t, cert, false, ip), secret)
			require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)
			methods, confirmations := ca.recorded()
			assert.Equal(t, []server.POPMethod{server.POPCentralKeyGeneration}, methods)
			assert.Equal(t, []popConfirmation{{server.ConfirmAccepted, server.POPCentralKeyGeneration}}, confirmations)
		})
	}
}

// A delayed request keeps its encrypted private key across a snapshot and gets it with the certificate.
func TestCentralKeyGenerationAfterPolling(t *testing.T) {
	secret := []byte("central-key-generation-poll")
	ca := newPOPCA(t)
	ca.delay = true
	kgaKey, kgaCert := newKGA(t, pkicmp.OIDExtKeyUsageCMKGA)
	newServer := func() *server.Server {
		return server.NewCAServer(ca, server.LightweightPolicy(),
			server.WithSecretLookup(&staticMACLookup{secret: secret}),
			server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, kgaCert),
		)
	}
	first := newServer()
	ts1 := httptest.NewServer(first)
	defer ts1.Close()
	waiting := exchange(t, ts1, centralKeyRequest(t, nil), secret)
	require.Equal(t, pkicmp.StatusWaiting, statusInfoOf(t, waiting).Status)
	snapshot, err := first.SnapshotTransactions()
	require.NoError(t, err)

	second := newServer()
	require.NoError(t, second.RestoreTransactions(snapshot, nil))
	ts2 := httptest.NewServer(second)
	defer ts2.Close()
	ip := exchange(t, ts2, followUp(pkicmp.NewPollReqBody(&pkicmp.PollReqContent{0}), waiting), secret)
	cert, _ := openPrivateKey(t, ip, secret, kgaCert, pkicmp.KeyPackageData)
	conf := exchange(t, ts2, popCertConf(t, cert, false, ip), secret)
	require.Equal(t, pkicmp.BodyTypePKIConf, conf.Body.Type)

	methods, _ := ca.recorded()
	assert.Equal(t, []server.POPMethod{server.POPCentralKeyGeneration, server.POPCentralKeyGeneration}, methods)
}

// otherKeyCA certifies a key of its own instead of the requested one.
type otherKeyCA struct {
	*popCA
}

// IssueCertificate replaces the template key before issuing.
func (c otherKeyCA) IssueCertificate(ctx context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl.PublicKey = &key.PublicKey
	return c.popCA.IssueCertificate(ctx, reqType, tmpl, sender)
}

// TestCentralKeyGenerationRefusals covers requests and settings the server refuses.
func TestCentralKeyGenerationRefusals(t *testing.T) {
	secret := []byte("central-key-generation-refusals")
	kgaKey, kgaCert := newKGA(t, pkicmp.OIDExtKeyUsageCMKGA)
	_, plainCert := newKGA(t)
	wrongAlgorithm := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}

	cases := []struct {
		name    string
		ca      server.CA
		options []server.Option
		request func(t *testing.T) *pkicmp.PKIMessage
		want    pkicmp.PKIFailureInfo
		text    string
	}{
		{"not enabled", newPOPCA(t), nil,
			func(t *testing.T) *pkicmp.PKIMessage { return centralKeyRequest(t, p256Algorithm(t)) },
			pkicmp.FailBadCertTemplate, "public key required"},
		{"proof of possession", newPOPCA(t), []server.Option{server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, kgaCert)},
			func(t *testing.T) *pkicmp.PKIMessage {
				msg := centralKeyRequest(t, nil)
				msgs, err := msg.Body.IR()
				require.NoError(t, err)
				method := pkicmp.SubsequentMessageEncrCert
				(*msgs)[0].Popo = pkicmp.NewKeyEnciphermentPOP(&method)
				return msg
			},
			pkicmp.FailBadPOP, ""},
		{"other algorithm generated", newPOPCA(t), []server.Option{server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, kgaCert)},
			func(t *testing.T) *pkicmp.PKIMessage { return centralKeyRequest(t, wrongAlgorithm) },
			pkicmp.FailBadAlg, ""},
		{"signer without cmKGA", newPOPCA(t), []server.Option{server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, plainCert)},
			func(t *testing.T) *pkicmp.PKIMessage { return centralKeyRequest(t, nil) },
			pkicmp.FailSystemFailure, ""},
		{"CA certifies another key", otherKeyCA{newPOPCA(t)}, []server.Option{server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, kgaCert)},
			func(t *testing.T) *pkicmp.PKIMessage { return centralKeyRequest(t, nil) },
			pkicmp.FailSystemFailure, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]server.Option{server.WithSecretLookup(&staticMACLookup{secret: secret})}, tc.options...)
			ts := httptest.NewServer(server.NewCAServer(tc.ca, server.LightweightPolicy(), opts...))
			defer ts.Close()
			status := rejectionStatus(t, exchange(t, ts, tc.request(t), secret))
			assert.Equal(t, tc.want, status.FailInfo, "%+v", status)
			if tc.text != "" {
				assert.Equal(t, pkicmp.PKIFreeText{tc.text}, status.StatusString)
			}
			// The CA hears that the certificate it issued was not delivered.
			if other, ok := tc.ca.(otherKeyCA); ok {
				_, confirmations := other.recorded()
				assert.Equal(t, []popConfirmation{{server.ConfirmRejected, server.POPCentralKeyGeneration}}, confirmations)
			}
		})
	}
}

// New reports settings that cannot sign key packages through Err.
func TestCentralKeyGenerationSettings(t *testing.T) {
	kgaKey, kgaCert := newKGA(t, pkicmp.OIDExtKeyUsageCMKGA)
	otherKey, _ := newKGA(t)
	_, plainCert := newKGA(t)
	cases := []struct {
		name string
		opt  server.Option
	}{
		{"no generator", server.WithCentralKeyGeneration(nil, kgaKey, kgaCert)},
		{"key mismatch", server.WithCentralKeyGeneration(&p256Generator{}, otherKey, kgaCert)},
		{"no cmKGA", server.WithCentralKeyGeneration(&p256Generator{}, kgaKey, plainCert)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, server.New(server.NewCAHandler(newPOPCA(t)), tc.opt).Err())
		})
	}
	assert.NoError(t, server.New(server.NewCAHandler(newPOPCA(t)),
		server.WithCentralKeyGeneration(server.KeyGeneratorFunc(func(context.Context, *pkicmp.AlgorithmIdentifier, *server.SenderIdentity) (*server.GeneratedKey, error) {
			return nil, nil
		}), kgaKey, kgaCert)).Err())
}
