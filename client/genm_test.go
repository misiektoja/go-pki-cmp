package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// supportCA answers general messages from fixed values.
type supportCA struct {
	revokingCA
	caCerts  []*x509.Certificate
	update   *pkicmp.RootCAKeyUpdate
	template *pkicmp.CertReqTemplate
	crl      *x509.RevocationList
	profile  string
}

// CACertificates returns the configured CA certificates.
func (c *supportCA) CACertificates(context.Context, *server.SenderIdentity) ([]*x509.Certificate, error) {
	return c.caCerts, nil
}

// RootCAUpdate returns the configured update.
func (c *supportCA) RootCAUpdate(context.Context, *x509.Certificate, *server.SenderIdentity) (*pkicmp.RootCAKeyUpdate, error) {
	return c.update, nil
}

// CertReqTemplate records the requested profile and returns the configured template.
func (c *supportCA) CertReqTemplate(_ context.Context, profile string, _ *server.SenderIdentity) (*pkicmp.CertReqTemplate, error) {
	c.profile = profile
	return c.template, nil
}

// LatestCRL returns the configured CRL.
func (c *supportCA) LatestCRL(context.Context, pkicmp.CRLSource, *server.SenderIdentity) (*x509.RevocationList, error) {
	return c.crl, nil
}

// supportRoot is a CA certificate and its key.
type supportRoot struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newSupportRoot returns a self-signed root CA.
func newSupportRoot(t *testing.T, name string) supportRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return supportRoot{cert: signSupportCert(t, name, key.Public(), nil, key), key: key}
}

// signSupportCert issues a CA certificate for pub, self-signed when parent is nil.
func signSupportCert(t *testing.T, name string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// supportCRL returns a CRL issued by root with the given thisUpdate.
func supportCRL(t *testing.T, root supportRoot, thisUpdate time.Time) *x509.RevocationList {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(time.Hour),
	}, root.cert, root.key)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}

// RFC 9483 §4.3 against the server package: every support message round trips.
func TestSupportMessagesAgainstServer(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=support-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	caKey, err := ca.PrivateKey()
	require.NoError(t, err)
	ee := &certyaml.Certificate{Subject: "cn=support-ee", Issuer: ca}
	eeCert, err := ee.X509Certificate()
	require.NoError(t, err)
	eeKey, err := ee.PrivateKey()
	require.NoError(t, err)

	oldRoot, newRoot := newSupportRoot(t, "Old Root"), newSupportRoot(t, "New Root")
	crlTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	backend := &supportCA{
		issued:  []*x509.Certificate{&eeCert},
		caCerts: []*x509.Certificate{&caCert},
		update: &pkicmp.RootCAKeyUpdate{
			NewWithNew: newRoot.cert,
			NewWithOld: signSupportCert(t, "New Root", newRoot.key.Public(), oldRoot.cert, oldRoot.key),
		},
		template: &pkicmp.CertReqTemplate{Template: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(pkix.Name{Organization: []string{"Example"}})}},
		crl:      supportCRL(t, newSupportRoot(t, "CRL Issuer"), crlTime),
	}
	srv := server.NewCAServer(backend, server.LightweightPolicy(), server.WithSigner(caKey, &caCert), server.WithCertificateLookup(backend))
	require.NoError(t, srv.Err())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	trusted := x509.NewCertPool()
	trusted.AddCert(&caCert)
	c := client.NewClient(ts.URL, client.WithTrustedCAs(trusted))
	creds, err := pkicmp.NewSignatureCredentials(eeKey, &eeCert, &caCert)
	require.NoError(t, err)
	ctx := context.Background()

	certs, err := c.GetCACertificates(ctx, creds)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.True(t, certs[0].Equal(&caCert))

	update, err := c.GetRootCAUpdate(ctx, oldRoot.cert, creds)
	require.NoError(t, err)
	require.NotNil(t, update)
	assert.True(t, update.NewWithNew.Equal(newRoot.cert))

	tmpl, err := c.GetCertReqTemplate(ctx, creds, client.WithCertProfile("router"))
	require.NoError(t, err)
	require.NotNil(t, tmpl)
	assert.Equal(t, "router", backend.profile)

	source := pkicmp.NewCRLIssuerSource(backend.crl.RawIssuer)
	crl, err := c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: source}, creds)
	require.NoError(t, err)
	require.NotNil(t, crl)
	assert.Equal(t, backend.crl.Raw, crl.Raw)
	crl, err = c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: source, ThisUpdate: crlTime}, creds)
	require.NoError(t, err)
	assert.Nil(t, crl, "the CRL held is current")

	current, err := c.GetCurrentCRL(ctx, creds)
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, backend.crl.Raw, current.Raw)

	// A server without the providers lists the types as unsupported.
	plain := server.NewCAServer(&revokingCA{}, server.LightweightPolicy(), server.WithSigner(caKey, &caCert), server.WithCertificateLookup(backend))
	require.NoError(t, plain.Err())
	plainTS := httptest.NewServer(plain)
	defer plainTS.Close()
	_, err = client.NewClient(plainTS.URL, client.WithTrustedCAs(trusted)).GetCACertificates(ctx, creds)
	assert.ErrorIs(t, err, client.ErrInfoTypeNotSupported)
}

// genpBody returns a genp body carrying items.
func genpBody(items ...pkicmp.InfoTypeAndValue) *pkicmp.PKIBody {
	return pkicmp.NewGenPBody(items...)
}

// macCreds returns the shared-secret credentials rrMockServer accepts.
func macCreds(t *testing.T) pkicmp.Credentials {
	t.Helper()
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	return creds
}

// The request carries one item and the header names the requested profile.
func TestSendGenMRequestContent(t *testing.T) {
	var got []pkicmp.InfoTypeAndValue
	var profile string
	ts, _ := rrMockServer(t, func(_ int32, req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		content, _ := req.Body.GenM()
		got = *content
		profile = req.Header.CertProfile()
		return genpBody(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCertReqTemplate})
	})

	tmpl, err := client.NewClient(ts.URL).GetCertReqTemplate(context.Background(), macCreds(t), client.WithCertProfile("device"))
	require.NoError(t, err)
	assert.Nil(t, tmpl, "an absent value means no requirements")
	require.Len(t, got, 1)
	assert.True(t, got[0].InfoType.Equal(pkicmp.InfoTypeCertReqTemplate))
	assert.Empty(t, got[0].InfoValue, "RFC 9483 §4.3.3 requires an absent request value")
	assert.Equal(t, "device", profile)
}

// RFC 9483 §4.4: a delayed genp arrives after an error message with status waiting.
func TestSendGenMPolling(t *testing.T) {
	ts, calls := rrMockServer(t, func(n int32, req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		switch n {
		case 1:
			return pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}})
		default:
			return genpBody(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts})
		}
	})
	certs, err := client.NewClient(ts.URL).GetCACertificates(context.Background(), macCreds(t))
	require.NoError(t, err)
	assert.Nil(t, certs)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

// Responses the caller must not act on are returned as errors.
func TestSupportMessageFailures(t *testing.T) {
	oldRoot, newRoot, other := newSupportRoot(t, "Old Root"), newSupportRoot(t, "New Root"), newSupportRoot(t, "Other Root")
	forged, err := pkicmp.NewRootCAKeyUpdateInfo(&pkicmp.RootCAKeyUpdate{
		NewWithNew: newRoot.cert,
		NewWithOld: signSupportCert(t, "New Root", newRoot.key.Public(), other.cert, other.key),
	})
	require.NoError(t, err)
	genuine, err := pkicmp.NewRootCAKeyUpdateInfo(&pkicmp.RootCAKeyUpdate{
		NewWithNew: newRoot.cert,
		NewWithOld: signSupportCert(t, "New Root", newRoot.key.Public(), oldRoot.cert, oldRoot.key),
	})
	require.NoError(t, err)
	crlTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	crl := supportCRL(t, other, crlTime)
	ctx := context.Background()

	tests := []struct {
		name         string
		body         *pkicmp.PKIBody
		call         func(c *client.Client) error
		want         string
		notSupported bool
	}{
		{
			name:         "UnsupportedType",
			body:         genpBody(pkicmp.NewUnsupportedOIDsInfo(pkicmp.InfoTypeCACerts)),
			call:         func(c *client.Client) error { _, err := c.GetCACertificates(ctx, macCreds(t)); return err },
			want:         "info type not supported",
			notSupported: true,
		},
		{
			// An RFC 4210 server ignores the request and sends what it always sends.
			name:         "IgnoredType",
			body:         genpBody(pkicmp.InfoTypeAndValue{InfoType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 4}, InfoValue: []byte{0x30, 0x00}}),
			call:         func(c *client.Client) error { _, err := c.GetCACertificates(ctx, macCreds(t)); return err },
			want:         "carries no",
			notSupported: true,
		},
		{
			name:         "EmptyResponse",
			body:         genpBody(),
			call:         func(c *client.Client) error { _, err := c.GetCurrentCRL(ctx, macCreds(t)); return err },
			want:         "carries no",
			notSupported: true,
		},
		{
			name: "UnexpectedBody",
			body: pkicmp.NewPKIConfBody(),
			call: func(c *client.Client) error { _, err := c.GetCACertificates(ctx, macCreds(t)); return err },
			want: "unexpected response body type",
		},
		{
			name: "ForgedRootUpdate",
			body: genpBody(forged),
			call: func(c *client.Client) error { _, err := c.GetRootCAUpdate(ctx, oldRoot.cert, macCreds(t)); return err },
			want: "newWithOld is not signed by the old root",
		},
		{
			name: "RootUpdateWithoutOldRoot",
			body: genpBody(genuine),
			call: func(c *client.Client) error { _, err := c.GetRootCAUpdate(ctx, nil, macCreds(t)); return err },
			want: "no old root",
		},
		{
			name: "StaleCRL",
			body: genpBody(pkicmp.NewCRLsInfo([]*x509.RevocationList{crl})),
			call: func(c *client.Client) error {
				_, err := c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: pkicmp.NewCRLIssuerSource(crl.RawIssuer), ThisUpdate: crlTime}, macCreds(t))
				return err
			},
			want: "not newer",
		},
		{
			name: "TwoCRLs",
			body: genpBody(pkicmp.NewCRLsInfo([]*x509.RevocationList{crl, crl})),
			call: func(c *client.Client) error {
				_, err := c.GetCRLUpdate(ctx, pkicmp.CRLStatus{Source: pkicmp.NewCRLIssuerSource(crl.RawIssuer)}, macCreds(t))
				return err
			},
			want: "2 CRLs",
		},
		{
			name: "Rejected",
			body: pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailNotAuthorized}}),
			call: func(c *client.Client) error { _, err := c.GetCACertificates(ctx, macCreds(t)); return err },
			want: "notAuthorized",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := rrMockServer(t, func(int32, *pkicmp.PKIMessage) *pkicmp.PKIBody { return tt.body })
			err := tt.call(client.NewClient(ts.URL))
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.want)
			assert.Equal(t, tt.notSupported, errors.Is(err, client.ErrInfoTypeNotSupported))
		})
	}

	t.Run("GenuineRootUpdate", func(t *testing.T) {
		ts, _ := rrMockServer(t, func(int32, *pkicmp.PKIMessage) *pkicmp.PKIBody { return genpBody(genuine) })
		update, err := client.NewClient(ts.URL).GetRootCAUpdate(ctx, oldRoot.cert, macCreds(t))
		require.NoError(t, err)
		assert.True(t, update.NewWithNew.Equal(newRoot.cert))
	})
}
