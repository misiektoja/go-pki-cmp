package server_test

import (
	"context"
	"crypto"
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

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// generalCA answers every general message type the server supports.
type generalCA struct {
	issueOnlyCA
	caCerts  []*x509.Certificate
	update   *pkicmp.RootCAKeyUpdate
	template *pkicmp.CertReqTemplate
	crl      *x509.RevocationList
	err      error

	oldRoot *x509.Certificate
	profile string
	source  pkicmp.CRLSource
}

// CACertificates returns the configured CA certificates.
func (c *generalCA) CACertificates(context.Context, *server.SenderIdentity) ([]*x509.Certificate, error) {
	return c.caCerts, c.err
}

// RootCAUpdate records the root the client names and returns the configured update.
func (c *generalCA) RootCAUpdate(_ context.Context, oldRoot *x509.Certificate, _ *server.SenderIdentity) (*pkicmp.RootCAKeyUpdate, error) {
	c.oldRoot = oldRoot
	return c.update, c.err
}

// CertReqTemplate records the requested profile and returns the configured template.
func (c *generalCA) CertReqTemplate(_ context.Context, profile string, _ *server.SenderIdentity) (*pkicmp.CertReqTemplate, error) {
	c.profile = profile
	return c.template, c.err
}

// LatestCRL records the requested source and returns the configured CRL.
func (c *generalCA) LatestCRL(_ context.Context, source pkicmp.CRLSource, _ *server.SenderIdentity) (*x509.RevocationList, error) {
	c.source = source
	return c.crl, c.err
}

// genmRoot is a CA certificate and its key.
type genmRoot struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newGenMRoot returns a self-signed root CA.
func newGenMRoot(t *testing.T, name string) genmRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return genmRoot{cert: signGenMCert(t, name, key.Public(), nil, key), key: key}
}

// signGenMCert issues a CA certificate for pub, self-signed when parent is nil.
func signGenMCert(t *testing.T, name string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
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

// genmCRL returns a CRL issued by root with the given thisUpdate.
func genmCRL(t *testing.T, root genmRoot, thisUpdate time.Time) *x509.RevocationList {
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

// signedGenM builds a genm carrying items and signed by signer.
func signedGenM(t *testing.T, signer revocationEntity, opts pkicmp.MessageOptions, items ...pkicmp.InfoTypeAndValue) *pkicmp.PKIMessage {
	t.Helper()
	opts.Sender = pkicmp.NewDirectoryNameFromRawDER(signer.cert.RawSubject)
	msg := pkicmp.NewPKIMessage(pkicmp.NewGenMBody(items...), opts)
	creds, err := pkicmp.NewSignatureCredentials(signer.key, signer.cert)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	return msg
}

// genpItems returns the items of a genp.
func genpItems(t *testing.T, msg *pkicmp.PKIMessage) []pkicmp.InfoTypeAndValue {
	t.Helper()
	require.Equal(t, pkicmp.BodyTypeGenP, msg.Body.Type, "expected genp, got %s", msg.Body.Type)
	content, err := msg.Body.GenP()
	require.NoError(t, err)
	return *content
}

// unsupportedIn returns the OIDs of the single unsupportedOIDs item in items.
func unsupportedIn(t *testing.T, items []pkicmp.InfoTypeAndValue) []asn1.ObjectIdentifier {
	t.Helper()
	for _, item := range items {
		if item.InfoType.Equal(pkicmp.InfoTypeUnsupportedOIDs) {
			oids, err := pkicmp.ParseUnsupportedOIDsInfo(item)
			require.NoError(t, err)
			return oids
		}
	}
	t.Fatalf("no unsupportedOIDs item")
	return nil
}

// RFC 9483 §4.3: each support message is answered with the matching item.
func TestGeneralMessagesAnswered(t *testing.T) {
	f := newRevocationFixture(t)
	oldRoot, newRoot := newGenMRoot(t, "Old Root"), newGenMRoot(t, "New Root")
	update := &pkicmp.RootCAKeyUpdate{
		NewWithNew: newRoot.cert,
		NewWithOld: signGenMCert(t, "New Root", newRoot.key.Public(), oldRoot.cert, oldRoot.key),
	}
	crlTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	ca := &generalCA{
		caCerts:  []*x509.Certificate{f.caCert},
		update:   update,
		template: &pkicmp.CertReqTemplate{Template: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(pkix.Name{Organization: []string{"Example"}})}},
		crl:      genmCRL(t, newGenMRoot(t, "CRL Issuer"), crlTime),
	}
	ts := f.serve(t, ca, server.LightweightPolicy())

	t.Run("CACertificates", func(t *testing.T) {
		items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts})))
		require.Len(t, items, 1)
		certs, err := pkicmp.ParseCACertsInfo(items[0])
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.True(t, certs[0].Equal(f.caCert))
	})

	t.Run("RootCAUpdate", func(t *testing.T) {
		items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.NewRootCACertInfo(oldRoot.cert))))
		require.Len(t, items, 1)
		got, err := pkicmp.ParseRootCAKeyUpdateInfo(items[0])
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.NewWithNew.Equal(newRoot.cert))
		require.NoError(t, got.Verify(oldRoot.cert))
		assert.True(t, ca.oldRoot.Equal(oldRoot.cert))
	})

	t.Run("CertReqTemplateWithProfile", func(t *testing.T) {
		msg := pkicmp.NewPKIMessage(pkicmp.NewGenMBody(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCertReqTemplate}), pkicmp.MessageOptions{
			Sender: pkicmp.NewDirectoryNameFromRawDER(f.ee.cert.RawSubject),
		})
		msg.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{pkicmp.NewCertProfileInfo("router")}
		creds, err := pkicmp.NewSignatureCredentials(f.ee.key, f.ee.cert)
		require.NoError(t, err)
		require.NoError(t, creds.Protect(msg))
		items := genpItems(t, postCMP(t, ts, msg))
		require.Len(t, items, 1)
		got, err := pkicmp.ParseCertReqTemplateInfo(items[0])
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "router", ca.profile)
	})

	// RFC 9483 §4.3.4: the CRL is returned only when it is newer than the one the client holds.
	crlTests := []struct {
		name       string
		thisUpdate time.Time
		want       bool
	}{
		{"NoCRLHeld", time.Time{}, true},
		{"OlderCRLHeld", crlTime.Add(-time.Hour), true},
		{"SameCRLHeld", crlTime, false},
		{"NewerCRLHeld", crlTime.Add(time.Hour), false},
	}
	for _, tt := range crlTests {
		t.Run("CRL"+tt.name, func(t *testing.T) {
			source := pkicmp.NewCRLDistributionPointSource("http://crl.example/ca.crl")
			item, err := pkicmp.NewCRLStatusListInfo(pkicmp.CRLStatus{Source: source, ThisUpdate: tt.thisUpdate})
			require.NoError(t, err)
			items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, item)))
			require.Len(t, items, 1)
			crls, err := pkicmp.ParseCRLsInfo(items[0])
			require.NoError(t, err)
			if tt.want {
				require.Len(t, crls, 1)
				assert.Equal(t, ca.crl.Raw, crls[0].Raw)
			} else {
				assert.Empty(t, crls)
			}
			assert.Equal(t, []string{"http://crl.example/ca.crl"}, ca.source.DistributionPointURIs())
		})
	}

	t.Run("CurrentCRL", func(t *testing.T) {
		items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCurrentCRL})))
		require.Len(t, items, 1)
		got, err := pkicmp.ParseCurrentCRLInfo(items[0])
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, ca.crl.Raw, got.Raw)
		assert.True(t, ca.source.IsZero(), "a current CRL request names no source")
	})

	t.Run("MACProtected", func(t *testing.T) {
		msg := pkicmp.NewPKIMessage(pkicmp.NewGenMBody(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}), macMessageOpts())
		protectMAC(msg, []byte("revocation-secret"))
		items := genpItems(t, postCMP(t, ts, msg))
		require.Len(t, items, 1)
		assert.True(t, items[0].InfoType.Equal(pkicmp.InfoTypeCACerts))
	})
}

// RFC 9810 §5.3.19.7: info types without a provider are listed as unsupported, next to the answered ones.
func TestGeneralMessageUnsupportedTypes(t *testing.T) {
	f := newRevocationFixture(t)
	crlStatus, err := pkicmp.NewCRLStatusListInfo(pkicmp.CRLStatus{Source: pkicmp.NewCRLIssuerSource(f.caCert.RawSubject)})
	require.NoError(t, err)
	unknown := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 99}

	t.Run("NoProviders", func(t *testing.T) {
		ts := f.serve(t, &issueOnlyCA{}, server.LightweightPolicy())
		for _, item := range []pkicmp.InfoTypeAndValue{
			{InfoType: pkicmp.InfoTypeCACerts},
			pkicmp.NewRootCACertInfo(f.caCert),
			{InfoType: pkicmp.InfoTypeCertReqTemplate},
			crlStatus,
			{InfoType: pkicmp.InfoTypeCurrentCRL},
			{InfoType: unknown},
		} {
			items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, item)))
			require.Len(t, items, 1)
			oids := unsupportedIn(t, items)
			require.Len(t, oids, 1)
			assert.True(t, oids[0].Equal(item.InfoType), "%s", item.InfoType)
		}
	})

	t.Run("MixedRequest", func(t *testing.T) {
		ts := f.serve(t, &generalCA{caCerts: []*x509.Certificate{f.caCert}}, server.LightweightPolicy())
		items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{},
			pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts},
			pkicmp.InfoTypeAndValue{InfoType: unknown},
		)))
		require.Len(t, items, 2)
		assert.True(t, items[0].InfoType.Equal(pkicmp.InfoTypeCACerts))
		oids := unsupportedIn(t, items)
		require.Len(t, oids, 1)
		assert.True(t, oids[0].Equal(unknown))
	})

	t.Run("EmptyRequest", func(t *testing.T) {
		ts := f.serve(t, &issueOnlyCA{}, server.LightweightPolicy())
		assert.Empty(t, genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}))))
	})
}

// The server refuses malformed requests and CA answers it cannot stand behind.
func TestGeneralMessageFailures(t *testing.T) {
	f := newRevocationFixture(t)
	oldRoot, newRoot, other := newGenMRoot(t, "Old Root"), newGenMRoot(t, "New Root"), newGenMRoot(t, "Other Root")

	tests := []struct {
		name string
		ca   *generalCA
		item pkicmp.InfoTypeAndValue
		fail pkicmp.PKIFailureInfo
	}{
		{"MalformedRootCACert", &generalCA{}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeRootCACert, InfoValue: []byte{0x30, 0x00}}, pkicmp.FailBadDataFormat},
		{"AbsentCRLStatusList", &generalCA{}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCRLStatusList}, pkicmp.FailBadDataFormat},
		{"UpdateWithoutNewWithOld", &generalCA{update: &pkicmp.RootCAKeyUpdate{NewWithNew: newRoot.cert}}, pkicmp.NewRootCACertInfo(oldRoot.cert), pkicmp.FailSystemFailure},
		{"UpdateSignedByOtherRoot", &generalCA{update: &pkicmp.RootCAKeyUpdate{
			NewWithNew: newRoot.cert,
			NewWithOld: signGenMCert(t, "New Root", newRoot.key.Public(), other.cert, other.key),
		}}, pkicmp.NewRootCACertInfo(oldRoot.cert), pkicmp.FailSystemFailure},
		{"TemplateWithPublicKey", &generalCA{template: &pkicmp.CertReqTemplate{Template: pkicmp.CertTemplate{PublicKey: []byte{0x30, 0x00}}}}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCertReqTemplate}, pkicmp.FailSystemFailure},
		{"ProviderError", &generalCA{err: &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized}}, pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}, pkicmp.FailNotAuthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := f.serve(t, tt.ca, server.LightweightPolicy())
			resp := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, tt.item))
			require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
			si := statusInfoOf(t, resp)
			assert.Equal(t, pkicmp.StatusRejection, si.Status)
			assert.Equal(t, tt.fail, si.FailInfo)
		})
	}
}

// RFC 9483 §4.3 rules apply under WithStrictProfileValidation only.
func TestGeneralMessageStrictProfile(t *testing.T) {
	f := newRevocationFixture(t)
	ca := &generalCA{caCerts: []*x509.Certificate{f.caCert}}
	strict := f.serve(t, ca, server.LightweightPolicy(), server.WithStrictProfileValidation())
	lenient := f.serve(t, ca, server.LightweightPolicy())

	source := pkicmp.NewCRLIssuerSource(f.caCert.RawSubject)
	twoStatuses, err := pkicmp.NewCRLStatusListInfo(pkicmp.CRLStatus{Source: source}, pkicmp.CRLStatus{Source: source})
	require.NoError(t, err)
	caCerts := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}

	tests := []struct {
		name  string
		items []pkicmp.InfoTypeAndValue
		fail  pkicmp.PKIFailureInfo
	}{
		{"TwoItems", []pkicmp.InfoTypeAndValue{caCerts, caCerts}, pkicmp.FailBadRequest},
		{"NoItems", nil, pkicmp.FailBadRequest},
		{"CACertsWithValue", []pkicmp.InfoTypeAndValue{{InfoType: pkicmp.InfoTypeCACerts, InfoValue: []byte{0x05, 0x00}}}, pkicmp.FailBadRequest},
		{"TemplateWithValue", []pkicmp.InfoTypeAndValue{{InfoType: pkicmp.InfoTypeCertReqTemplate, InfoValue: []byte{0x05, 0x00}}}, pkicmp.FailBadRequest},
		{"CurrentCRLWithValue", []pkicmp.InfoTypeAndValue{{InfoType: pkicmp.InfoTypeCurrentCRL, InfoValue: []byte{0x05, 0x00}}}, pkicmp.FailBadRequest},
		{"TwoCRLStatuses", []pkicmp.InfoTypeAndValue{twoStatuses}, pkicmp.FailBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := postCMP(t, strict, signedGenM(t, f.ee, pkicmp.MessageOptions{}, tt.items...))
			require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
			assert.Equal(t, tt.fail, statusInfoOf(t, resp).FailInfo)

			assert.Equal(t, pkicmp.BodyTypeGenP, postCMP(t, lenient, signedGenM(t, f.ee, pkicmp.MessageOptions{}, tt.items...)).Body.Type)
		})
	}

	t.Run("RequiresExtraCerts", func(t *testing.T) {
		msg := signedGenM(t, f.ee, pkicmp.MessageOptions{}, caCerts)
		msg.ExtraCerts = nil
		resp := postCMP(t, strict, msg)
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailBadMessageCheck, statusInfoOf(t, resp).FailInfo)
	})
}

// A genm starts and ends a transaction, so its transactionID cannot be reused.
func TestGeneralMessageTransactionRules(t *testing.T) {
	f := newRevocationFixture(t)
	ts := f.serve(t, &generalCA{}, server.LightweightPolicy())
	txnID := []byte("general-message-transaction")
	caCerts := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}

	assert.Equal(t, pkicmp.BodyTypeGenP, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)).Body.Type)
	second := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts))
	require.Equal(t, pkicmp.BodyTypeError, second.Body.Type)
	assert.Equal(t, pkicmp.FailTransactionIdInUse, statusInfoOf(t, second).FailInfo)

	resp := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{RecipNonce: make([]byte, 16)}, caCerts))
	require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
	assert.Equal(t, pkicmp.FailBadRecipientNonce, statusInfoOf(t, resp).FailInfo)
}

// Custom handlers answer through Response.GeneralResponse.
func TestGeneralMessageHandlerResults(t *testing.T) {
	f := newRevocationFixture(t)
	serve := func(t *testing.T, h server.HandlerFunc) *httptest.Server {
		srv := server.New(h, server.WithSigner(f.caKey, f.caCert), server.WithCertificateLookup(f.backend))
		require.NoError(t, srv.Err())
		ts := httptest.NewServer(srv)
		t.Cleanup(ts.Close)
		return ts
	}
	caCerts := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}

	t.Run("Items", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return &server.Response{GeneralResponse: []pkicmp.InfoTypeAndValue{pkicmp.NewCACertsInfo([]*x509.Certificate{f.caCert})}}, nil
		})
		items := genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, caCerts)))
		require.Len(t, items, 1)
		assert.True(t, items[0].InfoType.Equal(pkicmp.InfoTypeCACerts))
	})

	t.Run("NoAnswerIsUnsupported", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return nil, nil
		})
		oids := unsupportedIn(t, genpItems(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, caCerts))))
		require.Len(t, oids, 1)
		assert.True(t, oids[0].Equal(pkicmp.InfoTypeCACerts))
	})

	t.Run("WaitingIsNotSupported", func(t *testing.T) {
		ts := serve(t, func(context.Context, *pkicmp.PKIMessage, *server.SenderIdentity) (*server.Response, error) {
			return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: 10}}, nil
		})
		resp := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{}, caCerts))
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailSystemFailure, statusInfoOf(t, resp).FailInfo)
	})
}
