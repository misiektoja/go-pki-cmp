package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genmTestCA is a CA certificate and its key.
type genmTestCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newGenMTestRoot returns a self-signed root CA.
func newGenMTestRoot(t *testing.T, name string) genmTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return genmTestCA{cert: signGenMTestCert(t, name, key.Public(), nil, key), key: key}
}

// signGenMTestCert issues a CA certificate for pub, self-signed when parent is nil.
func signGenMTestCert(t *testing.T, name string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
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

// newGenMTestCRL returns a CRL issued by ca with the given thisUpdate.
func newGenMTestCRL(t *testing.T, ca genmTestCA, thisUpdate time.Time) *x509.RevocationList {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(thisUpdate.Unix()),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(24 * time.Hour),
	}, ca.cert, ca.key)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}

// rootRollover is an old root, a new root and the RFC 4210 §4.4 link certificates.
type rootRollover struct {
	oldRoot, newRoot genmTestCA
	update           *RootCAKeyUpdate
}

// newRootRollover builds a complete root CA key update.
func newRootRollover(t *testing.T) rootRollover {
	t.Helper()
	oldRoot := newGenMTestRoot(t, "Old Root")
	newRoot := newGenMTestRoot(t, "New Root")
	return rootRollover{
		oldRoot: oldRoot,
		newRoot: newRoot,
		update: &RootCAKeyUpdate{
			NewWithNew: newRoot.cert,
			NewWithOld: signGenMTestCert(t, "New Root", newRoot.key.Public(), oldRoot.cert, oldRoot.key),
			OldWithNew: signGenMTestCert(t, "Old Root", oldRoot.key.Public(), newRoot.cert, newRoot.key),
		},
	}
}

// General messages survive a full message round trip.
func TestGenMBodyRoundTrip(t *testing.T) {
	items := []InfoTypeAndValue{
		{InfoType: InfoTypeCACerts},
		NewUnsupportedOIDsInfo(InfoTypeCurrentCRL),
	}
	tests := []struct {
		name string
		body *PKIBody
		want []InfoTypeAndValue
	}{
		{"GenM", NewGenMBody(items...), items},
		{"GenP", NewGenPBody(items...), items},
		{"EmptyGenM", NewGenMBody(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, want := tt.body, tt.want
			der, err := NewPKIMessage(body, MessageOptions{}).MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			require.Equal(t, body.Type, parsed.Body.Type)

			var got []InfoTypeAndValue
			if body.Type == BodyTypeGenM {
				content, err := parsed.Body.GenM()
				require.NoError(t, err)
				got = *content
			} else {
				content, err := parsed.Body.GenP()
				require.NoError(t, err)
				got = *content
			}
			require.Len(t, got, len(want))
			for i := range want {
				assert.True(t, want[i].InfoType.Equal(got[i].InfoType))
				assert.Equal(t, want[i].InfoValue, got[i].InfoValue)
			}
		})
	}

	_, err := NewGenMBody().GenP()
	assert.Error(t, err)
}

// RFC 9483 §4.3.1: a sequence of certificates, or an absent value when none is available.
func TestCACertsInfo(t *testing.T) {
	a, b := newGenMTestRoot(t, "A"), newGenMTestRoot(t, "B")

	item := NewCACertsInfo([]*x509.Certificate{a.cert, b.cert})
	certs, err := ParseCACertsInfo(item)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.True(t, certs[0].Equal(a.cert))
	assert.True(t, certs[1].Equal(b.cert))

	none := NewCACertsInfo(nil)
	assert.Empty(t, none.InfoValue)
	certs, err = ParseCACertsInfo(none)
	require.NoError(t, err)
	assert.Nil(t, certs)

	_, err = ParseCACertsInfo(InfoTypeAndValue{InfoType: InfoTypeCACerts, InfoValue: []byte{0x30, 0x00}})
	assert.Error(t, err, "an empty sequence is neither absent nor a certificate list")
	_, err = ParseCACertsInfo(InfoTypeAndValue{InfoType: InfoTypeCRLs})
	assert.Error(t, err)
}

// RFC 9810 §5.3.19.15 encodes the optional certificates under explicit tags,
// which an independent decoder must read back as the original certificates.
func TestRootCAKeyUpdateEncoding(t *testing.T) {
	r := newRootRollover(t)
	item, err := NewRootCAKeyUpdateInfo(r.update)
	require.NoError(t, err)
	assert.True(t, item.InfoType.Equal(InfoTypeRootCAKeyUpdate))

	var decoded struct {
		NewWithNew asn1.RawValue
		NewWithOld asn1.RawValue `asn1:"optional,explicit,tag:0"`
		OldWithNew asn1.RawValue `asn1:"optional,explicit,tag:1"`
	}
	rest, err := asn1.Unmarshal(item.InfoValue, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, r.update.NewWithNew.Raw, decoded.NewWithNew.FullBytes)
	// encoding/asn1 keeps the explicit tag in a RawValue, so its content must be
	// the whole certificate, SEQUENCE tag included.
	assert.Equal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: r.update.NewWithOld.Raw}, asn1.RawValue{Class: decoded.NewWithOld.Class, Tag: decoded.NewWithOld.Tag, IsCompound: decoded.NewWithOld.IsCompound, Bytes: decoded.NewWithOld.Bytes})
	assert.Equal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: r.update.OldWithNew.Raw}, asn1.RawValue{Class: decoded.OldWithNew.Class, Tag: decoded.OldWithNew.Tag, IsCompound: decoded.OldWithNew.IsCompound, Bytes: decoded.OldWithNew.Bytes})

	parsed, err := ParseRootCAKeyUpdateInfo(item)
	require.NoError(t, err)
	assert.True(t, parsed.NewWithNew.Equal(r.update.NewWithNew))
	assert.True(t, parsed.NewWithOld.Equal(r.update.NewWithOld))
	assert.True(t, parsed.OldWithNew.Equal(r.update.OldWithNew))
	require.NoError(t, parsed.Verify(r.oldRoot.cert))

	// Without oldWithNew, only newWithOld follows newWithNew.
	partial := *r.update
	partial.OldWithNew = nil
	item, err = NewRootCAKeyUpdateInfo(&partial)
	require.NoError(t, err)
	parsed, err = ParseRootCAKeyUpdateInfo(item)
	require.NoError(t, err)
	assert.Nil(t, parsed.OldWithNew)
	assert.NotNil(t, parsed.NewWithOld)

	none, err := NewRootCAKeyUpdateInfo(nil)
	require.NoError(t, err)
	assert.Empty(t, none.InfoValue)
	parsed, err = ParseRootCAKeyUpdateInfo(none)
	require.NoError(t, err)
	assert.Nil(t, parsed)

	_, err = NewRootCAKeyUpdateInfo(&RootCAKeyUpdate{})
	assert.Error(t, err)
}

// RFC 4210 §4.4: the new root is trusted only through a link certificate signed by the old root.
func TestRootCAKeyUpdateVerify(t *testing.T) {
	r := newRootRollover(t)
	other := newGenMTestRoot(t, "Other Root")
	require.NoError(t, r.update.Verify(r.oldRoot.cert))

	tests := []struct {
		name   string
		change func(u *RootCAKeyUpdate)
		old    *x509.Certificate
	}{
		{"WrongOldRoot", func(*RootCAKeyUpdate) {}, other.cert},
		{"MissingNewWithOld", func(u *RootCAKeyUpdate) { u.NewWithOld = nil }, r.oldRoot.cert},
		{"NewWithOldForOtherKey", func(u *RootCAKeyUpdate) {
			u.NewWithOld = signGenMTestCert(t, "New Root", other.key.Public(), r.oldRoot.cert, r.oldRoot.key)
		}, r.oldRoot.cert},
		{"NewWithOldForOtherName", func(u *RootCAKeyUpdate) {
			u.NewWithOld = signGenMTestCert(t, "Renamed Root", r.newRoot.key.Public(), r.oldRoot.cert, r.oldRoot.key)
		}, r.oldRoot.cert},
		{"NewWithNewNotSelfSigned", func(u *RootCAKeyUpdate) {
			u.NewWithNew = signGenMTestCert(t, "New Root", r.newRoot.key.Public(), other.cert, other.key)
		}, r.oldRoot.cert},
		{"OldWithNewForOtherKey", func(u *RootCAKeyUpdate) {
			u.OldWithNew = signGenMTestCert(t, "Old Root", other.key.Public(), r.newRoot.cert, r.newRoot.key)
		}, r.oldRoot.cert},
		{"OldWithNewSignedByOther", func(u *RootCAKeyUpdate) {
			u.OldWithNew = signGenMTestCert(t, "Old Root", r.oldRoot.key.Public(), other.cert, other.key)
		}, r.oldRoot.cert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := *r.update
			tt.change(&u)
			assert.Error(t, u.Verify(tt.old))
		})
	}

	var nilUpdate *RootCAKeyUpdate
	assert.Error(t, nilUpdate.Verify(r.oldRoot.cert))
}

// RFC 9483 §4.3.2: the request carries the old root, or nothing when the server knows which one.
func TestRootCACertInfo(t *testing.T) {
	root := newGenMTestRoot(t, "Root")
	got, err := ParseRootCACertInfo(NewRootCACertInfo(root.cert))
	require.NoError(t, err)
	assert.True(t, got.Equal(root.cert))

	got, err = ParseRootCACertInfo(NewRootCACertInfo(nil))
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = ParseRootCACertInfo(InfoTypeAndValue{InfoType: InfoTypeRootCACert, InfoValue: []byte{0x30, 0x00}})
	assert.Error(t, err)
}

// RFC 9483 §4.3.3: a template without publicKey and an optional keySpec.
func TestCertReqTemplateInfo(t *testing.T) {
	ecParams, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	require.NoError(t, err)
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
		Parameters: asn1.RawValue{FullBytes: ecParams},
	})
	require.NoError(t, err)
	rsaLen, err := asn1.Marshal(2048)
	require.NoError(t, err)

	tmpl := &CertReqTemplate{
		Template: CertTemplate{Subject: NewDirectoryName(pkix.Name{CommonName: "", Organization: []string{"Example"}})},
		KeySpec: []AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 11}, Value: algID},
			{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 12}, Value: rsaLen},
		},
	}
	item, err := NewCertReqTemplateInfo(tmpl)
	require.NoError(t, err)
	got, err := ParseCertReqTemplateInfo(item)
	require.NoError(t, err)
	var subject pkix.Name
	subject.FillFromRDNSequence(&got.Template.Subject.DirectoryName)
	assert.Equal(t, []string{"Example"}, subject.Organization)
	require.Len(t, got.KeySpec, 2)
	assert.Equal(t, algID, got.KeySpec[0].Value)
	assert.Equal(t, rsaLen, got.KeySpec[1].Value)

	// Without keySpec the sequence holds only the template.
	item, err = NewCertReqTemplateInfo(&CertReqTemplate{Template: tmpl.Template})
	require.NoError(t, err)
	got, err = ParseCertReqTemplateInfo(item)
	require.NoError(t, err)
	assert.Empty(t, got.KeySpec)

	none, err := NewCertReqTemplateInfo(nil)
	require.NoError(t, err)
	assert.Empty(t, none.InfoValue)
	got, err = ParseCertReqTemplateInfo(none)
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = NewCertReqTemplateInfo(&CertReqTemplate{Template: CertTemplate{PublicKey: []byte{0x30, 0x00}}})
	assert.Error(t, err)
	_, err = NewCertReqTemplateInfo(&CertReqTemplate{Template: CertTemplate{SerialNumber: big.NewInt(1)}})
	assert.Error(t, err)
}

// RFC 9810 §5.3.19.17: the source choice is explicitly tagged, and the
// distribution point name keeps the implicit tags of RFC 5280.
func TestCRLStatusEncoding(t *testing.T) {
	thisUpdate := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	item, err := NewCRLStatusListInfo(CRLStatus{Source: NewCRLDistributionPointSource("http://a/c"), ThisUpdate: thisUpdate})
	require.NoError(t, err)
	assert.True(t, item.InfoType.Equal(InfoTypeCRLStatusList))

	utc, err := asn1.Marshal(thisUpdate)
	require.NoError(t, err)
	// dpn [0] EXPLICIT wraps fullName [0] IMPLICIT GeneralNames, which holds
	// uniformResourceIdentifier [6] IMPLICIT IA5String.
	want := tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, tlv(0x86, []byte("http://a/c")))), utc))
	assert.Equal(t, want, item.InfoValue)

	statuses, err := ParseCRLStatusListInfo(item)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, []string{"http://a/c"}, statuses[0].Source.DistributionPointURIs())
	assert.True(t, thisUpdate.Equal(statuses[0].ThisUpdate))
	assert.Empty(t, statuses[0].Source.DirectoryNames())
}

// RFC 9483 §4.3.4 names the CRL issuer in a directoryName when no distribution point is known.
func TestCRLStatusIssuerSource(t *testing.T) {
	ca := newGenMTestRoot(t, "CRL Issuer")
	item, err := NewCRLStatusListInfo(CRLStatus{Source: NewCRLIssuerSource(ca.cert.RawSubject)})
	require.NoError(t, err)

	var decoded struct {
		Source asn1.RawValue `asn1:"explicit,tag:1"`
	}
	rest, err := asn1.Unmarshal(item.InfoValue[2:], &decoded)
	require.NoError(t, err, "CRLStatus carries the issuer choice under an explicit [1]")
	assert.Empty(t, rest)

	statuses, err := ParseCRLStatusListInfo(item)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].ThisUpdate.IsZero())
	assert.Equal(t, [][]byte{ca.cert.RawSubject}, statuses[0].Source.DirectoryNames())
	assert.Empty(t, statuses[0].Source.DistributionPointURIs())

	// A time from 2050 on is a GeneralizedTime (RFC 5280 §4.1.2.5).
	late := time.Date(2051, 1, 2, 3, 4, 5, 0, time.UTC)
	item, err = NewCRLStatusListInfo(CRLStatus{Source: NewCRLIssuerSource(ca.cert.RawSubject), ThisUpdate: late})
	require.NoError(t, err)
	statuses, err = ParseCRLStatusListInfo(item)
	require.NoError(t, err)
	assert.True(t, late.Equal(statuses[0].ThisUpdate))

	// A client holding a CRL without an issuingDistributionPoint names its issuer in the fullName.
	dpnName := CRLSource{DistributionPoint: tlv(0xa0, generalNameDER(&statuses[0].Source.Issuer[0]))}
	assert.Equal(t, [][]byte{ca.cert.RawSubject}, dpnName.DirectoryNames())
	assert.Empty(t, dpnName.DistributionPointURIs())
	assert.False(t, dpnName.IsZero())
	assert.True(t, CRLSource{}.IsZero())

	_, err = NewCRLStatusListInfo()
	assert.Error(t, err)
	_, err = NewCRLStatusListInfo(CRLStatus{})
	assert.Error(t, err, "a status needs a source")
	_, err = ParseCRLStatusListInfo(InfoTypeAndValue{InfoType: InfoTypeCRLStatusList})
	assert.Error(t, err, "RFC 9483 §4.3.4 requires the request value")
	_, err = ParseCRLStatusListInfo(InfoTypeAndValue{InfoType: InfoTypeCRLStatusList, InfoValue: []byte{0x30, 0x00}})
	assert.Error(t, err)
	_, err = ParseCRLStatusListInfo(InfoTypeAndValue{InfoType: InfoTypeCRLStatusList, InfoValue: []byte{0x30, 0x04, 0x30, 0x02, 0x82, 0x00}})
	assert.Error(t, err, "an unknown source choice is rejected")
}

// RFC 9483 §4.3.4 and RFC 9810 §5.3.19.6: CRLs travel as DER CertificateList values.
func TestCRLInfo(t *testing.T) {
	ca := newGenMTestRoot(t, "CRL Issuer")
	crl := newGenMTestCRL(t, ca, time.Now().Add(-time.Minute).Truncate(time.Second))

	crls, err := ParseCRLsInfo(NewCRLsInfo([]*x509.RevocationList{crl}))
	require.NoError(t, err)
	require.Len(t, crls, 1)
	assert.Equal(t, crl.Raw, crls[0].Raw)

	crls, err = ParseCRLsInfo(NewCRLsInfo(nil))
	require.NoError(t, err)
	assert.Nil(t, crls)

	current, err := ParseCurrentCRLInfo(NewCurrentCRLInfo(crl))
	require.NoError(t, err)
	assert.Equal(t, crl.Raw, current.Raw)
	current, err = ParseCurrentCRLInfo(NewCurrentCRLInfo(nil))
	require.NoError(t, err)
	assert.Nil(t, current)

	_, err = ParseCRLsInfo(InfoTypeAndValue{InfoType: InfoTypeCRLs, InfoValue: []byte{0x30, 0x00}})
	assert.Error(t, err)
}

// RFC 9810 §5.3.19.7 lists the info types a server does not support.
func TestUnsupportedOIDsInfo(t *testing.T) {
	item := NewUnsupportedOIDsInfo(InfoTypeCurrentCRL, InfoTypeCRLStatusList)
	oids, err := ParseUnsupportedOIDsInfo(item)
	require.NoError(t, err)
	require.Len(t, oids, 2)
	assert.True(t, oids[0].Equal(InfoTypeCurrentCRL))
	assert.True(t, oids[1].Equal(InfoTypeCRLStatusList))

	_, err = ParseUnsupportedOIDsInfo(InfoTypeAndValue{InfoType: InfoTypeUnsupportedOIDs})
	assert.Error(t, err)
}

// RFC 9810 §5.1.1.4: certProfile is a sequence of UTF8String names.
func TestCertProfileInfo(t *testing.T) {
	h := PKIHeader{GeneralInfo: []InfoTypeAndValue{NewCertProfileInfo("device")}}
	assert.Equal(t, "device", h.CertProfile())
	assert.Equal(t, []byte{0x30, 0x08, 0x0c, 0x06, 'd', 'e', 'v', 'i', 'c', 'e'}, h.GeneralInfo[0].InfoValue)
}

// tlv encodes a short DER element with the given tag byte.
func tlv(tag byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	return append([]byte{tag, byte(len(c))}, c...)
}
