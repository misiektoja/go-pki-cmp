package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Every parser in this package consumes bytes chosen by a peer, and protection
// is verified before anything else establishes who that peer is. The targets
// below therefore assert only that no input reaches a panic: what a message
// means is the subject of the table tests, what it must never do is crash the
// process that parsed it.

// fuzzSecret is the shared secret used to build the MAC seeds and to verify them again.
var fuzzSecret = []byte("fuzz-shared-secret")

// fuzzSeeds returns encoded messages covering each body type and both protection mechanisms.
func fuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()

	// The golden files are OpenSSL-generated requests, so they carry encodings
	// this package did not produce itself.
	golden, err := filepath.Glob(filepath.Join("testdata", "*.der"))
	if err != nil {
		tb.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	cert := fuzzSeedCertificate(tb, key)

	revDetails, err := pkicmp.NewRevDetails(cert, pkicmp.CRLReasonKeyCompromise)
	if err != nil {
		tb.Fatal(err)
	}

	crlStatus, err := pkicmp.NewCRLStatusListInfo(pkicmp.CRLStatus{Source: pkicmp.NewCRLDistributionPointSource("http://a/c"), ThisUpdate: time.Now()})
	if err != nil {
		tb.Fatal(err)
	}
	rootUpdate, err := pkicmp.NewRootCAKeyUpdateInfo(&pkicmp.RootCAKeyUpdate{NewWithNew: cert, NewWithOld: cert, OldWithNew: cert})
	if err != nil {
		tb.Fatal(err)
	}
	template, err := pkicmp.NewCertReqTemplateInfo(&pkicmp.CertReqTemplate{
		Template: pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject)},
		KeySpec:  []pkicmp.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 12}, Value: []byte{0x02, 0x02, 0x08, 0x00}}},
	})
	if err != nil {
		tb.Fatal(err)
	}

	checkAfter := int64(60)
	bodies := []*pkicmp.PKIBody{
		pkicmp.NewGenMBody(crlStatus, pkicmp.NewRootCACertInfo(cert), pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}),
		pkicmp.NewGenPBody(pkicmp.NewCACertsInfo([]*x509.Certificate{cert}), rootUpdate, template, pkicmp.NewUnsupportedOIDsInfo(pkicmp.InfoTypeCRLs)),
		pkicmp.NewRRBody(&pkicmp.RevReqContent{revDetails}),
		pkicmp.NewPKIConfBody(),
		pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID:        0,
				Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: cert.Raw}}},
			}},
		}),
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{{CertHash: cert.Raw[:32], CertReqID: 0}}),
		pkicmp.NewPollReqBody(&pkicmp.PollReqContent{0}),
		pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: 0, CheckAfter: checkAfter}}),
		pkicmp.NewRPBody(&pkicmp.RevRepContent{
			Status:   []pkicmp.PKIStatusInfo{{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailCertRevoked}},
			RevCerts: []pkicmp.CertID{{Issuer: pkicmp.NewDirectoryNameFromRawDER(cert.RawIssuer), SerialNumber: cert.SerialNumber}},
		}),
		pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
			PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRequest},
		}),
	}

	protectors := []func(*pkicmp.PKIMessage) error{
		func(m *pkicmp.PKIMessage) error {
			creds, err := pkicmp.NewMACCredentials(fuzzSecret)
			if err != nil {
				return err
			}
			return creds.Protect(m)
		},
		func(m *pkicmp.PKIMessage) error {
			creds, err := pkicmp.NewSignatureCredentials(key, cert)
			if err != nil {
				return err
			}
			return creds.Protect(m)
		},
	}

	// One seed per golden file, one per protected body and one nested message.
	seeds := make([][]byte, 0, len(golden)+len(bodies)*len(protectors)+1)
	for _, path := range golden {
		data, err := os.ReadFile(path) // #nosec G304 -- fixed test data directory
		if err != nil {
			tb.Fatal(err)
		}
		seeds = append(seeds, data)
	}

	for _, body := range bodies {
		for _, protect := range protectors {
			msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
				Sender: pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject),
			})
			if err := protect(msg); err != nil {
				tb.Fatal(err)
			}
			der, err := msg.MarshalBinary()
			if err != nil {
				tb.Fatal(err)
			}
			seeds = append(seeds, der)
		}
	}

	// A nested body carrying the last two protected messages.
	last := seeds[len(seeds)-2:]
	inner := make([]*pkicmp.PKIMessage, 0, len(last))
	for _, der := range last {
		msg, err := pkicmp.ParsePKIMessage(der)
		if err != nil {
			tb.Fatal(err)
		}
		inner = append(inner, msg)
	}
	nested, err := pkicmp.NewPKIMessage(pkicmp.NewNestedBody(inner...), pkicmp.MessageOptions{}).MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	seeds = append(seeds, nested)

	return seeds
}

// fuzzSeedCertificate returns a self-signed certificate for building protected seeds.
func fuzzSeedCertificate(tb testing.TB, key *ecdsa.PrivateKey) *x509.Certificate {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fuzz Signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return cert
}

// exerciseBody parses the body CHOICE, which happens lazily on the first accessor call.
func exerciseBody(msg *pkicmp.PKIMessage) {
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		_, _ = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		_, _ = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		_, _ = msg.Body.KUR()
	case pkicmp.BodyTypeP10CR:
		_, _ = msg.Body.P10CR()
	case pkicmp.BodyTypeIP:
		_, _ = msg.Body.IP()
	case pkicmp.BodyTypeCP:
		_, _ = msg.Body.CP()
	case pkicmp.BodyTypeKUP:
		_, _ = msg.Body.KUP()
	case pkicmp.BodyTypeCertConf:
		_, _ = msg.Body.CertConf()
	case pkicmp.BodyTypePKIConf:
		_, _ = msg.Body.PKIConf()
	case pkicmp.BodyTypePollReq:
		_, _ = msg.Body.PollReq()
	case pkicmp.BodyTypePollRep:
		_, _ = msg.Body.PollRep()
	case pkicmp.BodyTypeRR:
		if rr, err := msg.Body.RR(); err == nil {
			for i := range *rr {
				_, _ = (*rr)[i].CRLEntryExtensions()
			}
		}
	case pkicmp.BodyTypeRP:
		_, _ = msg.Body.RP()
	case pkicmp.BodyTypeError:
		_, _ = msg.Body.Error()
	case pkicmp.BodyTypeGenM:
		if content, err := msg.Body.GenM(); err == nil {
			exerciseInfoItems(*content)
		}
	case pkicmp.BodyTypeGenP:
		if content, err := msg.Body.GenP(); err == nil {
			exerciseInfoItems(*content)
		}
	case pkicmp.BodyTypeNested:
		// Each level of nesting costs input bytes, so the recursion is bounded.
		if msgs, err := msg.Body.Nested(); err == nil {
			for _, inner := range msgs {
				exerciseBody(inner)
			}
		}
	}
}

// FuzzParsePKIMessage drives the whole-message parser and every body accessor.
func FuzzParsePKIMessage(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := pkicmp.ParsePKIMessage(data)
		if err != nil {
			return
		}
		exerciseBody(msg)

		// Re-encoding is allowed to fail, since a body this package can parse is
		// not always one it can build, but it must not panic and it must not
		// invent content for a message that carried none.
		if encoded, err := msg.MarshalBinary(); err == nil && len(encoded) == 0 {
			t.Fatal("marshalling a parsed message produced no bytes")
		}

		// Status accessors format peer-chosen text and failInfo bits.
		if rep, err := msg.Body.CertReqMessages(); err == nil && rep != nil {
			for i := range *rep {
				_ = (*rep)[i].Subject()
			}
		}
	})
}

// FuzzVerifyMACProtection drives PBM and PBMAC1 parameter handling, which runs
// before the message is authenticated and therefore on parameters any peer chose.
func FuzzVerifyMACProtection(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := pkicmp.ParsePKIMessage(data)
		if err != nil {
			return
		}
		// A verification failure is the expected outcome for almost every input.
		// The target is looking for a panic or a hang inside key derivation.
		_, _ = msg.Verify(pkicmp.VerifyOptions{SharedSecret: fuzzSecret})
	})
}

// FuzzVerifySignatureProtection drives extraCerts parsing, chain building and
// the sender binding on both the trust pool and the pre-trusted certificate path.
func FuzzVerifySignatureProtection(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	anchor := fuzzSeedCertificate(f, key)
	pool := x509.NewCertPool()
	pool.AddCert(anchor)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := pkicmp.ParsePKIMessage(data)
		if err != nil {
			return
		}
		_, _ = msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: msg.ExtraCerts,
			SenderKID:  msg.Header.SenderKID,
		})
		_, _ = msg.Verify(pkicmp.VerifyOptions{TrustedCert: anchor})
	})
}

// exerciseInfoItems runs every general message value parser on each item, whatever its info type.
func exerciseInfoItems(items []pkicmp.InfoTypeAndValue) {
	for _, item := range items {
		// The parsers check the info type first, so each item is relabelled to reach the value decoding.
		for _, infoType := range []asn1.ObjectIdentifier{
			pkicmp.InfoTypeCACerts, pkicmp.InfoTypeRootCACert, pkicmp.InfoTypeRootCAKeyUpdate,
			pkicmp.InfoTypeCertReqTemplate, pkicmp.InfoTypeCRLStatusList, pkicmp.InfoTypeCRLs,
			pkicmp.InfoTypeCurrentCRL, pkicmp.InfoTypeUnsupportedOIDs,
		} {
			item.InfoType = infoType
			_, _ = pkicmp.ParseCACertsInfo(item)
			_, _ = pkicmp.ParseRootCACertInfo(item)
			if update, err := pkicmp.ParseRootCAKeyUpdateInfo(item); err == nil && update != nil {
				_ = update.Verify(update.NewWithNew)
			}
			_, _ = pkicmp.ParseCertReqTemplateInfo(item)
			if statuses, err := pkicmp.ParseCRLStatusListInfo(item); err == nil {
				for _, status := range statuses {
					_ = status.Source.DistributionPointURIs()
					_ = status.Source.DirectoryNames()
				}
			}
			_, _ = pkicmp.ParseCRLsInfo(item)
			_, _ = pkicmp.ParseCurrentCRLInfo(item)
			_, _ = pkicmp.ParseUnsupportedOIDsInfo(item)
		}
	}
}
