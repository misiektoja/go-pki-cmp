package pkicmp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/misiektoja/go-pki-cmp/internal/kemcert"
	"github.com/misiektoja/go-pki-cmp/internal/slhdsasig"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// The SLH-DSA targets reach the parsers and signature checks for RFC 9909 keys
// and signatures. Like the targets in fuzz_test.go they look for panics and
// hangs. FuzzSLHDSAPublicKey also checks that the two SLH-DSA key parsers agree.
// Every target takes its trust anchor from the input, because each fuzzing
// worker builds its own fixture with fresh keys.

// slhdsaFuzzFixture holds signed SLH-DSA objects that seed the SLH-DSA targets.
// The root and the CSR use SLH-DSA-SHA2-128f. The end entity, the proof of
// possession and the new root use SLH-DSA-SHAKE-128f. The small parameter sets
// sign many times slower, and the golden OpenSSL requests already carry
// SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s signatures.
type slhdsaFuzzFixture struct {
	root, signer                       *x509.Certificate
	newWithNew, newWithOld, oldWithNew *x509.Certificate
	csr                                []byte
	pop                                []byte
	rootProtected, signerProtected     []byte
	rootUpdate                         []byte
}

var (
	slhdsaFuzzOnce    sync.Once
	slhdsaFuzzObjects *slhdsaFuzzFixture
	errSLHDSAFuzz     error
)

// slhdsaFuzzSeeds returns the shared SLH-DSA fixture. SLH-DSA signing is slow,
// especially under the race detector, so the fixture is made once per test binary.
func slhdsaFuzzSeeds(tb testing.TB) *slhdsaFuzzFixture {
	tb.Helper()
	slhdsaFuzzOnce.Do(func() { slhdsaFuzzObjects, errSLHDSAFuzz = newSLHDSAFuzzFixture() })
	if errSLHDSAFuzz != nil {
		tb.Fatal(errSLHDSAFuzz)
	}
	return slhdsaFuzzObjects
}

// newSLHDSAFuzzFixture signs the seed objects and checks that each one verifies, so that the seeds reach the signature checks.
func newSLHDSAFuzzFixture() (*slhdsaFuzzFixture, error) {
	_, rootKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		return nil, err
	}
	_, signerKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128f)
	if err != nil {
		return nil, err
	}
	var x slhdsaFuzzFixture
	if x.root, err = slhdsaFuzzCert("Fuzz SLH-DSA Root", rootKey.Public(), nil, rootKey, true); err != nil {
		return nil, err
	}
	if x.signer, err = slhdsaFuzzCert("Fuzz SLH-DSA Signer", signerKey.Public(), x.root, rootKey, false); err != nil {
		return nil, err
	}
	// The new root keeps the name of the old one, as in RFC 4210 §4.4.
	if x.newWithNew, err = slhdsaFuzzCert("Fuzz SLH-DSA Root", signerKey.Public(), nil, signerKey, true); err != nil {
		return nil, err
	}
	if x.newWithOld, err = slhdsaFuzzCert("Fuzz SLH-DSA Root", signerKey.Public(), x.root, rootKey, true); err != nil {
		return nil, err
	}
	if x.oldWithNew, err = slhdsaFuzzCert("Fuzz SLH-DSA Root", rootKey.Public(), x.newWithNew, signerKey, true); err != nil {
		return nil, err
	}
	if err := slhdsasig.CheckSignatureFrom(x.signer, x.root); err != nil {
		return nil, fmt.Errorf("end entity certificate: %w", err)
	}

	if x.csr, err = slhdsaFuzzCSR(rootKey); err != nil {
		return nil, err
	}
	if x.pop, err = slhdsaFuzzPOP(signerKey); err != nil {
		return nil, err
	}
	if x.rootProtected, err = slhdsaFuzzProtected(rootKey, x.root, pkicmp.VerifyOptions{TrustedCert: x.root}); err != nil {
		return nil, err
	}
	// The chain in extraCerts carries the root, because an SLH-DSA link is
	// followed only to an issuer among the candidates.
	pool := x509.NewCertPool()
	pool.AddCert(x.root)
	if x.signerProtected, err = slhdsaFuzzProtected(signerKey, x.signer, pkicmp.VerifyOptions{TrustPool: pool}, x.root); err != nil {
		return nil, err
	}

	update := &pkicmp.RootCAKeyUpdate{NewWithNew: x.newWithNew, NewWithOld: x.newWithOld, OldWithNew: x.oldWithNew}
	if err := update.Verify(x.root); err != nil {
		return nil, fmt.Errorf("root CA key update: %w", err)
	}
	item, err := pkicmp.NewRootCAKeyUpdateInfo(update)
	if err != nil {
		return nil, err
	}
	x.rootUpdate = item.InfoValue
	return &x, nil
}

// slhdsaFuzzCert issues a certificate named name for pub, signed by the SLH-DSA
// key signer under parent or self-signed when parent is nil.
func slhdsaFuzzCert(name string, pub crypto.PublicKey, parent *x509.Certificate, signer slhdsa.PrivateKey, isCA bool) (*x509.Certificate, error) {
	spki, err := pkicmp.MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	// The identifier depends only on the key, so a link certificate shares it with the root of its key.
	ski := sha256.Sum256(spki)
	// A long fuzzing run must not outlive the seeds.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski[:20],
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent = tmpl
	}
	oid, _ := pkicmp.SLHDSAAlgorithmOID(signer.ID)
	der, err := kemcert.CreateSLHDSACertificate(tmpl, parent, spki, oid, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// slhdsaFuzzCSR returns a PKCS #10 request that key signs for itself.
func slhdsaFuzzCSR(key slhdsa.PrivateKey) ([]byte, error) {
	spki, err := pkicmp.MarshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	oid, _ := pkicmp.SLHDSAAlgorithmOID(key.ID)
	der, err := kemcert.CreateCertificateRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "Fuzz SLH-DSA Request"}}, spki, oid, key)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := pkicmp.CheckCertificateRequestSignature(csr); err != nil {
		return nil, fmt.Errorf("PKCS #10 request: %w", err)
	}
	return der, nil
}

// slhdsaFuzzPOP returns an ir that requests a certificate for key and proves possession of it by signature.
func slhdsaFuzzPOP(key slhdsa.PrivateKey) ([]byte, error) {
	spki, err := pkicmp.MarshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	req := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertTemplate: pkicmp.CertTemplate{
		PublicKey: spki,
		Subject:   pkicmp.NewDirectoryName(pkix.Name{CommonName: "Fuzz SLH-DSA Device"}),
	}}}
	if err := req.GeneratePOP(key); err != nil {
		return nil, err
	}
	der, err := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{req}), pkicmp.MessageOptions{}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := verifySLHDSAFuzzPOP(der); err != nil {
		return nil, fmt.Errorf("proof of possession: %w", err)
	}
	return der, nil
}

// verifySLHDSAFuzzPOP parses an ir and verifies the proof of possession of its first request.
func verifySLHDSAFuzzPOP(der []byte) error {
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return err
	}
	reqs, err := msg.Body.CertReqMessages()
	if err != nil {
		return err
	}
	if reqs == nil || len(*reqs) == 0 {
		return errors.New("no certificate request")
	}
	return pkicmp.VerifyPOP(&(*reqs)[0])
}

// slhdsaFuzzProtected returns a genm that key protects for cert, with chain in
// extraCerts, after checking that it verifies with opts.
func slhdsaFuzzProtected(key slhdsa.PrivateKey, cert *x509.Certificate, opts pkicmp.VerifyOptions, chain ...*x509.Certificate) ([]byte, error) {
	creds, err := pkicmp.NewSignatureCredentials(key, cert, chain...)
	if err != nil {
		return nil, err
	}
	msg := pkicmp.NewPKIMessage(
		pkicmp.NewGenMBody(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}),
		pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject)},
	)
	if err := creds.Protect(msg); err != nil {
		return nil, err
	}
	der, err := msg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	parsed, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return nil, err
	}
	opts.ExtraCerts, opts.SenderKID = parsed.ExtraCerts, parsed.Header.SenderKID
	if _, err := parsed.Verify(opts); err != nil {
		return nil, fmt.Errorf("protection by %s: %w", cert.Subject.CommonName, err)
	}
	return der, nil
}

// slhdsaGoldenMessage reads and parses an OpenSSL request from testdata.
func slhdsaGoldenMessage(tb testing.TB, name string) ([]byte, *pkicmp.PKIMessage) {
	tb.Helper()
	der, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- fixed test data file
	if err != nil {
		tb.Fatal(err)
	}
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		tb.Fatal(err)
	}
	return der, msg
}

// slhdsaGoldenIR returns the OpenSSL ir whose proof of possession is signed with SLH-DSA-SHA2-128s.
func slhdsaGoldenIR(tb testing.TB) ([]byte, *pkicmp.CertReqMsg) {
	tb.Helper()
	der, msg := slhdsaGoldenMessage(tb, "ir_slhdsa_golden.der")
	reqs, err := msg.Body.CertReqMessages()
	if err != nil {
		tb.Fatal(err)
	}
	if reqs == nil || len(*reqs) == 0 {
		tb.Fatal("the golden ir has no certificate request")
	}
	return der, &(*reqs)[0]
}

// slhdsaGoldenCSR returns the OpenSSL PKCS #10 request signed with SLH-DSA-SHAKE-128s.
func slhdsaGoldenCSR(tb testing.TB) *x509.CertificateRequest {
	tb.Helper()
	_, msg := slhdsaGoldenMessage(tb, "p10cr_slhdsa_golden.der")
	csr, err := msg.Body.P10CR()
	if err != nil {
		tb.Fatal(err)
	}
	return csr
}

// FuzzSLHDSAPublicKey drives SLH-DSA SubjectPublicKeyInfo parsing.
// ParsePublicKey and the parser behind certificate signature checks must agree
// on every input, and an accepted key must encode back to the same bytes.
func FuzzSLHDSAPublicKey(f *testing.F) {
	// A public key is two random n-byte values, so every parameter set gets a seed without generating a key.
	for _, id := range []slhdsa.ID{
		slhdsa.SHA2_128s, slhdsa.SHA2_128f, slhdsa.SHA2_192s, slhdsa.SHA2_192f, slhdsa.SHA2_256s, slhdsa.SHA2_256f,
		slhdsa.SHAKE_128s, slhdsa.SHAKE_128f, slhdsa.SHAKE_192s, slhdsa.SHAKE_192f, slhdsa.SHAKE_256s, slhdsa.SHAKE_256f,
	} {
		raw := make([]byte, id.Scheme().PublicKeySize())
		if _, err := rand.Read(raw); err != nil {
			f.Fatal(err)
		}
		pub := slhdsa.PublicKey{ID: id}
		if err := pub.UnmarshalBinary(raw); err != nil {
			f.Fatal(err)
		}
		spki, err := pkicmp.MarshalPublicKey(pub)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(spki)
	}
	_, ir := slhdsaGoldenIR(f)
	f.Add(ir.CertReq.CertTemplate.PublicKey)
	f.Add(slhdsaGoldenCSR(f).RawSubjectPublicKeyInfo)

	f.Fuzz(func(t *testing.T, data []byte) {
		pub, err := pkicmp.ParsePublicKey(data)
		key, isSLHDSA, keyErr := slhdsasig.PublicKey(data)
		parsed, ok := pub.(slhdsa.PublicKey)
		switch {
		case !isSLHDSA:
			if ok {
				t.Fatal("ParsePublicKey returned an SLH-DSA key for a key that is not SLH-DSA")
			}
		case keyErr != nil:
			if err == nil {
				t.Fatalf("ParsePublicKey accepted a malformed SLH-DSA key as %T", pub)
			}
		case err != nil || !ok:
			t.Fatalf("ParsePublicKey refused an SLH-DSA key that slhdsasig.PublicKey accepted: %v", err)
		case !parsed.Equal(key):
			t.Fatal("the two parsers read different SLH-DSA keys")
		default:
			encoded, err := pkicmp.MarshalPublicKey(parsed)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatalf("an accepted SLH-DSA key does not encode back to its input: %v", err)
			}
		}
	})
}

// FuzzSLHDSACertificateRequest drives PKCS #10 request parsing and the SLH-DSA
// self-signature check, which a CA runs on a p10cr before anything identifies its sender.
func FuzzSLHDSACertificateRequest(f *testing.F) {
	f.Add(slhdsaFuzzSeeds(f).csr)
	f.Add(slhdsaGoldenCSR(f).Raw)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = slhdsasig.SignatureID(data)
		csr, err := x509.ParseCertificateRequest(data)
		if err != nil {
			return
		}
		_, _ = pkicmp.ParsePublicKey(csr.RawSubjectPublicKeyInfo)
		_ = pkicmp.CheckCertificateRequestSignature(csr)
	})
}

// FuzzSLHDSACertificateSignature drives the SLH-DSA certificate signature check
// that chain building and root CA key updates use, with both the certificate
// and its claimed issuer chosen by the peer.
func FuzzSLHDSACertificateSignature(f *testing.F) {
	x := slhdsaFuzzSeeds(f)
	f.Add(x.root.Raw, x.root.Raw)
	f.Add(x.signer.Raw, x.root.Raw)
	f.Add(x.newWithNew.Raw, x.newWithNew.Raw)
	f.Add(x.oldWithNew.Raw, x.newWithNew.Raw)

	f.Fuzz(func(t *testing.T, certDER, parentDER []byte) {
		_, _, _ = slhdsasig.SignatureID(certDER)
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return
		}
		_, _ = pkicmp.NewCertStatus(cert, 0)
		parent, err := x509.ParseCertificate(parentDER)
		if err != nil {
			return
		}
		_ = slhdsasig.CheckSignatureFrom(cert, parent)
	})
}

// FuzzSLHDSAProofOfPossession drives signature proof of possession for SLH-DSA
// keys, whose key, algorithm and signature all come from the request.
func FuzzSLHDSAProofOfPossession(f *testing.F) {
	f.Add(slhdsaFuzzSeeds(f).pop)
	golden, _ := slhdsaGoldenIR(f)
	f.Add(golden)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := pkicmp.ParsePKIMessage(data)
		if err != nil {
			return
		}
		reqs, err := msg.Body.CertReqMessages()
		if err != nil || reqs == nil {
			return
		}
		for i := range *reqs {
			_ = pkicmp.VerifyPOP(&(*reqs)[i])
			// These options reach the poposkInput checks too.
			_ = pkicmp.VerifyPOPWithOptions(&(*reqs)[i], pkicmp.POPOptions{
				SharedSecret:             fuzzSecret,
				Sender:                   &msg.Header.Sender,
				AllowPoposkInputVariants: true,
			})
		}
	})
}

// FuzzSLHDSAProtection drives SLH-DSA message protection with a pre-trusted
// certificate and through a chain in extraCerts to a trust anchor.
func FuzzSLHDSAProtection(f *testing.F) {
	x := slhdsaFuzzSeeds(f)
	f.Add(x.rootProtected, x.root.Raw)
	f.Add(x.signerProtected, x.root.Raw)
	f.Add(x.signerProtected, x.signer.Raw)

	f.Fuzz(func(t *testing.T, data, anchorDER []byte) {
		msg, err := pkicmp.ParsePKIMessage(data)
		if err != nil {
			return
		}
		anchor, err := x509.ParseCertificate(anchorDER)
		if err != nil {
			return
		}
		pool := x509.NewCertPool()
		pool.AddCert(anchor)
		_, _ = msg.Verify(pkicmp.VerifyOptions{
			TrustPool:  pool,
			ExtraCerts: msg.ExtraCerts,
			SenderKID:  msg.Header.SenderKID,
		})
		_, _ = msg.Verify(pkicmp.VerifyOptions{TrustedCert: anchor})
	})
}

// FuzzSLHDSARootCAKeyUpdate drives RootCAKeyUpdateContent parsing and the
// check of its SLH-DSA link certificates against the old root.
func FuzzSLHDSARootCAKeyUpdate(f *testing.F) {
	x := slhdsaFuzzSeeds(f)
	f.Add(x.rootUpdate, x.root.Raw)

	f.Fuzz(func(t *testing.T, value, oldRootDER []byte) {
		update, err := pkicmp.ParseRootCAKeyUpdateInfo(pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeRootCAKeyUpdate, InfoValue: value})
		if err != nil || update == nil {
			return
		}
		_ = update.Verify(nil)
		if oldRoot, err := x509.ParseCertificate(oldRootDER); err == nil {
			_ = update.Verify(oldRoot)
		}
	})
}
