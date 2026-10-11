package pkicmp_test

import (
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

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

var (
	oidUID             = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// newCertWithSubject issues a self-signed certificate carrying the given subject RDNs.
func newCertWithSubject(t *testing.T, rdns pkix.RDNSequence) *x509.Certificate {
	t.Helper()

	rawSubject, err := asn1.Marshal(rdns)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   rawSubject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// EJBCA names its CA with UID and domainComponent attributes, which pkix.Name
// parses into Names only. Dropping them would send a truncated recipient.
func TestNewDirectoryNameKeepsAttributesWithoutTypedFields(t *testing.T) {
	subject := pkix.RDNSequence{
		{{Type: oidDomainComponent, Value: "com"}},
		{{Type: oidDomainComponent, Value: "example"}},
		{{Type: oidUID, Value: "c-0123456789abcdef"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "ManagementCA"}},
	}
	cert := newCertWithSubject(t, subject)

	name := pkicmp.NewDirectoryName(cert.Subject)

	assert.Equal(t, cert.Subject.String(), name.DirectoryName.String(),
		"the encoded name must carry every attribute the certificate subject shows")

	var types []string
	for _, rdn := range name.DirectoryName {
		for _, atv := range rdn {
			types = append(types, atv.Type.String())
		}
	}
	assert.Equal(t, []string{
		oidDomainComponent.String(),
		oidDomainComponent.String(),
		oidUID.String(),
		"2.5.4.3",
	}, types, "attribute order must match the certificate")
}

// ExtraNames is an explicit encoding instruction, so Names must be ignored to
// avoid emitting an attribute twice.
func TestNewDirectoryNamePrefersExtraNames(t *testing.T) {
	name := pkix.Name{
		CommonName: "explicit",
		Names:      []pkix.AttributeTypeAndValue{{Type: oidUID, Value: "from-names"}},
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidUID, Value: "from-extra"}},
	}

	encoded := pkicmp.NewDirectoryName(name)

	assert.Equal(t, name.String(), encoded.DirectoryName.String())
	count := 0
	for _, rdn := range encoded.DirectoryName {
		for _, atv := range rdn {
			if atv.Type.Equal(oidUID) {
				count++
				assert.Equal(t, "from-extra", atv.Value)
			}
		}
	}
	assert.Equal(t, 1, count, "ExtraNames must not be duplicated from Names")
}

// A name built from typed fields alone must encode exactly as before.
func TestNewDirectoryNameWithOnlyTypedFieldsIsUnchanged(t *testing.T) {
	name := pkix.Name{CommonName: "plain", Organization: []string{"Example"}}

	assert.Equal(t, name.ToRDNSequence(), pkicmp.NewDirectoryName(name).DirectoryName)
}
