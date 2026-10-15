package pkicmp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func TestPopDecBodiesRoundTrip(t *testing.T) {
	sha256Alg := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	challenges := pkicmp.POPODecKeyChallContent{{
		OWF:           sha256Alg,
		Witness:       []byte{1, 2, 3},
		EncryptedRand: []byte{0x30, 0x03, 0x02, 0x01, 0x07},
	}}
	msg := pkicmp.NewPKIMessage(pkicmp.NewPopDecCBody(&challenges), pkicmp.MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	assert.Equal(t, pkicmp.BodyTypePopDecC, parsed.Body.Type)
	assert.Equal(t, "popdecc", parsed.Body.Type.String())
	// encryptedRand needs pvno 3 (RFC 9810 §5.2.8.3.3).
	assert.Equal(t, pkicmp.PVNO3, parsed.Header.PVNO)
	got, err := parsed.Body.PopDecC()
	require.NoError(t, err)
	require.Len(t, *got, 1)
	assert.Equal(t, challenges[0].Witness, (*got)[0].Witness)
	assert.Equal(t, challenges[0].EncryptedRand, (*got)[0].EncryptedRand)
	assert.True(t, (*got)[0].OWF.Algorithm.Equal(sha256Alg.Algorithm))

	answers := pkicmp.POPODecKeyRespContent{big.NewInt(0), new(big.Int).Lsh(big.NewInt(1), 200)}
	msg = pkicmp.NewPKIMessage(pkicmp.NewPopDecRBody(&answers), pkicmp.MessageOptions{})
	der, err = msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err = pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	assert.Equal(t, "popdecr", parsed.Body.Type.String())
	gotAnswers, err := parsed.Body.PopDecR()
	require.NoError(t, err)
	require.Len(t, *gotAnswers, 2)
	for i := range answers {
		assert.Equal(t, 0, answers[i].Cmp((*gotAnswers)[i]))
	}
	_, err = parsed.Body.PopDecC()
	assert.Error(t, err)
}

func TestRandRoundTrip(t *testing.T) {
	sender := pkicmp.NewDirectoryName(pkix.Name{CommonName: "CMP server"})
	r := &pkicmp.Rand{Int: big.NewInt(123456789), Sender: sender}
	der, err := r.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParseRand(der)
	require.NoError(t, err)
	assert.Equal(t, 0, r.Int.Cmp(parsed.Int))
	again, err := parsed.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, der, again, "the sender survives the round trip")

	_, err = pkicmp.ParseRand(append(der, 0))
	assert.Error(t, err)
}

func TestChallengeWitness(t *testing.T) {
	// The witness hashes the DER INTEGER, tag and length included: 02 02 00 80 for 128.
	want := sha256.Sum256([]byte{0x02, 0x02, 0x00, 0x80})
	assert.Equal(t, want[:], pkicmp.ChallengeWitness(crypto.SHA256, big.NewInt(128)))
}

func TestEncryptedCertificateAccessors(t *testing.T) {
	envelope := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	rep := pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
		CertReqID:        0,
		Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
		CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.NewEncryptedCertificate(envelope)},
	}}}
	msg := pkicmp.NewPKIMessage(pkicmp.NewIPBody(&rep), pkicmp.MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	// encryptedCert carries EnvelopedData, which needs pvno 3 (RFC 9810 §5.2.2).
	assert.Equal(t, pkicmp.PVNO3, parsed.Header.PVNO)
	ip, err := parsed.Body.IP()
	require.NoError(t, err)
	ckp := ip.Response[0].CertifiedKeyPair
	assert.Nil(t, ckp.CertOrEncCert.Certificate)
	assert.Equal(t, envelope, ckp.CertOrEncCert.EncryptedCertificate())

	plain := pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: []byte{0x30, 0x00}}}
	assert.Nil(t, plain.EncryptedCertificate())
	assert.Nil(t, plain.EncryptedValueCertificate())
	assert.Nil(t, ckp.CertOrEncCert.EncryptedValueCertificate())
}

// An EncryptedValue is CMP version 2 syntax, so it leaves the message at pvno 2.
func TestEncryptedValueCertificateAccessors(t *testing.T) {
	value := []byte{0x30, 0x04, 0x03, 0x02, 0x00, 0x01}
	rep := pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
		Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
		CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.NewEncryptedValueCertificate(value)},
	}}}
	der, err := pkicmp.NewPKIMessage(pkicmp.NewIPBody(&rep), pkicmp.MessageOptions{}).MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)
	assert.Equal(t, pkicmp.PVNO2, parsed.Header.PVNO)
	ip, err := parsed.Body.IP()
	require.NoError(t, err)
	got := ip.Response[0].CertifiedKeyPair.CertOrEncCert
	assert.Equal(t, value, got.EncryptedValueCertificate())
	assert.Nil(t, got.EncryptedCertificate())
	assert.Nil(t, got.Certificate)
}

func TestSubsequentMessagePOP(t *testing.T) {
	encrCert, challengeResp := pkicmp.SubsequentMessageEncrCert, pkicmp.SubsequentMessageChallengeResp
	for _, tc := range []struct {
		name string
		pop  func(*int64) *pkicmp.CertReqMsg
		want int64
	}{
		{"keyEncipherment encrCert", func(v *int64) *pkicmp.CertReqMsg { return &pkicmp.CertReqMsg{Popo: pkicmp.NewKeyEnciphermentPOP(v)} }, encrCert},
		{"keyAgreement challengeResp", func(v *int64) *pkicmp.CertReqMsg { return &pkicmp.CertReqMsg{Popo: pkicmp.NewKeyAgreementPOP(v)} }, challengeResp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			req := tc.pop(&want)
			req.CertReq.CertTemplate.PublicKey = []byte{0x30, 0x00}
			msgs := pkicmp.CertReqMessages{*req}
			der, err := pkicmp.NewPKIMessage(pkicmp.NewCRBody(&msgs), pkicmp.MessageOptions{}).MarshalBinary()
			require.NoError(t, err)
			parsed, err := pkicmp.ParsePKIMessage(der)
			require.NoError(t, err)
			cr, err := parsed.Body.CR()
			require.NoError(t, err)
			got, ok := (*cr)[0].Popo.SubsequentMessage()
			require.True(t, ok)
			assert.Equal(t, want, got)
		})
	}
	signature := &pkicmp.CertReqMsg{Popo: pkicmp.NewRAVerifiedPOP()}
	_, ok := signature.Popo.SubsequentMessage()
	assert.False(t, ok)
}

func TestParseMarshalPublicKey(t *testing.T) {
	kem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	kem1024, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, pub := range []crypto.PublicKey{kem768.EncapsulationKey(), kem1024.EncapsulationKey(), &ec.PublicKey} {
		der, err := pkicmp.MarshalPublicKey(pub)
		require.NoError(t, err)
		parsed, err := pkicmp.ParsePublicKey(der)
		require.NoError(t, err)
		assert.True(t, pkicmp.PublicKeysEqual(parsed, pub), "%T", pub)
		assert.Equal(t, pkicmp.IsKEMKey(pub), pkicmp.IsKEMKey(parsed))
	}
	assert.True(t, pkicmp.IsKEMKey(kem768.EncapsulationKey()))
	assert.False(t, pkicmp.IsKEMKey(&ec.PublicKey))

	// RFC 9935 §4: SEQUENCE { SEQUENCE { id-alg-ml-kem-768 }, BIT STRING }.
	der, err := pkicmp.MarshalPublicKey(kem768.EncapsulationKey())
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x82, 0x04, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, 0x82, 0x04, 0xa1, 0x00}, der[:22])
	// crypto/x509 does not know the algorithm.
	_, err = x509.ParsePKIXPublicKey(der)
	assert.Error(t, err)

	// ML-KEM-512 is refused.
	kem512 := append([]byte(nil), der...)
	kem512[16] = 0x01
	_, err = pkicmp.ParsePublicKey(kem512)
	assert.True(t, errors.Is(err, pkicmp.ErrMLKEM512))

	// A key of the wrong length for its parameter set is refused.
	short := append([]byte{0x30, 0x82, 0x04, 0xb1}, der[4:len(der)-1]...)
	short[19], short[20] = 0x04, 0xa0
	_, err = pkicmp.ParsePublicKey(short)
	assert.Error(t, err)
}

func TestChallengeVerifyWitness(t *testing.T) {
	n := big.NewInt(4242)
	ch := pkicmp.Challenge{
		OWF:     &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
		Witness: pkicmp.ChallengeWitness(crypto.SHA384, n),
	}
	require.NoError(t, ch.VerifyWitness(n))
	assert.ErrorIs(t, ch.VerifyWitness(big.NewInt(4243)), pkicmp.ErrWitnessMismatch)

	ch.OWF = &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}
	assert.Error(t, ch.VerifyWitness(n))
	ch.OWF = nil
	assert.Error(t, ch.VerifyWitness(n))
}

func TestChallengeEncryptedRandTagging(t *testing.T) {
	envelope := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	content := pkicmp.POPODecKeyChallContent{{Witness: []byte{0xaa}, EncryptedRand: envelope}}
	der, err := pkicmp.NewPKIMessage(pkicmp.NewPopDecCBody(&content), pkicmp.MessageOptions{}).MarshalBinary()
	require.NoError(t, err)
	// RFC 9810 uses EXPLICIT TAGS: [0] wraps the complete EnvelopedData.
	explicit := []byte{0x30, 0x0c, 0x04, 0x01, 0xaa, 0x04, 0x00, 0xa0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00}
	assert.True(t, bytes.Contains(der, explicit), "encryptedRand is explicitly tagged")

}
