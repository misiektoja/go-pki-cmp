package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// challengeServer answers the first request with the popdecc that challenge
// builds and counts the requests it receives.
func challengeServer(t *testing.T, secret []byte, challenge func(req *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	sender := pkicmp.NewDirectoryName(pkix.Name{CommonName: "challenging CA"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		content := pkicmp.POPODecKeyChallContent{challenge(req, sender)}
		resp := pkicmp.NewPKIMessage(pkicmp.NewPopDecCBody(&content), pkicmp.MessageOptions{
			Sender:        sender,
			TransactionID: req.Header.TransactionID,
			RecipNonce:    req.Header.SenderNonce,
		})
		mc, _ := pkicmp.NewMACCredentials(secret)
		_ = mc.Protect(resp)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

// encryptedRand encrypts a Rand naming sender for pub as a popdecc challenge does.
func encryptedRand(t *testing.T, n *big.Int, sender pkicmp.GeneralName, pub crypto.PublicKey) []byte {
	t.Helper()
	content, err := (&pkicmp.Rand{Int: n, Sender: sender}).MarshalBinary()
	require.NoError(t, err)
	envelope, err := cms.Encrypt(content, pub, cms.RecipientID{Issuer: []byte{0x30, 0x00}, SerialNumber: big.NewInt(0)})
	require.NoError(t, err)
	return envelope
}

// A popdecc that does not prove itself is not answered.
func TestChallengeRefused(t *testing.T) {
	secret := []byte("challenge-refused")
	key, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	sha256 := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	n := big.NewInt(123456789)
	other := pkicmp.NewDirectoryName(pkix.Name{CommonName: "another CA"})

	for _, tc := range []struct {
		name      string
		challenge func(req *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge
		want      string
	}{
		{"wrong witness", func(_ *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge {
			return pkicmp.Challenge{OWF: sha256, Witness: pkicmp.ChallengeWitness(crypto.SHA256, big.NewInt(1)), EncryptedRand: encryptedRand(t, n, sender, key.EncapsulationKey())}
		}, "verify popdecc witness"},
		{"other sender", func(_ *pkicmp.PKIMessage, _ pkicmp.GeneralName) pkicmp.Challenge {
			return pkicmp.Challenge{OWF: sha256, Witness: pkicmp.ChallengeWitness(crypto.SHA256, n), EncryptedRand: encryptedRand(t, n, other, key.EncapsulationKey())}
		}, "names another sender"},
		{"no owf", func(_ *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge {
			return pkicmp.Challenge{Witness: pkicmp.ChallengeWitness(crypto.SHA256, n), EncryptedRand: encryptedRand(t, n, sender, key.EncapsulationKey())}
		}, "verify popdecc witness"},
		{"no encryptedRand", func(_ *pkicmp.PKIMessage, _ pkicmp.GeneralName) pkicmp.Challenge {
			return pkicmp.Challenge{OWF: sha256, Witness: pkicmp.ChallengeWitness(crypto.SHA256, n)}
		}, "no encryptedRand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, calls := challengeServer(t, secret, tc.challenge)
			creds, err := pkicmp.NewMACCredentials(secret)
			require.NoError(t, err)
			_, err = client.NewClient(ts.URL).SendIRWithIndirectPOP(context.Background(), key, client.ChallengeResponse, creds,
				client.WithTemplateSubject(pkix.Name{CommonName: "challenged"}))
			assert.ErrorContains(t, err, tc.want)
			assert.Equal(t, int32(1), calls.Load(), "no popdecr is sent")
		})
	}
}

// A popdecc answers only a request that asked for one.
func TestChallengeNotRequested(t *testing.T) {
	secret := []byte("challenge-not-requested")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	ts, calls := challengeServer(t, secret, func(_ *pkicmp.PKIMessage, sender pkicmp.GeneralName) pkicmp.Challenge {
		return pkicmp.Challenge{Witness: []byte{1}, EncryptedRand: encryptedRand(t, big.NewInt(1), sender, kem.EncapsulationKey())}
	})
	creds, err := pkicmp.NewMACCredentials(secret)
	require.NoError(t, err)
	c := client.NewClient(ts.URL)

	_, err = c.SendIR(context.Background(), ecKey, creds, client.WithTemplateSubject(pkix.Name{CommonName: "signer"}))
	assert.ErrorContains(t, err, "popdecc challenge the request did not ask for")
	_, err = c.SendIRWithIndirectPOP(context.Background(), kem, client.EncryptedCertificate, creds, client.WithTemplateSubject(pkix.Name{CommonName: "encrypted"}))
	assert.ErrorContains(t, err, "popdecc challenge the request did not ask for")
	assert.Equal(t, int32(2), calls.Load())
}

// An encrypted certificate is refused for a request that proved possession by signature.
func TestEncryptedCertificateForSigningKey(t *testing.T) {
	pki := newTestPKI()
	signer, err := pki.ee.PrivateKey()
	require.NoError(t, err)
	envelope, err := cms.Encrypt(pki.eeCert.Raw, signer.Public(), cms.IssuerAndSerial(pki.eeCert))
	require.NoError(t, err)
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
			Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
			CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.NewEncryptedCertificate(envelope)},
		}}})
	}, []byte("secret"))
	defer server.Close()

	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	_, err = client.NewClient(server.URL).SendIR(context.Background(), signer, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	assert.ErrorContains(t, err, "encrypted certificate for a key that signs")
}

// The client decrypts a certificate sent in the EncryptedValue of CMP version 2,
// and refuses one for a request that proved possession by signature.
func TestEncryptedValueCertificate(t *testing.T) {
	pki := newTestPKI()
	ee := &certyaml.Certificate{Subject: "cn=rsa-ee", Issuer: pki.ca, KeyType: certyaml.KeyTypeRSA}
	cert, err := ee.X509Certificate()
	require.NoError(t, err)
	key, err := ee.PrivateKey()
	require.NoError(t, err)
	value, err := cms.NewEncryptedValue(cert.Raw, key.Public().(*rsa.PublicKey))
	require.NoError(t, err)
	reply := func(*pkicmp.PKIMessage) *pkicmp.PKIBody {
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
			Status:           pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
			CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.NewEncryptedValueCertificate(value)},
		}}})
	}
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	subject := client.WithTemplateSubject(pkix.Name{CommonName: "rsa-ee"})

	server := mockCMPServer(pki, reply, []byte("secret"))
	defer server.Close()
	result, err := client.NewClient(server.URL).SendIRWithIndirectPOP(context.Background(), key, client.EncryptedCertificate, creds, subject)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, result.Certificate.Raw)

	signing := mockCMPServer(pki, reply, []byte("secret"))
	defer signing.Close()
	_, err = client.NewClient(signing.URL).SendIR(context.Background(), key, creds, subject)
	assert.ErrorContains(t, err, "encrypted certificate for a key that signs")
}
