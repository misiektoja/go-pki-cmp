package client_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// firstCertReqMsg returns the CertReqMsg of an ir.
func firstCertReqMsg(t *testing.T, req *pkicmp.PKIMessage) *pkicmp.CertReqMsg {
	t.Helper()
	msgs, err := req.Body.IR()
	require.NoError(t, err)
	require.NotNil(t, msgs)
	require.Len(t, *msgs, 1)
	return &(*msgs)[0]
}

// sendIRWith enrolls the end entity key of a test PKI with the request options against a CA that
// answers under the certReqId of the request. It returns the ir the CA received.
func sendIRWith(t *testing.T, opts ...client.RequestOption) (*pkicmp.PKIMessage, error) {
	t.Helper()
	pki := newTestPKI()
	var received *pkicmp.PKIMessage
	server := mockCMPServer(pki, func(req *pkicmp.PKIMessage) *pkicmp.PKIBody {
		received = req
		return pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			CAPubs: []pkicmp.CMPCertificate{{Raw: pki.caCert.Raw}},
			Response: []pkicmp.CertResponse{{
				CertReqID: firstCertReqMsg(t, req).CertReq.CertReqID,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: pki.eeCert.Raw}},
				},
			}},
		})
	}, []byte("secret"))
	defer server.Close()

	key, err := pki.ee.PrivateKey()
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	_, err = client.NewClient(server.URL).SendIR(context.Background(), key, creds, opts...)
	return received, err
}

// RFC 4211 §5: the client chooses the certReqId and the CA repeats it in its answer.
func TestWithCertReqID(t *testing.T) {
	req, err := sendIRWith(t, client.WithCertReqID(1023))
	require.NoError(t, err)
	assert.Equal(t, int64(1023), firstCertReqMsg(t, req).CertReq.CertReqID)

	req, err = sendIRWith(t)
	require.NoError(t, err)
	assert.Equal(t, int64(0), firstCertReqMsg(t, req).CertReq.CertReqID, "the default stays 0")

	received, err := sendIRWith(t, client.WithCertReqID(-1))
	require.ErrorContains(t, err, "certReqId -1 is negative")
	assert.Nil(t, received, "nothing is sent for a negative certReqId")
}

// WithGeneralInfo items follow the certProfile in the header of the first message.
func TestWithGeneralInfo(t *testing.T) {
	profileID, err := asn1.Marshal(int64(7))
	require.NoError(t, err)
	item := pkicmp.InfoTypeAndValue{InfoType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 36878, 3, 3, 1, 1}, InfoValue: profileID}
	req, err := sendIRWith(t, client.WithCertProfile("device"), client.WithGeneralInfo(item))
	require.NoError(t, err)
	require.Len(t, req.Header.GeneralInfo, 2)
	assert.Equal(t, "device", req.Header.CertProfile())
	assert.True(t, req.Header.GeneralInfo[1].InfoType.Equal(item.InfoType))
	assert.Equal(t, item.InfoValue, req.Header.GeneralInfo[1].InfoValue)

	req, err = sendIRWith(t)
	require.NoError(t, err)
	assert.Empty(t, req.Header.GeneralInfo)
}

// WithPOPHash changes the digest of the signature proof of possession. SHA-1 verifies only on
// request, as RFC 9481 §7.1 deprecates it, and keys without a digest refuse the option.
func TestWithPOPHash(t *testing.T) {
	ecdsaWithSHA384 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	ecdsaWithSHA1 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

	req, err := sendIRWith(t, client.WithPOPHash(crypto.SHA384))
	require.NoError(t, err)
	reqMsg := firstCertReqMsg(t, req)
	assert.True(t, reqMsg.Popo.Signature.Algorithm.Algorithm.Equal(ecdsaWithSHA384), "popo algorithm %v", reqMsg.Popo.Signature.Algorithm.Algorithm)
	assert.NoError(t, pkicmp.VerifyPOP(reqMsg))

	req, err = sendIRWith(t, client.WithPOPHash(crypto.SHA1))
	require.NoError(t, err)
	reqMsg = firstCertReqMsg(t, req)
	assert.True(t, reqMsg.Popo.Signature.Algorithm.Algorithm.Equal(ecdsaWithSHA1), "popo algorithm %v", reqMsg.Popo.Signature.Algorithm.Algorithm)
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, pkicmp.VerifyPOP(reqMsg), &ve)
	assert.Equal(t, pkicmp.ReasonUnsupportedAlgorithm, ve.Reason)
	assert.NoError(t, pkicmp.VerifyPOPWithOptions(reqMsg, pkicmp.POPOptions{AllowSHA1Signatures: true}))

	_, err = sendIRWith(t, client.WithPOPHash(crypto.SHA224))
	require.ErrorContains(t, err, "unsupported signature digest")

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	_, err = client.NewClient("http://127.0.0.1:1").SendIR(context.Background(), edKey, creds, client.WithPOPHash(crypto.SHA256))
	require.ErrorContains(t, err, "take no digest")
}
