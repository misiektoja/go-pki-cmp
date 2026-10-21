package server_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// A reused transactionID is answered with transactionIdInUse even when the transaction limits
// are full, as they are for a host that restores one stored transaction into a server limited
// to one.
func TestReusedTransactionIDAtTransactionLimit(t *testing.T) {
	f := newRevocationFixture(t)
	caCerts := pkicmp.InfoTypeAndValue{InfoType: pkicmp.InfoTypeCACerts}
	txnID := []byte("reused-transaction-id")
	limits := []server.Option{server.WithMaxTransactions(1), server.WithMaxTransactionsPerCredential(1)}

	// limited returns a server limited to one transaction and its handler, so a test can snapshot it.
	limited := func(t *testing.T) (*server.Server, *httptest.Server) {
		opts := append([]server.Option{
			server.WithSigner(f.caKey, f.caCert),
			server.WithCertificateLookup(f.backend),
		}, limits...)
		srv := server.NewCAServer(&generalCA{}, server.LightweightPolicy(), opts...)
		require.NoError(t, srv.Err())
		ts := httptest.NewServer(srv)
		t.Cleanup(ts.Close)
		return srv, ts
	}
	assertInUse := func(t *testing.T, resp *pkicmp.PKIMessage) {
		t.Helper()
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		si := statusInfoOf(t, resp)
		assert.Equal(t, pkicmp.StatusRejection, si.Status)
		assert.Equal(t, pkicmp.FailTransactionIdInUse, si.FailInfo, "status text %v", si.StatusString)
	}

	t.Run("SameServer", func(t *testing.T) {
		_, ts := limited(t)
		require.Equal(t, pkicmp.BodyTypeGenP, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)).Body.Type)
		assertInUse(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)))
	})

	t.Run("RestoredServer", func(t *testing.T) {
		first, ts := limited(t)
		require.Equal(t, pkicmp.BodyTypeGenP, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)).Body.Type)
		data, err := first.SnapshotTransactions()
		require.NoError(t, err)

		restored, ts := limited(t)
		require.NoError(t, restored.RestoreTransactions(data, nil))
		assertInUse(t, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)))
	})

	t.Run("NewTransactionStillLimited", func(t *testing.T) {
		_, ts := limited(t)
		require.Equal(t, pkicmp.BodyTypeGenP, postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: txnID}, caCerts)).Body.Type)
		resp := postCMP(t, ts, signedGenM(t, f.ee, pkicmp.MessageOptions{TransactionID: []byte("another-transaction-id")}, caCerts))
		require.Equal(t, pkicmp.BodyTypeError, resp.Body.Type)
		assert.Equal(t, pkicmp.FailSystemUnavail, statusInfoOf(t, resp).FailInfo)
	})
}
