package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A credential's counter goes away with its last transaction, whichever way
// the transaction ends, so the counters do not grow with every credential the
// server has ever seen.
func TestCredentialCountersAreReleased(t *testing.T) {
	tracker := newTransactionTracker(10, 2)
	start := func(cred, txn string) *transactionEntry {
		exists, err := tracker.startIfAbsent([]byte(cred), []byte(txn))
		require.NoError(t, err)
		require.False(t, exists)
		v, ok := tracker.transactions.Load(makeKey([]byte(cred), []byte(txn)))
		require.True(t, ok)
		return v.(*transactionEntry)
	}

	entry := start("a", "1")
	start("a", "2")
	start("b", "1")
	assert.Equal(t, 2, tracker.trackedCredentials())
	assert.Equal(t, 2, tracker.credentialCount(makeCredentialKey([]byte("a"))))

	_, err := tracker.startIfAbsent([]byte("a"), []byte("3"))
	require.EqualError(t, err, "per-credential transaction limit reached")

	exists, err := tracker.startIfAbsent([]byte("a"), []byte("1"))
	require.NoError(t, err)
	require.True(t, exists, "an existing transaction is not counted twice")
	assert.Equal(t, 2, tracker.credentialCount(makeCredentialKey([]byte("a"))))

	require.True(t, tracker.remove([]byte("a"), []byte("1"), entry))
	assert.Equal(t, 1, tracker.credentialCount(makeCredentialKey([]byte("a"))))
	tracker.delete([]byte("a"), []byte("2"))
	assert.Equal(t, 1, tracker.trackedCredentials(), "credential a is forgotten with its last transaction")

	time.Sleep(2 * time.Millisecond)
	tracker.cleanupExpired(time.Millisecond, time.Millisecond)
	assert.Equal(t, 0, tracker.trackedCredentials())
	assert.Equal(t, int64(0), tracker.count.Load())

	start("a", "3")
	assert.Equal(t, 1, tracker.credentialCount(makeCredentialKey([]byte("a"))))
}
