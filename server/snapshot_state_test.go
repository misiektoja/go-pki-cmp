package server

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestSnapshotPreservesPollingBindingAndExpiry retains pending nonces, credential isolation and original age.
func TestSnapshotPreservesPollingBindingAndExpiry(t *testing.T) {
	original := New(nil)
	credential, transaction := []byte("credential"), []byte("transaction")
	if _, err := original.startIfAbsent(credential, transaction); err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, 16)
	if !original.setPending(credential, transaction, waitingState{reqType: RequestIR, certReqID: 0, implicitConfirm: true, pollRef: "pending-reference", senderNonce: nonce, checkAfter: time.Second, lastPollTime: time.Now()}) {
		t.Fatal("pending transition failed")
	}
	data, err := original.SnapshotTransactions()
	if err != nil {
		t.Fatal(err)
	}
	restored := New(nil)
	if err := restored.RestoreTransactions(data, nil); err != nil {
		t.Fatal(err)
	}
	pending, ok := restored.getPending(credential, transaction)
	if !ok || pending.pollRef != "pending-reference" || !bytes.Equal(pending.senderNonce, nonce) || pending.checkAfter != time.Second || !pending.implicitConfirm || pending.certReqID == nil || *pending.certReqID != 0 {
		t.Fatal("polling state changed")
	}
	if _, ok := restored.getPending([]byte("other"), transaction); ok {
		t.Fatal("another credential reached pending state")
	}
	if err := restored.RestoreTransactions(data, nil); err == nil {
		t.Fatal("nonempty server overwritten")
	}
	var snapshot transactionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	// Older than the default waiting lifetime of 24 hours.
	snapshot.Entries[0].LastActivity = time.Now().Add(-25 * time.Hour)
	expired, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	old := New(nil)
	if err := old.RestoreTransactions(expired, nil); err != nil {
		t.Fatal(err)
	}
	old.CleanupExpired()
	if _, ok := old.getPending(credential, transaction); ok {
		t.Fatal("restore extended transaction lifetime")
	}
}

// TestSnapshotRejectsInvalidStateAtomically prevents corrupt state from partially replacing a fresh server.
func TestSnapshotRejectsInvalidStateAtomically(t *testing.T) {
	source := New(nil)
	for _, id := range []string{"first", "second"} {
		if _, err := source.startIfAbsent([]byte("credential"), []byte(id)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := source.SnapshotTransactions()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []*Server{New(nil, WithMaxTransactions(1)), New(nil, WithMaxTransactionsPerCredential(1))} {
		if err := target.RestoreTransactions(data, nil); err == nil {
			t.Fatal("configured capacity bypassed")
		}
		if target.count.Load() != 0 {
			t.Fatal("failed restore changed live state")
		}
	}
	var snapshot transactionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Entries[1] = snapshot.Entries[0]
	duplicate, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := New(nil)
	if err := target.RestoreTransactions(duplicate, nil); err == nil || target.count.Load() != 0 {
		t.Fatal("duplicate keys accepted or partially restored")
	}
	snapshot.Entries = snapshot.Entries[:1]
	snapshot.Entries[0].State = stateIssued
	incomplete, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.RestoreTransactions(incomplete, nil); err == nil {
		t.Fatal("incomplete issued state accepted")
	}
}
