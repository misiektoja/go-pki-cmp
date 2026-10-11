package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sort"
	"sync/atomic"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

type transactionSnapshot struct {
	Version int
	Signer  []byte
	Entries []savedTransaction
}

type savedTransaction struct {
	Key                 transactionKey
	Credential          credentialKey
	State               txnState
	LastActivity        time.Time
	RequestType         RequestType
	PollRef             string
	SenderNonce         []byte
	LastPollTime        time.Time
	CheckAfter          time.Duration
	Certificate         []byte
	IssueRef            json.RawMessage
	IssuedSenderNonce   []byte
	ClientSenderNonce   []byte
	ProtectionAlgorithm *pkicmp.AlgorithmIdentifier
	// CertReqID is absent from snapshots taken before it was recorded. A
	// transaction restored from one confirms without the certReqId check.
	CertReqID *int64 `json:",omitempty"`
}

// SnapshotTransactions encodes trusted recovery state while the caller excludes concurrent requests and cleanup.
func (s *Server) SnapshotTransactions() ([]byte, error) {
	snapshot := transactionSnapshot{Version: 1, Signer: s.snapshotSigner()}
	var snapshotErr error
	s.transactions.Range(func(key, value any) bool {
		entry := value.(*transactionEntry)
		saved := savedTransaction{
			Key:                 key.(transactionKey),
			Credential:          entry.credentialKey,
			State:               entry.state,
			LastActivity:        entry.lastActivity,
			RequestType:         entry.reqType,
			PollRef:             entry.pollRef,
			SenderNonce:         entry.senderNonce,
			LastPollTime:        entry.lastPollTime,
			CheckAfter:          entry.checkAfter,
			IssuedSenderNonce:   entry.issuedSenderNonce,
			ClientSenderNonce:   entry.clientSenderNonce,
			ProtectionAlgorithm: entry.protectionAlgorithm,
			CertReqID:           entry.certReqID,
		}
		if entry.cert != nil {
			saved.Certificate = entry.cert.Raw
		}
		if entry.issueRef != nil {
			saved.IssueRef, snapshotErr = json.Marshal(entry.issueRef)
			if snapshotErr != nil {
				return false
			}
		}
		if entry.protectionParams != nil && entry.protectionAlgorithm == nil {
			snapshotErr = errors.New("transaction has no serializable protection parameters")
			return false
		}
		snapshot.Entries = append(snapshot.Entries, saved)
		return true
	})
	if snapshotErr != nil {
		return nil, snapshotErr
	}
	sort.Slice(snapshot.Entries, func(i, j int) bool {
		return bytes.Compare(snapshot.Entries[i].Key[:], snapshot.Entries[j].Key[:]) < 0
	})
	data, err := json.Marshal(snapshot)
	if len(data) > 64<<20 {
		return nil, errors.New("transaction snapshot exceeds 64 MiB")
	}
	return data, err
}

// RestoreTransactions loads trusted snapshots into an empty server before it serves requests.
func (s *Server) RestoreTransactions(data []byte, decodeIssueRef func(json.RawMessage) (any, error)) error {
	if s.count.Load() != 0 {
		return errors.New("restore requires an empty transaction tracker")
	}
	if len(data) > 64<<20 {
		return errors.New("transaction snapshot exceeds 64 MiB")
	}
	var snapshot transactionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if snapshot.Version != 1 || !bytes.Equal(snapshot.Signer, s.snapshotSigner()) {
		return errors.New("transaction snapshot version or signer does not match")
	}
	if len(snapshot.Entries) > s.maxTransactions {
		return errors.New("transaction snapshot exceeds capacity")
	}
	next := newTransactionTracker(s.maxTransactions, s.maxTransactionsPerCredential)
	for _, saved := range snapshot.Entries {
		if saved.State < stateActive || saved.State > stateCompleted ||
			saved.LastActivity.IsZero() || saved.LastActivity.After(time.Now().Add(time.Minute)) {
			return errors.New("invalid saved transaction state or timestamp")
		}
		entry := &transactionEntry{
			state:               saved.State,
			credentialKey:       saved.Credential,
			lastActivity:        saved.LastActivity,
			reqType:             saved.RequestType,
			pollRef:             saved.PollRef,
			senderNonce:         saved.SenderNonce,
			lastPollTime:        saved.LastPollTime,
			checkAfter:          saved.CheckAfter,
			issuedSenderNonce:   saved.IssuedSenderNonce,
			clientSenderNonce:   saved.ClientSenderNonce,
			protectionAlgorithm: saved.ProtectionAlgorithm,
			certReqID:           saved.CertReqID,
		}
		if len(saved.Certificate) > 0 {
			cert, err := x509.ParseCertificate(saved.Certificate)
			if err != nil {
				return err
			}
			entry.cert = cert
		}
		// The client's senderNonce is not checked: RFC 4210 makes it optional and
		// only WithStrictProfileValidation requires 128 bits.
		if saved.State == stateIssued && (entry.cert == nil || len(entry.issuedSenderNonce) < 16) {
			return errors.New("issued transaction is incomplete")
		}
		if saved.State == statePending && (saved.PollRef == "" || len(saved.SenderNonce) < 16 || saved.CheckAfter < 0) {
			return errors.New("pending transaction is incomplete")
		}
		if saved.ProtectionAlgorithm != nil {
			entry.protectionParams = pkicmp.WithProtectionAlgorithm(saved.ProtectionAlgorithm)
		}
		if len(saved.IssueRef) > 0 {
			var err error
			if decodeIssueRef != nil {
				entry.issueRef, err = decodeIssueRef(saved.IssueRef)
			} else {
				err = json.Unmarshal(saved.IssueRef, &entry.issueRef)
			}
			if err != nil {
				return err
			}
		}
		if _, duplicate := next.transactions.LoadOrStore(saved.Key, entry); duplicate {
			return errors.New("duplicate saved transaction")
		}
		count, _ := next.credentialCounts.LoadOrStore(saved.Credential, &atomic.Int64{})
		if count.(*atomic.Int64).Add(1) > int64(next.maxTransactionsPerCredential) {
			return errors.New("saved credential exceeds transaction capacity")
		}
		next.count.Add(1)
	}
	s.transactionTracker = next
	return nil
}

// snapshotSigner binds recovered protocol state to the configured response certificate.
func (s *Server) snapshotSigner() []byte {
	if s.cfg.signerCert == nil {
		return nil
	}
	digest := sha256.Sum256(s.cfg.signerCert.Raw)
	return digest[:]
}
