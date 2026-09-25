package actor

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/networkshard/shardlure/internal/store"
)

// All corpus consumers share the same versioned, length-framed stream. A comma
// delimiter makes {"a,b","c"} indistinguishable from {"a","b,c"}.
func newUsernameHash() hash.Hash {
	h := sha256.New()
	_, _ = io.WriteString(h, "shardlure-username-set-v2\x00")
	return h
}

type journalSummaryCodec struct{}

func NewJournalSummaryCodec() store.JournalSummaryCodec { return journalSummaryCodec{} }

type journalFold struct {
	Version                                int    `json:"version"`
	Hash                                   []byte `json:"hash"`
	Users, CN, Service, Crypto, Admin, Ops int
}

func encodeJournalFold(h hash.Hash, f playbookFeatures) ([]byte, error) {
	raw, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(journalFold{Version: 2, Hash: raw, Users: f.users, CN: f.cn, Service: f.svc, Crypto: f.crypto, Admin: f.admin, Ops: f.k8s})
}

func decodeJournalFold(state []byte) (hash.Hash, playbookFeatures, error) {
	invalid := errors.New("journal summary: incompatible fold state")
	var f journalFold
	if len(state) > 1024 || json.Unmarshal(state, &f) != nil || f.Version != 2 || f.Users < 0 {
		return nil, playbookFeatures{}, invalid
	}
	for _, n := range []int{f.CN, f.Service, f.Crypto, f.Admin, f.Ops} {
		if n < 0 || n > f.Users {
			return nil, playbookFeatures{}, invalid
		}
	}
	h := newUsernameHash()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(f.Hash); err != nil {
		return nil, playbookFeatures{}, invalid
	}
	return h, playbookFeatures{users: f.Users, cn: f.CN, svc: f.Service, crypto: f.Crypto, admin: f.Admin, k8s: f.Ops}, nil
}

func (journalSummaryCodec) Start() ([]byte, error) {
	return encodeJournalFold(newUsernameHash(), playbookFeatures{})
}

func (journalSummaryCodec) AddUser(state []byte, username string) ([]byte, error) {
	h, f, err := decodeJournalFold(state)
	if err != nil {
		return nil, err
	}
	addUsernameHash(h, username)
	f.add(username)
	return encodeJournalFold(h, f)
}

func (journalSummaryCodec) Finish(state []byte, c store.JournalCounters) (store.JournalDerived, error) {
	h, f, err := decodeJournalFold(state)
	if err != nil {
		return store.JournalDerived{}, err
	}
	if f.users != c.UniqueUsers || c.Count < f.users || c.Last.Before(c.First) {
		return store.JournalDerived{}, store.ErrJournalSummaryCoverage
	}
	window := c.Last.Sub(c.First).Hours()
	aph := float64(c.Count) / max(window, minWindowHours)
	r := store.JournalDerived{Playbook: f.classify(aph), GeneratedNotes: fmt.Sprintf("%d distinct usernames", f.users), Confidence: ConfidenceJournalBase, ProbeScore: journalProbeScore(c.Count, aph, f.users)}
	if f.users > 0 {
		r.UsernameHash = hex.EncodeToString(h.Sum(nil)[:8])
	}
	if window >= minWindowHours && aph > 100 {
		r.Confidence = ConfidenceJournalHighAPH
	}
	return r, nil
}

func addUsernameHash(h hash.Hash, username string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(username)))
	_, _ = h.Write(size[:])
	_, _ = io.WriteString(h, username)
}
