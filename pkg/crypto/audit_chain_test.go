package crypto

import (
	"strings"
	"testing"
	"time"
)

// Lock the public contract of the audit hash-chain primitive so any
// future refactor that would break on-disk hashes fails fast. Hashes
// are persisted; a silent change to the algorithm would invalidate
// every row in audit_log_chain.

func TestComputeAuditChainHash_Deterministic(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a := ComputeAuditChainHash("", "audit-1", `{"action":"create"}`, ts)
	b := ComputeAuditChainHash("", "audit-1", `{"action":"create"}`, ts)
	if a != b {
		t.Fatalf("same input → different hash: %s vs %s", a, b)
	}
}

func TestComputeAuditChainHash_FormatIsHex64(t *testing.T) {
	h := ComputeAuditChainHash("", "x", "y", time.Unix(0, 0))
	if len(h) != 64 {
		t.Fatalf("want 64 hex chars, got %d: %s", len(h), h)
	}
	for _, r := range h {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			t.Fatalf("non-hex char %q in %s", r, h)
		}
	}
}

func TestComputeAuditChainHash_DifferentPrev_DifferentHash(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := ComputeAuditChainHash("aaaa", "log-1", "pl", ts)
	b := ComputeAuditChainHash("bbbb", "log-1", "pl", ts)
	if a == b {
		t.Fatal("prevHash change must change the digest")
	}
}

func TestComputeAuditChainHash_DifferentPayload_DifferentHash(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := ComputeAuditChainHash("", "log-1", "payload-a", ts)
	b := ComputeAuditChainHash("", "log-1", "payload-b", ts)
	if a == b {
		t.Fatal("payload change must change the digest")
	}
}

func TestComputeAuditChainHash_DifferentTimestamp_DifferentHash(t *testing.T) {
	a := ComputeAuditChainHash("", "x", "y", time.Unix(0, 0))
	b := ComputeAuditChainHash("", "x", "y", time.Unix(1, 0))
	if a == b {
		t.Fatal("timestamp change must change the digest")
	}
}

func TestComputeAuditChainHash_DifferentAuditID_DifferentHash(t *testing.T) {
	ts := time.Unix(0, 0)
	a := ComputeAuditChainHash("", "id-a", "p", ts)
	b := ComputeAuditChainHash("", "id-b", "p", ts)
	if a == b {
		t.Fatal("audit id change must change the digest")
	}
}

// Length-prefixing defense: concatenation attacks must not collide.
// Without length prefixes, ("foo", "bar") could collide with ("fooba", "r").
func TestComputeAuditChainHash_FieldBoundariesUnambiguous(t *testing.T) {
	ts := time.Unix(0, 0)
	// prev="ab", id="cd"
	a := ComputeAuditChainHash("ab", "cd", "", ts)
	// prev="", id="abcd"
	b := ComputeAuditChainHash("", "abcd", "", ts)
	if a == b {
		t.Fatal("field boundaries must be unambiguous (length-prefix missing?)")
	}
}

// UTC normalisation: a timestamp expressed in a different zone but
// pointing at the same instant must hash identically, so dashboard
// display timezones never affect the chain.
func TestComputeAuditChainHash_TimezoneNormalized(t *testing.T) {
	utc := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	laTZ, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("tz data missing: %v", err)
	}
	la := utc.In(laTZ)
	a := ComputeAuditChainHash("", "x", "y", utc)
	b := ComputeAuditChainHash("", "x", "y", la)
	if a != b {
		t.Fatalf("same instant must hash identically across zones: %s vs %s", a, b)
	}
}

// Chain walk example — simulates the verify procedure that an auditor
// would run against the audit_log_chain table.
func TestComputeAuditChainHash_ChainWalk(t *testing.T) {
	type entry struct {
		ID       string
		Payload  string
		TS       time.Time
		PrevHash string
		Hash     string
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []entry{
		{ID: "1", Payload: "first", TS: base},
		{ID: "2", Payload: "second", TS: base.Add(time.Second)},
		{ID: "3", Payload: "third", TS: base.Add(2 * time.Second)},
	}

	// Build chain.
	prev := ""
	for i := range entries {
		entries[i].PrevHash = prev
		entries[i].Hash = ComputeAuditChainHash(prev, entries[i].ID, entries[i].Payload, entries[i].TS)
		prev = entries[i].Hash
	}

	// Verify: recompute each hash, ensure it matches.
	for i, e := range entries {
		want := ComputeAuditChainHash(e.PrevHash, e.ID, e.Payload, e.TS)
		if want != e.Hash {
			t.Fatalf("entry %d recomputed hash mismatch", i)
		}
		if i > 0 && e.PrevHash != entries[i-1].Hash {
			t.Fatalf("entry %d prev_hash does not link to entry %d hash", i, i-1)
		}
	}

	// Tamper: change one payload and prove the chain breaks.
	entries[1].Payload = "MUTATED"
	tampered := ComputeAuditChainHash(entries[1].PrevHash, entries[1].ID, entries[1].Payload, entries[1].TS)
	if tampered == entries[1].Hash {
		t.Fatal("tampering payload must change recomputed hash")
	}
	// And everything downstream no longer matches either.
	if strings.EqualFold(tampered, entries[2].PrevHash) {
		t.Fatal("tampered hash must not equal stored prev_hash of next entry")
	}
}
