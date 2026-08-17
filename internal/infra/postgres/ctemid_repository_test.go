package postgres

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/ctemid"
)

// TestDedupeCTEMID guards the within-batch dedup that keeps UpsertBatch's single
// multi-row INSERT ... ON CONFLICT (ctem_id) DO UPDATE from proposing the same
// conflict key twice (Postgres: "ON CONFLICT DO UPDATE command cannot affect row
// a second time"). A duplicated feed entry must NOT be able to abort the sync.
func TestDedupeCTEMID(t *testing.T) {
	mk := func(id, title string) *ctemid.CTEMID {
		return ctemid.NewCTEMID(id, ctemid.CategoryOther, title, "", "", "", nil, nil)
	}

	entries := []*ctemid.CTEMID{
		mk("CTEM-1", "first"),
		mk("CTEM-2", "second"),
		mk("CTEM-1", "first-updated"), // duplicate id — last wins
		nil,                           // nil is dropped, not a panic
		mk("CTEM-3", "third"),
	}

	got := dedupeCTEMID(entries)

	if len(got) != 3 {
		t.Fatalf("expected 3 unique entries, got %d", len(got))
	}
	// First-appearance order preserved: CTEM-1, CTEM-2, CTEM-3.
	wantIDs := []string{"CTEM-1", "CTEM-2", "CTEM-3"}
	for i, w := range wantIDs {
		if got[i].CTEMID() != w {
			t.Errorf("position %d: ctem_id = %q, want %q", i, got[i].CTEMID(), w)
		}
	}
	// The duplicate collapsed to the LAST occurrence (upsert = last wins).
	if got[0].Title() != "first-updated" {
		t.Errorf("duplicate ctem_id should keep last title, got %q", got[0].Title())
	}

	// No duplicate conflict key remains — the invariant UpsertBatch relies on.
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e.CTEMID()] {
			t.Fatalf("duplicate ctem_id %q survived dedup", e.CTEMID())
		}
		seen[e.CTEMID()] = true
	}
}
