package signer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Tier ceilings follow the scan approval mode (RFC-073 §7): in Off and On
// a scope entry names targets for every tier, in Strict its max_tier is a
// ceiling. The ledger must never be wider than the database and must not
// refuse what the database allows.

const tTenantB = "22222222-2222-4222-8222-222222222222"

func setCeilings(on bool) jobsign.LedgerOp {
	return jobsign.LedgerOp{Op: jobsign.OpSetTierCeilings, TierCeilings: &on}
}

func TestLedgerCeilings_OffCoversEveryTierOnlyInsideEntries(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 0, nil))))
	wantReason(t, signTargets(s, "zap", "app.example.com"), ReasonTierExceedsLedge)

	if kind := mustApply(t, s, change(0, nil, setCeilings(false))); kind != jobsign.ChangeWiden {
		t.Fatalf("turning ceilings off is a %s, want widen", kind)
	}
	if ref := signTargets(s, "zap", "app.example.com"); ref != nil {
		t.Fatalf("ceilings off: an intrusive probe inside an entry was refused: %+v", ref)
	}
	// Still only inside the entries, and exclusions still apply.
	wantReason(t, signTargets(s, "zap", "victim.example.org"), ReasonOutOfLedger)
	mustApply(t, s, change(0, nil, jobsign.LedgerOp{Op: jobsign.OpPutExclusion,
		Exclusion: &jobsign.LedgerExclusion{ID: tExclusion, Type: "domain", Pattern: "prod.example.com"}}))
	wantReason(t, signTargets(s, "zap", "prod.example.com"), ReasonTargetExcluded)

	// Another organization keeps its ceilings.
	mustApply(t, s, jobsign.LedgerChange{TenantID: tTenantB, ChangeID: tChange, Approvals: []jobsign.LedgerApproval{},
		Ops: []jobsign.LedgerOp{putEntry(entry(tEntry2, "domain", "*.example.com", 0, nil))}})
	_, ref := s.Sign(statement(func(m map[string]any) {
		m["tenant_id"] = tTenantB
		m["tool"] = "zap"
		m["targets"] = []string{"app.example.com"}
	}))
	wantReason(t, ref, ReasonTierExceedsLedge)

	// Back on (Strict) narrows without approvals.
	if kind := mustApply(t, s, change(2, nil, setCeilings(true))); kind != jobsign.ChangeNarrow {
		t.Fatalf("turning ceilings on is a %s, want narrow", kind)
	}
	wantReason(t, signTargets(s, "zap", "app.example.com"), ReasonTierExceedsLedge)
	if kind := mustApply(t, s, change(0, nil, setCeilings(true))); kind != jobsign.ChangeNoop {
		t.Fatalf("ceilings already on: %s, want noop", kind)
	}
}

// Turning the ceilings off lets every entry cover intrusive probes: the
// operator's floor for intrusive entries applies, once.
func TestLedgerCeilings_OffNeedsTheIntrusiveFloor(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) { enforcing(c); c.LedgerT2MinApprovals = 1 })
	_, ref := s.Ledger().Apply(change(0, nil, setCeilings(false)), tNow)
	wantReason(t, ref, ReasonNotApproved)
	mustApply(t, s, change(0, []string{tAdminB}, setCeilings(false)))
	// Already off: a later widening carrying the same operation needs no
	// intrusive approval.
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil)), setCeilings(false)))
}

// A sync can turn the ceilings back on, never off.
func TestLedgerCeilings_SyncNarrowsOnly(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	e := *entry(tEntry, "domain", "*.example.com", 1, nil)
	mustApply(t, s, change(0, nil, putEntry(&e)))

	res, ref := s.Ledger().Sync(jobsign.LedgerSnapshot{TenantID: tTenant, Entries: []jobsign.LedgerEntry{e},
		Exclusions: []jobsign.LedgerExclusion{}, TierCeilingsOff: true}, tNow)
	if ref != nil || res.Narrowed != 0 || res.Diverged != 1 {
		t.Fatalf("a snapshot with ceilings off widened or was not counted: %+v %+v", res, ref)
	}
	wantReason(t, signTargets(s, "zap", "app.example.com"), ReasonTierExceedsLedge)

	mustApply(t, s, change(0, nil, setCeilings(false)))
	res, ref = s.Ledger().Sync(jobsign.LedgerSnapshot{TenantID: tTenant, Entries: []jobsign.LedgerEntry{e},
		Exclusions: []jobsign.LedgerExclusion{}}, tNow)
	if ref != nil || res.Narrowed != 1 || res.Diverged != 0 {
		t.Fatalf("a Strict snapshot did not narrow the ceilings back on: %+v %+v", res, ref)
	}
	wantReason(t, signTargets(s, "zap", "app.example.com"), ReasonTierExceedsLedge)
}

// The state survives a restart (replayed from the log) and an export and
// import.
func TestLedgerCeilings_ReplayExportImport(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	s := newService(t, dir, key, enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 0, nil)), setCeilings(false)))
	_ = s.Close()

	s = newService(t, dir, key, enforcing)
	if ref := signTargets(s, "zap", "app.example.com"); ref != nil {
		t.Fatalf("ceilings off lost on restart: %+v", ref)
	}
	_ = s.Close()

	f, err := os.Open(filepath.Join(dir, "ledger.log"))
	if err != nil {
		t.Fatal(err)
	}
	exp, _, err := ReadLedger(f, tNow)
	_ = f.Close()
	if err != nil || len(exp.Tenants) != 1 || !exp.Tenants[0].TierCeilingsOff {
		t.Fatalf("export lost the ceilings: %+v %v", exp, err)
	}
	raw, _ := json.Marshal(exp)
	dir2 := t.TempDir()
	if _, err := ImportLedger(dir2, raw, false, tNow); err != nil {
		t.Fatal(err)
	}
	s2 := newService(t, dir2, key, enforcing)
	if ref := signTargets(s2, "zap", "app.example.com"); ref != nil {
		t.Fatalf("ceilings off lost on import: %+v", ref)
	}
}

func TestLedgerCeilings_MalformedOperations(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	bad := []jobsign.LedgerOp{
		{Op: jobsign.OpSetTierCeilings},
		{Op: jobsign.OpSetTierCeilings, TierCeilings: ptr(false), ID: tEntry},
		{Op: jobsign.OpPutEntry, Entry: entry(tEntry, "domain", "*.example.com", 1, nil), TierCeilings: ptr(false)},
		{Op: jobsign.OpRemoveEntry, ID: tEntry, TierCeilings: ptr(true)},
	}
	for i, op := range bad {
		if _, ref := s.Ledger().Apply(change(0, nil, op), tNow.Add(time.Duration(i))); ref == nil || ref.reason != ReasonLedgerMalformed {
			t.Fatalf("op %d: want malformed, got %+v", i, ref)
		}
	}
}
