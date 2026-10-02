package ctemcycle

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestScopeChangeEvent_Validate(t *testing.T) {
	good := ScopeChangeEvent{
		CycleID: shared.NewID(), TenantID: shared.NewID(),
		AssetID: shared.NewID(), Kind: ScopeChangeAdded,
		At: time.Now(),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good event rejected: %v", err)
	}

	// missing cycle id
	bad := good
	bad.CycleID = shared.ID{}
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing cycle id should fail: %v", err)
	}

	// invalid kind
	bad = good
	bad.Kind = "exploded"
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad kind should fail: %v", err)
	}
}

func TestRollupChanges_Counts(t *testing.T) {
	cid := shared.NewID()
	tid := shared.NewID()
	a := shared.NewID()
	b := shared.NewID()
	c := shared.NewID()

	events := []ScopeChangeEvent{
		{CycleID: cid, TenantID: tid, AssetID: a, Kind: ScopeChangeAdded, Reason: "cloud-discover"},
		{CycleID: cid, TenantID: tid, AssetID: b, Kind: ScopeChangeAdded, Reason: "cloud-discover"},
		{CycleID: cid, TenantID: tid, AssetID: c, Kind: ScopeChangeRemoved, Reason: "decom"},
	}
	r := RollupChanges(cid, events)
	if len(r.AddedAssets) != 2 || len(r.RemovedAssets) != 1 {
		t.Fatalf("counts wrong: +%d -%d", len(r.AddedAssets), len(r.RemovedAssets))
	}
	if r.AddedByReason["cloud-discover"] != 2 {
		t.Fatalf("reason tally wrong: %v", r.AddedByReason)
	}
	if r.RemovedByReason["decom"] != 1 {
		t.Fatalf("remove reason wrong: %v", r.RemovedByReason)
	}
}

func TestRollupChanges_IgnoresOtherCycles(t *testing.T) {
	cid := shared.NewID()
	other := shared.NewID()
	events := []ScopeChangeEvent{
		{CycleID: other, TenantID: shared.NewID(), AssetID: shared.NewID(), Kind: ScopeChangeAdded},
	}
	r := RollupChanges(cid, events)
	if !r.IsEmpty() {
		t.Fatal("events for other cycle must be ignored")
	}
}

func TestRollupChanges_SkipsMalformed(t *testing.T) {
	cid := shared.NewID()
	events := []ScopeChangeEvent{
		{CycleID: cid, AssetID: shared.NewID(), Kind: ScopeChangeAdded}, // missing tenant
		{CycleID: cid, TenantID: shared.NewID(), AssetID: shared.NewID(), Kind: "garbage"},
		{CycleID: cid, TenantID: shared.NewID(), AssetID: shared.NewID(), Kind: ScopeChangeAdded},
	}
	r := RollupChanges(cid, events)
	if len(r.AddedAssets) != 1 {
		t.Fatalf("expected 1 valid, got %d", len(r.AddedAssets))
	}
}

func TestRollupChanges_SizeAndEmpty(t *testing.T) {
	r := RollupChanges(shared.NewID(), nil)
	if !r.IsEmpty() {
		t.Fatal("no events → must be empty")
	}
	if r.Size() != 0 {
		t.Fatalf("size = %d", r.Size())
	}
}
