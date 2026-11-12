package postgres

// SaveReplacement is all or nothing: a failed update of the retired entry
// leaves no replacement behind and the old entry in effect. Links stay
// inside one tenant, one replacement waits at a time, and
// PendingReplacement never answers another tenant's row.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/scope"
)

func TestScopeSaveReplacement_DB(t *testing.T) {
	db := openScopeApproversDB(t)
	ctx := context.Background()
	tenant := newApproverSeed(t, db).tenant
	other := newApproverSeed(t, db).tenant
	targets := NewScopeTargetRepository(&DB{DB: db})
	now := time.Now().UTC()

	old, err := scope.NewEntry(tenant, scope.TargetTypeCIDR, "192.0.2.0/24", "", "", scope.EntryOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := targets.Create(ctx, old); err != nil {
		t.Fatal(err)
	}

	// Atomic: the retired entry's update fails (it belongs to no row of
	// this tenant), so the replacement is not saved either.
	next, _ := scope.NewEntry(tenant, scope.TargetTypeCIDR, "198.51.100.0/24", "", "", scope.EntryOptions{Now: now})
	next.SetSupersedes(old.ID())
	ghost, _ := scope.NewEntry(tenant, scope.TargetTypeCIDR, "203.0.113.0/24", "", "", scope.EntryOptions{Now: now})
	ghost.Supersede(next.ID(), now)
	if err := targets.SaveReplacement(ctx, next, ghost); !errors.Is(err, scope.ErrTargetNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := targets.GetByID(ctx, tenant, next.ID()); !errors.Is(err, scope.ErrTargetNotFound) {
		t.Fatalf("a failed replacement left its new entry: %v", err)
	}
	if got, _ := targets.GetByID(ctx, tenant, old.ID()); got.Status() != scope.StatusActive {
		t.Fatalf("old entry: %s", got.Status())
	}

	// A replacement cannot point at another tenant's entry (the composite
	// foreign key).
	foreign, _ := scope.NewEntry(other, scope.TargetTypeCIDR, "198.51.100.0/25", "", "", scope.EntryOptions{Now: now})
	foreign.SetSupersedes(old.ID())
	if err := targets.SaveReplacement(ctx, foreign); err == nil {
		t.Fatal("a replacement linked to another tenant's entry was saved")
	}

	// Pending: one at a time; the old entry is untouched.
	pending, _ := scope.NewEntry(tenant, scope.TargetTypeCIDR, "198.51.100.0/24", "", "", scope.EntryOptions{ApprovalsRequired: 1, Now: now})
	pending.SetSupersedes(old.ID())
	if err := targets.SaveReplacement(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if id, err := targets.PendingReplacement(ctx, tenant, old.ID()); err != nil || id == nil || *id != pending.ID() {
		t.Fatalf("pending replacement: %v %v", id, err)
	}
	if id, err := targets.PendingReplacement(ctx, other, old.ID()); err != nil || id != nil {
		t.Fatalf("another tenant reads the pending replacement: %v %v", id, err)
	}
	second, _ := scope.NewEntry(tenant, scope.TargetTypeCIDR, "198.51.100.0/26", "", "", scope.EntryOptions{ApprovalsRequired: 1, Now: now})
	second.SetSupersedes(old.ID())
	if err := targets.SaveReplacement(ctx, second); !errors.Is(err, scope.ErrReplacementPending) {
		t.Fatalf("second pending replacement: %v", err)
	}

	// Approved: both rows change together and read back linked.
	if _, err := pending.Approve("00000000-0000-0000-0000-0000000000aa", now); err != nil {
		t.Fatal(err)
	}
	old.Supersede(pending.ID(), now)
	if err := targets.SaveReplacement(ctx, nil, pending, old); err != nil {
		t.Fatal(err)
	}
	gotOld, _ := targets.GetByID(ctx, tenant, old.ID())
	gotNew, _ := targets.GetByID(ctx, tenant, pending.ID())
	if gotOld.Status() != scope.StatusSuperseded || gotOld.SupersededBy() == nil || *gotOld.SupersededBy() != pending.ID() ||
		gotNew.Status() != scope.StatusActive || gotNew.Supersedes() == nil || *gotNew.Supersedes() != old.ID() {
		t.Fatalf("links: old %s %v, new %s %v", gotOld.Status(), gotOld.SupersededBy(), gotNew.Status(), gotNew.Supersedes())
	}
}
