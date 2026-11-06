package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The sub-status catalog round-trips, lists in lifecycle order, refuses a
// duplicate key, and never answers for another tenant.
func TestLifecycleSubStatusRepository_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewLifecycleSubStatusRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	actor := seedGroupsUser(ctx, t, db, "lc.sub")
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(tenantID shared.ID, key, status, reason string, order int) *findinglifecycle.SubStatus {
		t.Helper()
		s, err := findinglifecycle.NewSubStatus(tenantID, findinglifecycle.SubStatusInput{
			Key: key, Name: "Name " + key, Color: "teal", CanonicalStatus: status, ClosureReason: reason,
			SortOrder: order, Labels: map[string]string{"vi": "Nhãn " + key},
		}, &actor, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	bounty := mk(tenant, "bounty_paid", "resolved", "fixed", 0)
	review := mk(tenant, "in_review", "in_progress", "", 2)
	dev := mk(tenant, "in_dev", "in_progress", "", 1)
	triage := mk(tenant, "needs_info", "new", "", 5)
	foreign := mk(other, "in_dev", "in_progress", "", 0) // the same key in another tenant is fine

	dup, _ := findinglifecycle.NewSubStatus(tenant, findinglifecycle.SubStatusInput{Key: "in_dev", Name: "x", Color: "red", CanonicalStatus: "confirmed"}, nil, now)
	if err := repo.Create(ctx, dup); !errors.Is(err, findinglifecycle.ErrSubStatusKeyTaken) {
		t.Errorf("duplicate key: err = %v", err)
	}

	got, err := repo.GetByID(ctx, tenant, bounty.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.ClosureReason() != "fixed" || got.Labels()["vi"] != "Nhãn bounty_paid" || got.CreatedBy() == nil || *got.CreatedBy() != actor {
		t.Errorf("round trip: %q %v %v", got.ClosureReason(), got.Labels(), got.CreatedBy())
	}
	if _, err := repo.GetByID(ctx, tenant, foreign.ID()); !errors.Is(err, findinglifecycle.ErrSubStatusNotFound) {
		t.Errorf("another tenant's sub-status: err = %v", err)
	}

	list, err := repo.List(ctx, tenant, findinglifecycle.SubStatusFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []shared.ID{triage.ID(), dev.ID(), review.ID(), bounty.ID()}
	if len(list) != len(want) {
		t.Fatalf("list = %d entries, want %d", len(list), len(want))
	}
	for i := range want {
		if list[i].ID() != want[i] {
			t.Errorf("list[%d] = %s, want %s (lifecycle order, then sort order)", i, list[i].Key(), want[i])
		}
	}

	name := "Code review"
	if err := review.Update(findinglifecycle.SubStatusUpdate{Name: &name}, &actor, now); err != nil {
		t.Fatal(err)
	}
	review.Archive(&actor, now)
	if err := repo.Update(ctx, review); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.CountActive(ctx, tenant, findinglifecycle.ObjectKindFinding); n != 3 {
		t.Errorf("active = %d, want 3", n)
	}
	active, _ := repo.List(ctx, tenant, findinglifecycle.SubStatusFilter{})
	all, _ := repo.List(ctx, tenant, findinglifecycle.SubStatusFilter{IncludeArchived: true})
	if len(active) != 3 || len(all) != 4 {
		t.Errorf("active %d, all %d", len(active), len(all))
	}
	again, _ := repo.GetByID(ctx, tenant, review.ID())
	if again.Name() != name || !again.IsArchived() {
		t.Errorf("after update: %s archived=%v", again.Name(), again.IsArchived())
	}

	// An update addressed to another tenant changes nothing.
	hijack := findinglifecycle.ReconstituteSubStatus(findinglifecycle.SubStatusData{
		ID: foreign.ID(), TenantID: tenant, Kind: findinglifecycle.ObjectKindFinding, CanonicalStatus: foreign.CanonicalStatus(),
		Key: foreign.Key(), Name: "hijacked", Color: "red",
	})
	if err := repo.Update(ctx, hijack); !errors.Is(err, findinglifecycle.ErrSubStatusNotFound) {
		t.Errorf("cross-tenant update: err = %v", err)
	}
	f, _ := repo.GetByID(ctx, other, foreign.ID())
	if f.Name() == "hijacked" {
		t.Error("cross-tenant update changed the row")
	}

	// Findings that carry a sub-status are counted per tenant.
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	if _, err := db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, sub_status_id)
		VALUES ($1, $2, 'sast', 't', 'm', 'low', 'lc-count-' || gen_random_uuid(), 'in_progress', $3)`,
		tenant.String(), asset.String(), dev.ID().String()); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.CountFindings(ctx, tenant, dev.ID()); err != nil || n != 1 {
		t.Errorf("findings of in_dev = %d (%v), want 1", n, err)
	}
	if n, _ := repo.CountFindings(ctx, other, dev.ID()); n != 0 {
		t.Errorf("another tenant counts %d findings of this sub-status", n)
	}
}
