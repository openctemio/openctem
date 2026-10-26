package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The scan list's batch reads are tenant-scoped: another tenant's run or
// private template is never returned, even when its id is asked for.

func TestListByTenantAndIDs_OnlyTheTenantsRuns(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	tenantA, scanA := seedCounterScan(ctx, t, db)
	tenantB, scanB := seedCounterScan(ctx, t, db)
	runA := seedCounterRun(ctx, t, runs, tenantA, scanA)
	runB := seedCounterRun(ctx, t, runs, tenantB, scanB)

	got, err := runs.ListByTenantAndIDs(ctx, tenantA, []shared.ID{runA.ID, runB.ID})
	if err != nil {
		t.Fatalf("ListByTenantAndIDs: %v", err)
	}
	if len(got) != 1 || got[0].ID != runA.ID {
		t.Fatalf("got %d run(s), want only tenant A's run", len(got))
	}
	if none, err := runs.ListByTenantAndIDs(ctx, tenantA, nil); err != nil || len(none) != 0 {
		t.Fatalf("no ids: %v %v", none, err)
	}
}

func TestTemplateNames_OwnAndSystemOnly(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	tenantA := seedScanTriggerTenant(ctx, t, db)
	tenantB := seedScanTriggerTenant(ctx, t, db)

	seed := func(tenant shared.ID, name string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, $3)`,
			id.String(), tenant.String(), name); err != nil {
			t.Fatalf("seed template: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_workflows WHERE id = $1`, id.String())
		})
		return id
	}
	own := seed(tenantA, "External recon")
	other := seed(tenantB, "Other tenant secret workflow")
	system, _ := shared.IDFromString(quickScanTemplate)

	names, err := repo.TemplateNames(ctx, tenantA, []shared.ID{own, other, system})
	if err != nil {
		t.Fatalf("TemplateNames: %v", err)
	}
	if names[own] != "External recon" {
		t.Errorf("own template name = %q", names[own])
	}
	if _, leaked := names[other]; leaked {
		t.Error("another tenant's template name was returned")
	}
	if names[system] == "" {
		t.Error("the system template was not named")
	}
}

func TestRecentByScans_TopNNewestFirstAndTenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	tenantA, scanA := seedCounterScan(ctx, t, db)
	tenantB, scanB := seedCounterScan(ctx, t, db)
	var ids []shared.ID
	for i := 0; i < 4; i++ {
		r := seedCounterRun(ctx, t, runs, tenantA, scanA)
		// Spread the creation times so the order is unambiguous.
		if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET created_at = now() - make_interval(mins => $2) WHERE id = $1`,
			r.ID.String(), 10-i); err != nil {
			t.Fatalf("age run: %v", err)
		}
		ids = append(ids, r.ID)
	}
	seedCounterRun(ctx, t, runs, tenantB, scanB)

	got, err := runs.RecentByScans(ctx, tenantA, []shared.ID{scanA, scanB}, 3)
	if err != nil {
		t.Fatalf("RecentByScans: %v", err)
	}
	if _, leaked := got[scanB]; leaked {
		t.Fatal("another tenant's scan runs were returned")
	}
	a := got[scanA]
	if len(a) != 3 {
		t.Fatalf("got %d runs, want the limit 3", len(a))
	}
	// Newest first: the last seeded run is the newest.
	if a[0].ID != ids[3] || a[1].ID != ids[2] || a[2].ID != ids[1] {
		t.Fatalf("order = %v %v %v, want %v %v %v", a[0].ID, a[1].ID, a[2].ID, ids[3], ids[2], ids[1])
	}
	if a[0].Status == "" || a[0].CreatedAt.IsZero() {
		t.Fatalf("status/created_at not read: %+v", a[0])
	}
	// The other tenant's own scan is readable by that tenant only.
	if gotB, err := runs.RecentByScans(ctx, tenantB, []shared.ID{scanA, scanB}, 10); err != nil || len(gotB[scanB]) != 1 || len(gotB[scanA]) != 0 {
		t.Fatalf("tenant B read: %v %v", gotB, err)
	}
	if none, err := runs.RecentByScans(ctx, tenantA, nil, 10); err != nil || len(none) != 0 {
		t.Fatalf("no ids: %v %v", none, err)
	}
}
