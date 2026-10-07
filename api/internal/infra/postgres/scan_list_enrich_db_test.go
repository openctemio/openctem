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
	runs := NewPipelineRunRepository(&DB{DB: db})
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
	repo := NewPipelineTemplateRepository(&DB{DB: db})
	tenantA := seedScanTriggerTenant(ctx, t, db)
	tenantB := seedScanTriggerTenant(ctx, t, db)

	seed := func(tenant shared.ID, name string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO pipeline_templates (id, tenant_id, name) VALUES ($1, $2, $3)`,
			id.String(), tenant.String(), name); err != nil {
			t.Fatalf("seed template: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM pipeline_templates WHERE id = $1`, id.String())
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
