package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The findings plan limit (research 84 M5): a sensor's ingest stores new
// findings only up to the organization's limit; each new finding over it is
// refused on its own (a per-item error), while re-sightings of existing
// findings are still stored. The real entitlement service and plan
// repository decide. Requires DATABASE_URL.
func TestFindingsPlanLimit_DB(t *testing.T) {
	ctx := context.Background()
	sqlDB := openOccDB(t)
	db := &DB{DB: sqlDB}
	tid := seedTestTenant(ctx, t, sqlDB)
	assetID := seedTestAsset(ctx, t, sqlDB, tid)
	plans := NewPlanRepository(db)
	repo := NewFindingRepository(db)
	run := shared.NewID().String()[:8]

	mk := func(t *testing.T, fp string) *vulnerability.Finding {
		t.Helper()
		f, err := vulnerability.NewFinding(tid, assetID, vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityMedium, "limit probe")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint("limit-" + run + "-" + fp)
		return f
	}
	count := func(t *testing.T) int {
		return countPlanRows(t, sqlDB, `SELECT count(*) FROM findings WHERE tenant_id = $1`, tid.String())
	}

	// One finding exists before any limit applies.
	if err := repo.Create(ctx, mk(t, "existing")); err != nil {
		t.Fatal(err)
	}
	repo.SetPlanLimits(entitlement.NewService(plans, nil, nil, nil, nil))

	// Unlimited (the default on every plan): nothing is refused and the
	// usage of findings is not counted.
	if u, err := plans.Usage(ctx, tid, false); err != nil || u[plan.Findings] != 0 {
		t.Fatalf("usage without findings: %v %v", u, err)
	}
	if u, err := plans.Usage(ctx, tid, true); err != nil || u[plan.Findings] != 1 {
		t.Fatalf("usage with findings: %v %v", u, err)
	}

	// Limit 3 with 1 stored: room for 2 new findings.
	if err := plans.SetOverride(ctx, plan.Override{TenantID: tid, Key: plan.Findings, Value: 3, Reason: "test", SetAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plans.DeleteOverride(context.Background(), tid, plan.Findings) })

	batch := []*vulnerability.Finding{mk(t, "existing"), mk(t, "n1"), mk(t, "n2"), mk(t, "n3")}
	res, err := repo.CreateBatchWithResult(ctx, batch)
	if err != nil {
		t.Fatalf("an ingest over the limit must not fail as a whole: %v", err)
	}
	if res.Created != 2 || res.Updated != 1 || res.Skipped != 1 {
		t.Fatalf("created=%d updated=%d skipped=%d, want 2/1/1 (errors %v)", res.Created, res.Updated, res.Skipped, res.Errors)
	}
	if msg := res.Errors[3]; !strings.Contains(msg, "plan limit reached: findings") || len(res.Errors) != 1 {
		t.Fatalf("errors = %v, want one plan-limit error for index 3", res.Errors)
	}
	if !res.WasInserted(1) || !res.WasInserted(2) || res.WasInserted(3) {
		t.Fatalf("inserted = %v, want n1 and n2 only", res.Inserted)
	}
	if n := count(t); n != 3 {
		t.Fatalf("stored findings = %d, want 3", n)
	}

	// At the limit, a re-sighting of every stored finding still passes.
	res, err = repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(t, "existing"), mk(t, "n1"), mk(t, "n2")})
	if err != nil || res.Updated != 3 || res.Skipped != 0 {
		t.Fatalf("re-sightings at the limit: %v %+v", err, res)
	}

	// A manual finding is refused with the limit error, nothing written.
	wantLimit(t, repo.Create(ctx, mk(t, "manual")), plan.Findings)
	if n := count(t); n != 3 {
		t.Fatalf("refused manual finding written: %d rows", n)
	}

	// Unlimited again: new findings pass.
	if err := plans.DeleteOverride(ctx, tid, plan.Findings); err != nil {
		t.Fatal(err)
	}
	if res, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(t, "n3")}); err != nil || res.Created != 1 {
		t.Fatalf("unlimited: %v %+v", err, res)
	}
}
