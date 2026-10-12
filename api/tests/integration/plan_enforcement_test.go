package integration

// Plan limits enforced at the insert, end to end against a real Postgres
// (docs/architecture/plans-and-limits.md): a Free organization over a limit
// keeps everything it has, new additions are refused with the limit error,
// and the refusal is counted.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestPlanLimitsEnforcedEndToEnd(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	s := uuid.NewString()[:8]
	tid := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "enf-"+s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
	users := make([]shared.ID, 3)
	for i := range users {
		users[i] = shared.NewID()
		if _, err := db.Exec(`INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'U', 'active')`,
			users[i].String(), "enf-"+s+"-"+string(rune('a'+i))+"@example.test"); err != nil {
			t.Fatal(err)
		}
		id := users[i]
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String()) })
	}

	plans := postgres.NewPlanRepository(db)
	ent := entitlement.NewService(plans, nil, nil, nil, logger.NewNop())
	tenants := postgres.NewTenantRepository(db)
	assets := postgres.NewAssetRepository(db)

	// Two members before the organization is on a plan: unlimited.
	for _, u := range users[:2] {
		m, _ := tenant.NewMembership(u, tid, tenant.RoleMember, nil)
		if err := tenants.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	tenants.SetPlanLimits(ent)
	assets.SetPlanLimits(ent)

	// Free with one seat and one asset (overrides): already over on seats.
	if err := plans.SetTenantPlan(ctx, tid, plan.Free, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, k := range []plan.Key{plan.Seats, plan.Assets} {
		if err := plans.SetOverride(ctx, plan.Override{TenantID: tid, Key: k, Value: 1, Reason: "test", SetAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	before := testutil.ToFloat64(metrics.PlanLimitRefusalsTotal.WithLabelValues(string(plan.Seats)))
	m, _ := tenant.NewMembership(users[2], tid, tenant.RoleViewer, nil)
	err := tenants.CreateMembership(ctx, m)
	var lim *plan.ErrLimitReached
	if !errors.As(err, &lim) || lim.Limit != 1 || lim.Used != 2 {
		t.Fatalf("third member over a 1-seat limit: %v", err)
	}
	if got := handler.PlanLimitMessage(lim); got != "Your plan allows 1 seats; you use 2. Remove some, or ask your administrator for more." {
		t.Fatalf("message: %q", got)
	}
	if testutil.ToFloat64(metrics.PlanLimitRefusalsTotal.WithLabelValues(string(plan.Seats))) != before+1 {
		t.Fatal("refusal not counted")
	}
	sum, err := ent.Effective(ctx, tid)
	if err != nil || !sum.OverLimit {
		t.Fatalf("over limit must be flagged: %+v %v", sum, err)
	}
	var members int
	_ = db.QueryRow(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND status = 'active'`, tid.String()).Scan(&members)
	if members != 2 {
		t.Fatalf("nobody may be removed: %d members", members)
	}

	// Ingest: the first new asset fits, a batch with two more is refused
	// whole, re-ingesting the existing one still works.
	a1, _ := asset.NewAssetWithTenant(tid, "a1-"+s+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
	if _, _, _, err := assets.UpsertBatch(ctx, []*asset.Asset{a1}); err != nil {
		t.Fatalf("first asset: %v", err)
	}
	a2, _ := asset.NewAssetWithTenant(tid, "a2-"+s+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
	a3, _ := asset.NewAssetWithTenant(tid, "a3-"+s+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
	if _, _, _, err := assets.UpsertBatch(ctx, []*asset.Asset{a2, a3}); !errors.As(err, &lim) || lim.Key != plan.Assets {
		t.Fatalf("batch over the asset limit must be refused: %v", err)
	}
	again, _ := asset.NewAssetWithTenant(tid, "a1-"+s+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
	if _, _, _, err := assets.UpsertBatch(ctx, []*asset.Asset{again}); err != nil {
		t.Fatalf("re-ingesting an existing asset at the limit: %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1`, tid.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("assets: %d, want 1", n)
	}
	_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id = $1`, tid.String())
}
