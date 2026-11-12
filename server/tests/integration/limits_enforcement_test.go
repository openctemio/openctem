package integration

// Limits enforced at the insert, end to end against a real Postgres
// (docs/architecture/limits.md): an organization over a limit
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
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestLimitsEnforcedEndToEnd(t *testing.T) {
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

	lims := postgres.NewLimitsRepository(db)
	ent := entitlement.NewService(lims, nil, logger.NewNop())
	tenants := postgres.NewTenantRepository(db)
	assets := postgres.NewAssetRepository(db)

	// Two members before any limit is set: unlimited.
	for _, u := range users[:2] {
		m, _ := tenant.NewMembership(u, tid, tenant.RoleMember, nil)
		if err := tenants.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	tenants.SetLimits(ent)
	assets.SetLimits(ent)

	// One seat and one asset: already over on seats.
	for _, k := range []limits.Key{limits.Seats, limits.Assets} {
		if err := lims.SetLimit(ctx, limits.Limit{TenantID: tid, Key: k, Value: 1, Origin: limits.OriginOperator, Reason: "test", SetAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	before := testutil.ToFloat64(metrics.LimitRefusalsTotal.WithLabelValues(string(limits.Seats)))
	m, _ := tenant.NewMembership(users[2], tid, tenant.RoleViewer, nil)
	err := tenants.CreateMembership(ctx, m)
	var lim *limits.ErrLimitReached
	if !errors.As(err, &lim) || lim.Limit != 1 || lim.Used != 2 {
		t.Fatalf("third member over a 1-seat limit: %v", err)
	}
	if got := handler.LimitMessage(lim); got != "The limit is 1 seats; 2 are in use. Remove some, or ask your administrator for more." {
		t.Fatalf("message: %q", got)
	}
	if testutil.ToFloat64(metrics.LimitRefusalsTotal.WithLabelValues(string(limits.Seats))) != before+1 {
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
	if _, _, _, err := assets.UpsertBatch(ctx, []*asset.Asset{a2, a3}); !errors.As(err, &lim) || lim.Key != limits.Assets {
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
