package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// refusingChecker refuses every addition of one key and records each call.
type refusingChecker struct {
	mu     sync.Mutex
	refuse plan.Key
	calls  []string
	deltas map[plan.Key]int
}

func (c *refusingChecker) Check(_ context.Context, _ shared.ID, key plan.Key, delta int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, string(key))
	if c.deltas == nil {
		c.deltas = map[plan.Key]int{}
	}
	c.deltas[key] += delta
	if key == c.refuse {
		return &plan.ErrLimitReached{Key: key, Limit: 1, Used: 1}
	}
	return nil
}

func (c *refusingChecker) Headroom(_ context.Context, _ shared.ID, key plan.Key) (int, error) {
	if key == c.refuse {
		return 0, nil
	}
	return plan.Unlimited, nil
}

func (c *refusingChecker) RecordRefusals(plan.Key, int) {}

func countPlanRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func wantLimit(t *testing.T, err error, key plan.Key) {
	t.Helper()
	var lim *plan.ErrLimitReached
	if !errors.As(err, &lim) || lim.Key != key {
		t.Fatalf("want a %s limit refusal, got %v", key, err)
	}
}

// Every insert that counts against a plan limit is refused before it writes,
// as the application role. Requires DATABASE_URL.
func TestPlanLimitsRefuseAtTheInsert(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	suffix := shared.NewID().String()[28:]
	tid := planTestTenant(t, sqlDB, "limits-"+suffix)
	user := planTestUser(t, sqlDB, "limits-"+suffix+"@example.test")

	t.Run("seats: membership and invitation accept", func(t *testing.T) {
		r := NewTenantRepository(db)
		r.SetPlanLimits(&refusingChecker{refuse: plan.Seats})
		m, _ := tenant.NewMembership(user, tid, tenant.RoleViewer, nil)
		wantLimit(t, r.CreateMembership(ctx, m), plan.Seats)
		inv, err := tenant.NewInvitation(tid, "limits-"+suffix+"@example.test", tenant.RoleViewer, user, []string{"00000000-0000-0000-0000-000000000004"})
		if err != nil {
			t.Fatal(err)
		}
		wantLimit(t, r.AcceptInvitationTx(ctx, inv, m), plan.Seats)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM tenant_members WHERE tenant_id = $1`, tid.String()); n != 0 {
			t.Fatalf("refused membership written: %d", n)
		}
	})

	t.Run("invites_per_day", func(t *testing.T) {
		r := NewTenantRepository(db)
		r.SetPlanLimits(&refusingChecker{refuse: plan.InvitesPerDay})
		inv, err := tenant.NewInvitation(tid, "inv-"+suffix+"@example.test", tenant.RoleViewer, user, []string{"00000000-0000-0000-0000-000000000004"})
		if err != nil {
			t.Fatal(err)
		}
		wantLimit(t, r.CreateInvitation(ctx, inv), plan.InvitesPerDay)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1`, tid.String()); n != 0 {
			t.Fatalf("refused invitation written: %d", n)
		}
	})

	t.Run("api_keys", func(t *testing.T) {
		r := NewAPIKeyRepository(db)
		r.SetPlanLimits(&refusingChecker{refuse: plan.APIKeys})
		k := apikey.NewAPIKey(shared.NewID(), tid, "k", "hash-"+suffix, "oct_x")
		wantLimit(t, r.Create(ctx, k), plan.APIKeys)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM api_keys WHERE tenant_id = $1`, tid.String()); n != 0 {
			t.Fatalf("refused key written: %d", n)
		}
	})

	t.Run("ci_trusts", func(t *testing.T) {
		r := NewCIRunRepository(db)
		r.SetPlanLimits(&refusingChecker{refuse: plan.CITrusts})
		c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tid, Name: "gh", Provider: cirun.ProviderGitHub, CreatedAt: time.Now()}
		wantLimit(t, r.CreateTrustConfig(ctx, c), plan.CITrusts)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM ci_trust_configs WHERE tenant_id = $1`, tid.String()); n != 0 {
			t.Fatalf("refused trust written: %d", n)
		}
	})

	t.Run("sensors: the organization's own, not platform sensors", func(t *testing.T) {
		chk := &refusingChecker{refuse: plan.Sensors}
		r := NewSensorRepository(db)
		r.SetPlanLimits(chk)
		s, err := sensordom.NewSensor(tid, "s-"+suffix, sensordom.SensorTypeWorker, "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		wantLimit(t, r.Create(ctx, s), plan.Sensors)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM sensors WHERE tenant_id = $1`, tid.String()); n != 0 {
			t.Fatalf("refused sensor written: %d", n)
		}

		// A platform sensor is never one of the organization's sensors.
		before := len(chk.calls)
		ps, _ := sensordom.NewSensor(tid, "ps-"+suffix, sensordom.SensorTypeWorker, "", nil, "")
		ps.IsPlatformSensor = true
		_ = r.Create(ctx, ps)
		_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sensors WHERE id = $1`, ps.ID.String())
		if len(chk.calls) != before {
			t.Fatal("a platform sensor must not count against the sensor limit")
		}

		p := NewSensorPairingRepository(db)
		p.SetPlanLimits(chk)
		_, err = p.Approve(ctx, sensordom.PairingApproval{PairingID: shared.NewID(), TenantID: tid, ApprovedBy: user, Now: time.Now()}, nil)
		wantLimit(t, err, plan.Sensors)
		// A re-pair replaces an existing sensor: no limit check (the
		// unknown request is then simply not found).
		repair := shared.NewID()
		before = len(chk.calls)
		if _, err = p.Approve(ctx, sensordom.PairingApproval{PairingID: shared.NewID(), TenantID: tid, ApprovedBy: user, Now: time.Now()}, &repair); err == nil {
			t.Fatal("unknown request must not be approved")
		}
		if len(chk.calls) != before {
			t.Fatal("a re-pair must not count against the sensor limit")
		}
	})

	t.Run("assets: create and the new rows of an ingest batch", func(t *testing.T) {
		r := NewAssetRepository(db)
		existing, _ := asset.NewAssetWithTenant(tid, "old-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		if err := r.Create(ctx, existing); err != nil {
			t.Fatal(err)
		}

		chk := &refusingChecker{refuse: plan.Assets}
		r.SetPlanLimits(chk)
		a, _ := asset.NewAssetWithTenant(tid, "new-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		wantLimit(t, r.Create(ctx, a), plan.Assets)

		_, _, _, err := r.UpsertBatch(ctx, []*asset.Asset{a})
		wantLimit(t, err, plan.Assets)
		if n := countPlanRows(t, sqlDB, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid.String()); n != 1 {
			t.Fatalf("refused assets written: %d rows", n)
		}

		// Re-ingesting only assets that exist adds nothing: delta 0 passes
		// without a check, even at the limit.
		counting := &refusingChecker{refuse: plan.Assets}
		r.SetPlanLimits(counting)
		again, _ := asset.NewAssetWithTenant(tid, "old-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		if _, _, _, err := r.UpsertBatch(ctx, []*asset.Asset{again}); err != nil {
			t.Fatalf("an update of an existing asset must pass at the limit: %v", err)
		}

		// A mixed batch counts only the new names, once each.
		mixed := &refusingChecker{}
		r.SetPlanLimits(mixed)
		n1, _ := asset.NewAssetWithTenant(tid, "n1-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		n2, _ := asset.NewAssetWithTenant(tid, "n2-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		old2, _ := asset.NewAssetWithTenant(tid, "old-"+suffix+".example.test", asset.AssetTypeDomain, asset.CriticalityMedium)
		if _, _, _, err := r.UpsertBatch(ctx, []*asset.Asset{n1, n2, old2}); err != nil {
			t.Fatal(err)
		}
		if mixed.deltas[plan.Assets] != 2 {
			t.Fatalf("new assets counted: %d, want 2", mixed.deltas[plan.Assets])
		}
		_, _ = sqlDB.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1`, tid.String())
	})
}
