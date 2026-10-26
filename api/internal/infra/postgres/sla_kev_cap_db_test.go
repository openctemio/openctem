package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sla"
)

// The known exploited deadline cap is persisted per policy: 14 by default
// (also for rows written before the column), 0 (off) kept as 0, the CHECK
// refuses values out of range.
func TestSLAPolicy_KEVCapRoundTrip_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	p, err := sla.NewDefaultPolicy(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetTenantDefault(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if got.KEVCapDays() != sla.DefaultKEVCapDays {
		t.Fatalf("cap = %d, want %d", got.KEVCapDays(), sla.DefaultKEVCapDays)
	}
	if err := got.UpdateKEVCapDays(0); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, err := repo.GetByTenantAndID(ctx, tenant, p.ID())
	if err != nil {
		t.Fatal(err)
	}
	if again.KEVCapDays() != 0 {
		t.Fatalf("cap after update = %d, want 0 (off)", again.KEVCapDays())
	}

	// A row inserted without the column (an older pod) gets 14.
	legacy := seedTestTenant(ctx, t, db)
	if _, err := db.ExecContext(ctx, `INSERT INTO sla_policies (id, tenant_id, name, is_default, critical_days, high_days, medium_days, low_days, info_days)
		VALUES ($1, $2, 'legacy', TRUE, 2, 15, 30, 60, 0)`, shared.NewID().String(), legacy.String()); err != nil {
		t.Fatal(err)
	}
	lp, err := repo.GetTenantDefault(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if lp.KEVCapDays() != sla.DefaultKEVCapDays {
		t.Fatalf("legacy row cap = %d, want %d", lp.KEVCapDays(), sla.DefaultKEVCapDays)
	}

	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET kev_cap_days = 366 WHERE tenant_id = $1`, legacy.String()); err == nil {
		t.Fatal("kev_cap_days = 366 accepted, want the CHECK to refuse it")
	}
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET kev_cap_days = -1 WHERE tenant_id = $1`, legacy.String()); err == nil {
		t.Fatal("kev_cap_days = -1 accepted, want the CHECK to refuse it")
	}
}
