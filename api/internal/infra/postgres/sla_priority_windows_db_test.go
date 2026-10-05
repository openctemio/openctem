package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sla"
)

// The P0..P3 windows a policy sets are persisted and drive the deadline. They
// used to be dropped on write and replaced by hardcoded defaults on read.
func TestSLAPolicy_PriorityWindowsRoundTrip_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	p, err := sla.NewDefaultPolicy(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.UpdatePriorityDays(1, 3, 10, 20); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetTenantDefault(ctx, tenant)
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got.P0Days() != 1 || got.P1Days() != 3 || got.P2Days() != 10 || got.P3Days() != 20 {
		t.Fatalf("priority days = %d/%d/%d/%d, want 1/3/10/20", got.P0Days(), got.P1Days(), got.P2Days(), got.P3Days())
	}
	detected := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d := got.CalculateDeadlineFor("P0", "medium", detected); !d.Equal(detected.Add(24 * time.Hour)) {
		t.Fatalf("P0 medium deadline = %s, want 1 day after detection (not medium_days)", d)
	}

	// Update writes them too.
	if err := got.UpdatePriorityDays(2, 4, 8, 16); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, err := repo.GetByTenantAndID(ctx, tenant, p.ID())
	if err != nil {
		t.Fatal(err)
	}
	if again.P0Days() != 2 || again.P3Days() != 16 {
		t.Fatalf("after update priority days = %d..%d, want 2..16", again.P0Days(), again.P3Days())
	}

	// Another tenant cannot read it.
	other := seedTestTenant(ctx, t, db)
	if _, err := repo.GetByTenantAndID(ctx, other, p.ID()); !errors.Is(err, sla.ErrNotFound) && !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want not found", err)
	}
}

// A row written without priority days (every row before this change, and an
// old pod during a rolling deploy) keeps the platform defaults. The 000142
// column defaults (P0 = 7 days) must no longer apply: reading them would
// lengthen every P0 deadline the moment a policy exists.
func TestSLAPolicy_UnsetPriorityWindowsKeepDefaults_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sla_policies (id, tenant_id, name, is_default, critical_days, high_days, medium_days, low_days, info_days)
		VALUES ($1, $2, 'legacy', TRUE, 2, 15, 30, 60, 90)`, id.String(), tenant.String()); err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}
	var p0 *int
	if err := db.QueryRowContext(ctx, `SELECT p0_days FROM sla_policies WHERE id = $1`, id.String()).Scan(&p0); err != nil {
		t.Fatal(err)
	}
	if p0 != nil {
		t.Fatalf("p0_days column default = %d, want NULL (inherit the platform default)", *p0)
	}

	got, err := repo.GetTenantDefault(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if got.P0Days() != sla.DefaultPriorityDays["P0"] || got.P3Days() != sla.DefaultPriorityDays["P3"] {
		t.Fatalf("legacy row priority days = %d..%d, want defaults %d..%d",
			got.P0Days(), got.P3Days(), sla.DefaultPriorityDays["P0"], sla.DefaultPriorityDays["P3"])
	}
	if !got.EscalationEnabled() {
		t.Fatal("a policy row without escalation_enabled must default to on (notifications keep flowing)")
	}

	// The CHECK constraint refuses an out-of-range window written behind the API.
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET p0_days = 0 WHERE id = $1`, id.String()); err == nil {
		t.Fatal("p0_days = 0 accepted; want the range CHECK to refuse it")
	}
}
