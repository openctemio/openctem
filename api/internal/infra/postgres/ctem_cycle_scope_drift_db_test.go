package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// scope_drift_size counts the external-surface assets first seen during the
// cycle (RFC-036 §6.9): not internal types, not assets seen before the cycle,
// not rejected names, not deleted assets and never another tenant's.
func TestCTEMCycleMetrics_ScopeDrift(t *testing.T) {
	raw := openCharterEvalDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, raw)
	other := seedTestTenant(ctx, t, raw)
	start := time.Now().UTC().Add(-10 * 24 * time.Hour)
	end := time.Now().UTC().Add(-1 * time.Hour)

	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1, 'drift cycle', 'closed', $2, $3, $4) RETURNING id`,
		tenant.String(), shared.NewID().String(), start, end).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	asset := func(tid shared.ID, typ string, firstSeen time.Time) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type, first_seen) VALUES ($1, $2, $3, $4, $5)`,
			id, tid.String(), "drift-"+id, typ, firstSeen); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		return id
	}
	in := start.Add(24 * time.Hour)
	asset(tenant, "subdomain", in)
	asset(tenant, "domain", in)
	asset(tenant, "host", in)                         // internal type
	asset(tenant, "subdomain", start.Add(-time.Hour)) // before the cycle
	asset(other, "subdomain", in)                     // another tenant
	rejected := asset(tenant, "subdomain", in)
	deleted := asset(tenant, "ip_address", in)
	if _, err := raw.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'rejected', 0)`,
		rejected, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
		t.Fatal(err)
	}

	cid, _ := shared.IDFromString(cycleID)
	m, err := NewCTEMCycleMetricsRepository(&DB{DB: raw}).Compute(ctx, tenant, cid)
	if err != nil {
		t.Fatal(err)
	}
	if got := m[ctemcycle.MetricScopeDriftSize]; got != 2 {
		t.Fatalf("scope_drift_size = %v, want 2 (the new domain and subdomain)", got)
	}
}
