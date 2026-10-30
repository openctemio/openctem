package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The connector coverage figures count a host as scanned only once its batch
// settled it as scanned. A dispatched host whose scan was unreachable or
// failed is never scanned and uncovered; another tenant's hosts never count.
func TestScanCoverageStats_DispatchIsNotCoverage_DB(t *testing.T) {
	db, ctx := openRegistryDB(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q[:40], err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'connector coverage', $2)`, id.String(), "cc-"+id.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenant, other := newTenant(), newTenant()
	host := func(tid shared.ID, crit, state string, attempted, succeeded bool) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status) VALUES ($1, $2, $3, 'host', $4, 'active')`,
			id.String(), tid.String(), "h-"+id.String()+".example.com", crit)
		if !attempted {
			return
		}
		exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_attempt_at, last_success_at)
			VALUES ($1, $2, $3, '', $4, now(), CASE WHEN $5 THEN now() END)`,
			tid.String(), id.String(), connectorCapability, state, succeeded)
	}
	host(tenant, "critical", "covered", true, true) // scanned
	host(tenant, "critical", "failed", true, false) // dispatched, unreachable
	host(tenant, "low", "failed", true, false)      // dispatched, failed
	host(tenant, "low", "", false, false)           // never dispatched
	host(other, "critical", "covered", true, true)  // another tenant

	stats, err := NewScanCoverageRepository(&DB{DB: db}).CoverageStats(ctx, tenant, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalScannable != 4 || stats.CoveredInWindow != 1 || stats.NeverScanned != 3 ||
		stats.CriticalNeverScanned != 1 || stats.CriticalUncovered != 1 {
		t.Fatalf("stats = %+v, want total 4, covered 1, never scanned 3, critical never 1, critical uncovered 1", stats)
	}
	if stats.CoveragePercent != 25 {
		t.Fatalf("coverage percent %v, want 25", stats.CoveragePercent)
	}
}
