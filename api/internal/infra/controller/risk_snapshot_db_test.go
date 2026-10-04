package controller

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The daily risk snapshot counts active exposures per tenant. The exposures
// of a soft-deleted asset are history, not active work (owner decision O3):
// they are not counted, and another tenant's count is its own.
func TestRiskSnapshot_ActiveExposuresSkipDeletedAssets_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping risk snapshot DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	tenant, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'risk snapshot test', $2)`, id.String(), "rs-"+id.String())
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		}
	})
	asset := func(tenantID shared.ID, deleted bool) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, deleted_at)
		      VALUES ($1, $2, $3, 'host', CASE WHEN $4 THEN NOW() END)`,
			id.String(), tenantID.String(), "rs-"+id.String(), deleted)
		exec(`INSERT INTO exposure_events (tenant_id, asset_id, event_type, severity, state, title, fingerprint, source)
		      VALUES ($1, $2, 'port_open', 'high', 'active', 'open port', $3, 'test')`,
			tenantID.String(), id.String(), "rs-"+id.String())
		return id
	}
	asset(tenant, false)
	asset(tenant, true)
	asset(other, false)

	if _, err := NewRiskSnapshotController(db, logger.NewNop()).Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for id, want := range map[shared.ID]int{tenant: 1, other: 1} {
		var got int
		if err := db.QueryRowContext(ctx,
			`SELECT exposures_active FROM risk_snapshots WHERE tenant_id = $1 AND snapshot_date = CURRENT_DATE`,
			id.String()).Scan(&got); err != nil {
			t.Fatalf("read snapshot: %v", err)
		}
		if got != want {
			t.Errorf("tenant %s exposures_active = %d, want %d", id, got, want)
		}
	}
}
