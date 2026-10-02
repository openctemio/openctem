package handler

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/testdb"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

func openHandlerTestDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return raw, ctx
}

// TestCTEMCycleHandler_ActivateSkipsNonUUIDServices: a charter that still
// holds a service name next to real service IDs used to fail the ::uuid[]
// cast and freeze nothing. Activation must snapshot from the valid IDs.
func TestCTEMCycleHandler_ActivateSkipsNonUUIDServices(t *testing.T) {
	raw, ctx := openHandlerTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, raw)

	seedAsset := func(name string) string {
		id := shared.NewID().String()
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'host')`,
			id, tenantID, name); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		return id
	}
	inService := seedAsset("in-service")
	_ = seedAsset("not-in-service")

	var serviceID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO business_services (tenant_id, name) VALUES ($1,'Payments') RETURNING id`,
		tenantID).Scan(&serviceID); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1,$2,$3)`,
		tenantID, serviceID, inService); err != nil {
		t.Fatalf("link asset: %v", err)
	}

	activate := func(charter string) (string, int) {
		t.Helper()
		var cycleID string
		if err := raw.QueryRowContext(ctx,
			`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, charter)
			 VALUES ($1,'c','planning',$2,$3::jsonb) RETURNING id`,
			tenantID, shared.NewID().String(), charter).Scan(&cycleID); err != nil {
			t.Fatalf("seed cycle: %v", err)
		}
		h := NewCTEMCycleHandler(raw, nil, logger.NewNop())
		w := httptest.NewRecorder()
		h.Activate(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/activate", tenantID, cycleID))
		if w.Code != http.StatusOK {
			t.Fatalf("activate status = %d; body=%s", w.Code, w.Body.String())
		}
		var n int
		if err := raw.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM ctem_cycle_scope_snapshots WHERE cycle_id = $1`, cycleID).Scan(&n); err != nil {
			t.Fatalf("count snapshot: %v", err)
		}
		return cycleID, n
	}

	// Mixed: the name is skipped, the ID scopes the snapshot to its one asset.
	cycleID, n := activate(fmt.Sprintf(`{"in_scope_services":["Payments API","%s"]}`, serviceID))
	if n != 1 {
		t.Fatalf("mixed charter snapshot rows = %d, want 1", n)
	}
	var target sql.NullString
	if err := raw.QueryRowContext(ctx,
		`SELECT scope_target_id::text FROM ctem_cycle_scope_snapshots WHERE cycle_id = $1 AND asset_id = $2`,
		cycleID, inService).Scan(&target); err != nil {
		t.Fatalf("read snapshot row: %v", err)
	}
	if target.String != serviceID {
		t.Fatalf("scope_target_id = %q, want %s", target.String, serviceID)
	}

	// Names only: no valid ID remains, so the all-assets fallback applies.
	if _, n := activate(`{"in_scope_services":["Payments API","Checkout"]}`); n != 2 {
		t.Fatalf("names-only charter snapshot rows = %d, want 2 (all tenant assets)", n)
	}
}
