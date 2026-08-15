package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestBusinessContextLookupRepo_GetForAssets verifies the real BU / business-
// service criticality SQL against app_test: it must return the MAX criticality
// per asset across multiple memberships, with the source name.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestBusinessContextLookupRepo_GetForAssets(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "bizctx-test", "bizctx-"+tenantID.String()[:8])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	// Asset.
	var assetIDStr string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,$3) RETURNING id`,
		tenantID.String(), "web-01", "domain").Scan(&assetIDStr); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	assetID, _ := shared.IDFromString(assetIDStr)

	// Two business units on the asset: medium + critical → MAX must be critical.
	buMedium := shared.NewID()
	buCritical := shared.NewID()
	mustExec(t, db, `INSERT INTO business_units (id, tenant_id, name, criticality) VALUES ($1,$2,$3,$4)`,
		buMedium.String(), tenantID.String(), "IT", "medium")
	mustExec(t, db, `INSERT INTO business_units (id, tenant_id, name, criticality) VALUES ($1,$2,$3,$4)`,
		buCritical.String(), tenantID.String(), "Payments", "critical")
	mustExec(t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`,
		shared.NewID().String(), tenantID.String(), buMedium.String(), assetID.String())
	mustExec(t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`,
		shared.NewID().String(), tenantID.String(), buCritical.String(), assetID.String())

	// One business service on the asset: high.
	svcHigh := shared.NewID()
	mustExec(t, db, `INSERT INTO business_services (id, tenant_id, name, criticality) VALUES ($1,$2,$3,$4)`,
		svcHigh.String(), tenantID.String(), "Checkout", "high")
	mustExec(t, db, `INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1,$2,$3)`,
		tenantID.String(), svcHigh.String(), assetID.String())

	repo := NewBusinessContextLookupRepo(db)
	got, err := repo.GetForAssets(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		t.Fatalf("GetForAssets: %v", err)
	}
	bctx := got[assetID]
	if bctx.BusinessUnitCriticality != asset.CriticalityCritical {
		t.Fatalf("BU criticality = %q, want critical", bctx.BusinessUnitCriticality)
	}
	if bctx.BusinessUnitName != "Payments" {
		t.Fatalf("BU name = %q, want Payments", bctx.BusinessUnitName)
	}
	if bctx.BusinessServiceCriticality != asset.CriticalityHigh {
		t.Fatalf("service criticality = %q, want high", bctx.BusinessServiceCriticality)
	}
	if bctx.BusinessServiceName != "Checkout" {
		t.Fatalf("service name = %q, want Checkout", bctx.BusinessServiceName)
	}
}

// TestBusinessContextLookupRepo_ControlPlanePropagation verifies the Pass-3
// control-plane SQL: an asset that is the control plane of a CRITICAL asset
// (target of an is_control_plane edge, per the #467 depends_on data model)
// inherits that criticality via ControlPlaneServes*. DB-gated.
func TestBusinessContextLookupRepo_ControlPlanePropagation(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "cp-test", "cp-"+tenantID.String()[:8])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	// served: a CRITICAL business service asset (the SOURCE of the edge).
	var servedStr string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO assets (tenant_id, name, asset_type, criticality) VALUES ($1,$2,$3,$4) RETURNING id`,
		tenantID.String(), "checkout-svc", "service", "critical").Scan(&servedStr); err != nil {
		t.Fatalf("insert served asset: %v", err)
	}
	// controlPlane: a MEDIUM IdP (the TARGET of the edge) — should be raised.
	var cpStr string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO assets (tenant_id, name, asset_type, criticality) VALUES ($1,$2,$3,$4) RETURNING id`,
		tenantID.String(), "idp-01", "identity", "medium").Scan(&cpStr); err != nil {
		t.Fatalf("insert control-plane asset: %v", err)
	}
	served, _ := shared.IDFromString(servedStr)
	cp, _ := shared.IDFromString(cpStr)

	// Edge: served --depends_on--> controlPlane, is_control_plane=true.
	mustExec(t, db, `
		INSERT INTO asset_relationships
			(id, tenant_id, source_asset_id, target_asset_id, relationship_type,
			 confidence, discovery_method, impact_weight, is_control_plane)
		VALUES ($1,$2,$3,$4,'depends_on','medium','manual',5,TRUE)`,
		shared.NewID().String(), tenantID.String(), served.String(), cp.String())

	repo := NewBusinessContextLookupRepo(db)
	got, err := repo.GetForAssets(ctx, tenantID, []shared.ID{cp, served})
	if err != nil {
		t.Fatalf("GetForAssets: %v", err)
	}
	// The control-plane asset inherits the served asset's criticality.
	if c := got[cp].ControlPlaneServesCriticality; c != asset.CriticalityCritical {
		t.Fatalf("control-plane ControlPlaneServesCriticality = %q, want critical", c)
	}
	if got[cp].ControlPlaneServesName != "checkout-svc" {
		t.Errorf("ControlPlaneServesName = %q, want checkout-svc", got[cp].ControlPlaneServesName)
	}
	// The served asset itself is nobody's control plane → no propagation.
	if c := got[served].ControlPlaneServesCriticality; c != "" {
		t.Errorf("served asset should have no control-plane criticality, got %q", c)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
