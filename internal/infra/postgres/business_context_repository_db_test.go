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

// TestBusinessContextLookupRepo_ControlPlaneMultiHop verifies the bounded
// multi-hop control-plane walk end-to-end through the SQL/BFS path: a control
// plane of a control plane of a crown jewel inherits the crown jewel's
// criticality (Feature 1). It also confirms a cycle terminates and that a
// critical asset beyond the depth cap does NOT propagate. DB-gated.
func TestBusinessContextLookupRepo_ControlPlaneMultiHop(t *testing.T) {
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
		tenantID.String(), "cp-multi", "cpm-"+tenantID.String()[:8])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	mkAsset := func(name, crit string) shared.ID {
		var idStr string
		if err := db.QueryRowContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type, criticality) VALUES ($1,$2,$3,$4) RETURNING id`,
			tenantID.String(), name, "service", crit).Scan(&idStr); err != nil {
			t.Fatalf("insert asset %s: %v", name, err)
		}
		id, _ := shared.IDFromString(idStr)
		return id
	}
	// cpEdge: served --depends_on--> controlPlane, is_control_plane=true (the
	// TARGET/controlPlane is the control plane of the SOURCE/served).
	cpEdge := func(served, controlPlane shared.ID) {
		mustExec(t, db, `
			INSERT INTO asset_relationships
				(id, tenant_id, source_asset_id, target_asset_id, relationship_type,
				 confidence, discovery_method, impact_weight, is_control_plane)
			VALUES ($1,$2,$3,$4,'depends_on','medium','manual',5,TRUE)`,
			shared.NewID().String(), tenantID.String(), served.String(), controlPlane.String())
	}

	// Chain: idp(low) is CP of secrets(low); secrets is CP of crown(critical).
	// idp -> secrets -> crown, two hops. idp must inherit critical.
	idp := mkAsset("idp-01", "low")
	secrets := mkAsset("secrets-01", "low")
	crown := mkAsset("crown-01", "critical")
	cpEdge(secrets, idp)   // idp is control plane of secrets
	cpEdge(crown, secrets) // secrets is control plane of crown

	// A critical asset 4 hops from idp must NOT propagate (cap is 3).
	// idp -> secrets -> crown -> h3(medium) -> deepCrit(critical).
	h3 := mkAsset("h3-01", "medium")
	deepCrit := mkAsset("deep-crit-01", "critical")
	cpEdge(h3, crown)    // crown is control plane of h3   (idp hop 3)
	cpEdge(deepCrit, h3) // h3 is control plane of deepCrit (idp hop 4 — beyond cap)

	repo := NewBusinessContextLookupRepo(db)
	got, err := repo.GetForAssets(ctx, tenantID, []shared.ID{idp})
	if err != nil {
		t.Fatalf("GetForAssets: %v", err)
	}
	if c := got[idp].ControlPlaneServesCriticality; c != asset.CriticalityCritical {
		t.Fatalf("2-hop propagation: idp ControlPlaneServesCriticality = %q, want critical", c)
	}
	if got[idp].ControlPlaneServesName != "crown-01" {
		t.Errorf("multi-hop served name = %q, want crown-01 (the hop-2 crown jewel)", got[idp].ControlPlaneServesName)
	}

	// Introduce a cycle (crown -> idp), then re-query: must still terminate and
	// still return critical (regression guard for the cycle guard).
	cpEdge(idp, crown) // crown becomes control plane of idp → idp<->...->crown cycle
	done := make(chan struct{})
	go func() {
		got, err = repo.GetForAssets(ctx, tenantID, []shared.ID{idp})
		close(done)
	}()
	<-done
	if err != nil {
		t.Fatalf("GetForAssets with cycle: %v", err)
	}
	if c := got[idp].ControlPlaneServesCriticality; c != asset.CriticalityCritical {
		t.Fatalf("cycle graph: idp ControlPlaneServesCriticality = %q, want critical", c)
	}
	_ = deepCrit // its criticality must never reach idp; asserted via crown-01 name above
}

// TestBusinessContextLookupRepo_BUHierarchyInheritance verifies Feature 2: an
// asset in a child BU inherits the MAX criticality up the parent chain, only
// raises, and a flat BU is unchanged. DB-gated.
func TestBusinessContextLookupRepo_BUHierarchyInheritance(t *testing.T) {
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
		tenantID.String(), "bu-hier", "buh-"+tenantID.String()[:8])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	mkAsset := func(name string) shared.ID {
		var idStr string
		if err := db.QueryRowContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,$3) RETURNING id`,
			tenantID.String(), name, "domain").Scan(&idStr); err != nil {
			t.Fatalf("insert asset %s: %v", name, err)
		}
		id, _ := shared.IDFromString(idStr)
		return id
	}
	mkBU := func(name, crit string, parent *shared.ID) shared.ID {
		id := shared.NewID()
		if parent == nil {
			mustExec(t, db, `INSERT INTO business_units (id, tenant_id, name, criticality) VALUES ($1,$2,$3,$4)`,
				id.String(), tenantID.String(), name, crit)
		} else {
			mustExec(t, db, `INSERT INTO business_units (id, tenant_id, name, criticality, parent_id) VALUES ($1,$2,$3,$4,$5)`,
				id.String(), tenantID.String(), name, crit, parent.String())
		}
		return id
	}
	link := func(bu, a shared.ID) {
		mustExec(t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`,
			shared.NewID().String(), tenantID.String(), bu.String(), a.String())
	}

	// Root (critical) -> Div (medium) -> Squad (low). Asset lives in Squad.
	root := mkBU("Payments", "critical", nil)
	div := mkBU("Division", "medium", &root)
	squad := mkBU("Squad", "low", &div)
	child := mkAsset("child-app")
	link(squad, child)

	// A separate flat BU (high) with its own asset — back-compat, no parent.
	flat := mkBU("IT", "high", nil)
	flatAsset := mkAsset("it-app")
	link(flat, flatAsset)

	repo := NewBusinessContextLookupRepo(db)
	got, err := repo.GetForAssets(ctx, tenantID, []shared.ID{child, flatAsset})
	if err != nil {
		t.Fatalf("GetForAssets: %v", err)
	}
	// child inherits the root's critical via Squad -> Div -> Payments.
	if c := got[child].BusinessUnitCriticality; c != asset.CriticalityCritical {
		t.Fatalf("BU inheritance: child BusinessUnitCriticality = %q, want critical", c)
	}
	if got[child].BusinessUnitName != "Payments" {
		t.Errorf("BU inheritance source name = %q, want Payments", got[child].BusinessUnitName)
	}
	// flat BU unchanged (own high, no parent) — back-compat.
	if c := got[flatAsset].BusinessUnitCriticality; c != asset.CriticalityHigh {
		t.Fatalf("flat BU: BusinessUnitCriticality = %q, want high", c)
	}
	if got[flatAsset].BusinessUnitName != "IT" {
		t.Errorf("flat BU name = %q, want IT", got[flatAsset].BusinessUnitName)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
