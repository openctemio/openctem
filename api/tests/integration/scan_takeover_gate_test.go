package integration

// research/22 decision E13 on a migrated database with the production gate:
// a dependency asset may be probed only by a nuclei scan with exactly the
// `takeover` tag, and only while the DNS check has an open dangling_cname on
// it. Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"database/sql"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/easmdns"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func openDangling(t *testing.T, db *sql.DB, tenant, asset shared.ID, name, state string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, state, title, details, fingerprint, source,
			first_seen_at, last_seen_at, created_at, updated_at)
		VALUES ($1, $2, $3, 'dangling_cname', 'medium', $4, $5, jsonb_build_object('domain', $6::text), $7, $8, now(), now(), now(), now())`,
		shared.NewID().String(), tenant.String(), asset.String(), state, "Dangling CNAME: "+name, name,
		shared.NewID().String(), easmdns.Source); err != nil {
		t.Fatal(err)
	}
}

func TestScanTakeoverGate(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	seedScopeTarget(t, db, tenantA, "domain", "*.tko.example.com")

	dangling := seedOwnedAsset(t, db, tenantA, "shop.tko.example.com", "subdomain")
	decide(t, db, tenantA, dangling, attribution.StateDependency)
	openDangling(t, db, tenantA, dangling, "shop.tko.example.com", "active")

	fixed := seedOwnedAsset(t, db, tenantA, "fixed.tko.example.com", "subdomain")
	decide(t, db, tenantA, fixed, attribution.StateDependency)
	openDangling(t, db, tenantA, fixed, "fixed.tko.example.com", "resolved")

	review := seedOwnedAsset(t, db, tenantA, "rev.tko.example.com", "subdomain")
	automatic(t, db, tenantA, review, attribution.StateNeedsReview)
	openDangling(t, db, tenantA, review, "rev.tko.example.com", "active")

	// Tenant B's open dangling CNAME on the same name never admits A's asset.
	bOnly := seedOwnedAsset(t, db, tenantA, "bonly.tko.example.com", "subdomain")
	decide(t, db, tenantA, bOnly, attribution.StateDependency)
	bAsset := seedOwnedAsset(t, db, tenantB, "bonly.tko.example.com", "subdomain")
	openDangling(t, db, tenantB, bAsset, "bonly.tko.example.com", "active")

	pg := &postgres.DB{DB: db}
	gate := easmapp.NewActiveGate(postgres.NewAttributionRepository(pg), postgres.NewAssetRepository(pg),
		scopeService(db), postgres.NewEASMSeedRepository(pg)).WithTakeoverEvidence(postgres.NewEASMDNSRepository(pg))
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)), scansvc.WithAttributionGate(gate))

	create := func(scanner string, config map[string]any, target string) error {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "tko " + shared.NewID().String(), ScanType: "single",
			ScannerName: scanner, ScannerConfig: config, Targets: []string{target}, TenantRunner: true,
		})
		return err
	}
	takeover := map[string]any{"tags": []any{"takeover"}}

	if err := create("nuclei", takeover, "shop.tko.example.com"); err != nil {
		t.Fatalf("takeover scan of a dependency with an open dangling CNAME refused: %v", err)
	}
	refusals := []struct {
		name, scanner, target string
		config                map[string]any
	}{
		{"another tag", "nuclei", "shop.tko.example.com", map[string]any{"tags": []any{"takeover", "cve"}}},
		{"templates", "nuclei", "shop.tko.example.com", map[string]any{"tags": []any{"takeover"}, "templates": []any{"x.yaml"}}},
		{"another scanner", "httpx", "shop.tko.example.com", takeover},
		{"dangling CNAME resolved", "nuclei", "fixed.tko.example.com", takeover},
		{"needs_review is not a dependency", "nuclei", "rev.tko.example.com", takeover},
		{"only another tenant's dangling CNAME", "nuclei", "bonly.tko.example.com", takeover},
	}
	for _, r := range refusals {
		if err := create(r.scanner, r.config, r.target); err == nil {
			t.Errorf("%s: admitted", r.name)
		}
	}
}
