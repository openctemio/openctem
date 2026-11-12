package integration

// Unclassified assets (docs/rfcs/RFC-054-scope-model.md §16) on a migrated
// database with the production gate (easm.ActiveGate over the real
// repositories, the unclassified-scans policy read from the tenant row):
// every scan entry point admits an unclassified asset that passes the
// platform guardrails and refuses a guardrailed one (scan create through
// the API, quick scan, and the dispatch gate every other path uses:
// workflow runs and their hops, automation and coverage, validation,
// connector scans, the claim-time re-check), the setting off and the
// Strict scan approval mode keep the old rule, and another tenant's
// assets and settings never count.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// unclassifiedGate is the production gate with the policy read from the
// tenant row as the server wires it (scope settings, governance mode; an
// unset mode is Off here, the platform default of this database).
func unclassifiedGate(db *sql.DB) *easmapp.ActiveGate {
	g := ownershipGate(db)
	g.SetUnclassified(func(ctx context.Context, tenantID shared.ID) (string, error) {
		var mode, setting sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT scan_approval_policy, settings->'scope'->>'unclassified_scans' FROM tenants WHERE id = $1`,
			tenantID.String()).Scan(&mode, &setting); err != nil {
			return "off", err
		}
		m := scangov.Mode(mode.String)
		if !mode.Valid {
			m = scangov.ModeOff
		}
		s := setting.String
		if s == "" {
			s = "low_impact"
		}
		return scangov.UnclassifiedMode(m, s), nil
	}, postgres.NewAttributionRepository(&postgres.DB{DB: db}))
	return g
}

func seedAssetWithProps(t *testing.T, db *sql.DB, tenant shared.ID, name, typ, props string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO assets (id, tenant_id, name, asset_type, status, properties) VALUES ($1, $2, $3, $4, 'active', $5::jsonb)`,
		id.String(), tenant.String(), name, typ, props); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func TestScanUnclassifiedGate(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`UPDATE tenants SET scan_approval_policy = 'off' WHERE id = ANY($1)`, []string{tenantA.String(), tenantB.String()})
	// One exact entry: unc-a.example is one of tenant A's registrable domains.
	seedScopeTarget(t, db, tenantA, "domain", "www.unc-a.example")

	owned := `{"asn": 64500, "asn_org": "Example Org Networks"}`
	seedOwnedAsset(t, db, tenantA, "mail.unc-a.example", "subdomain")       // passes
	seedAssetWithProps(t, db, tenantA, "203.0.113.40", "ip_address", owned) // passes
	seedOwnedAsset(t, db, tenantA, "203.0.113.41", "ip_address")            // network unknown
	seedOwnedAsset(t, db, tenantA, "x.thirdparty-unc.example", "subdomain") // foreign domain
	seedAssetWithProps(t, db, tenantA, "104.16.9.9", "ip_address", owned)   // CDN edge range
	seedAssetWithProps(t, db, tenantA, "203.0.113.42", "ip_address", `{"asn": 16509, "asn_org": "AMAZON-02"}`)
	rejected := seedOwnedAsset(t, db, tenantA, "old.unc-a.example", "subdomain")
	decide(t, db, tenantA, rejected, "rejected")
	excludedName := "excl.unc-a.example"
	seedOwnedAsset(t, db, tenantA, excludedName, "subdomain")
	seedApprovedExclusion(t, db, tenantA, "domain", excludedName)
	// Tenant B has an asset of a name tenant A admits.
	seedOwnedAsset(t, db, tenantB, "b.unc-b.example", "subdomain")

	allowed := []string{"mail.unc-a.example", "203.0.113.40"}
	refused := map[string]string{
		"203.0.113.41":             scopedom.RefusalGuardrailed,
		"x.thirdparty-unc.example": scopedom.RefusalGuardrailed,
		"104.16.9.9":               scopedom.RefusalGuardrailed,
		"203.0.113.42":             scopedom.RefusalGuardrailed,
		"old.unc-a.example":        scopedom.RefusalRejected,
		"typed.unc-a.example":      scopedom.RefusalNoEntry, // not in the inventory
	}
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(unclassifiedGate(db)))

	createScan := func(tenant shared.ID, target string) error {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenant.String(), Name: "unc " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{target}, TenantRunner: true,
		})
		return err
	}
	refusalOf := func(err error) string {
		var de *shared.DomainError
		if !errors.As(err, &de) {
			return ""
		}
		details, _ := de.Details.(map[string]any)
		list, _ := details["refused"].([]scopedom.Refusal)
		if len(list) == 0 {
			return "?"
		}
		return list[0].Code
	}

	t.Run("api scan", func(t *testing.T) {
		for _, target := range allowed {
			if err := createScan(tenantA, target); err != nil {
				t.Fatalf("%s refused: %v", target, err)
			}
		}
		for target, code := range refused {
			if got := refusalOf(createScan(tenantA, target)); got != code {
				t.Errorf("%s: refusal %q, want %q", target, got, code)
			}
		}
	})

	// Quick scan: the refusals (the admitted targets go on to sensor
	// routing, which this harness does not wire; the dispatch gate below
	// admits them).
	t.Run("quick scan", func(t *testing.T) {
		for target := range refused {
			if _, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenantA.String(), ScannerName: "httpx", Targets: []string{target}}); err == nil {
				t.Errorf("%s: quick scan allowed", target)
			}
		}
	})

	// Workflow runs and hops, automation, coverage, validation, connector
	// scans and the claim-time re-check all call the dispatch gate.
	t.Run("dispatch gate paths", func(t *testing.T) {
		targets := slices.Clone(allowed)
		for k := range refused {
			targets = append(targets, k)
		}
		targets = append(targets, excludedName)
		for _, path := range []string{"workflow_hop", "automation", "coverage", "claim_recheck"} {
			got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: targets, Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.Allowed, allowed) {
				t.Fatalf("%s: allowed = %v, want %v", path, got.Allowed, allowed)
			}
			if !slices.Contains(got.Excluded, excludedName) {
				t.Fatalf("%s: an exclusion must win: %v", path, got.Excluded)
			}
		}
		// A passive step takes an admitted unclassified asset too.
		passive, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: allowed, PassiveOnly: true})
		if err != nil || !slices.Equal(passive.Allowed, allowed) {
			t.Fatalf("passive: %+v %v", passive, err)
		}
	})

	t.Run("cross-tenant", func(t *testing.T) {
		// Tenant B has no entry and no asset of tenant A's names; its own
		// asset is under none of its domains (no entries at all).
		got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantB,
			Targets: []string{"mail.unc-a.example", "203.0.113.40", "b.unc-b.example"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Allowed) != 0 {
			t.Fatalf("tenant B admitted %v", got.Allowed)
		}
	})

	t.Run("setting off and Strict", func(t *testing.T) {
		exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{scope}', COALESCE(settings->'scope', '{}'::jsonb) || '{"unclassified_scans":"off"}') WHERE id = $1`, tenantA.String())
		// The organization's "off" holds on every placement, its own sensors included.
		for _, place := range []attribution.Placement{attribution.PlacementUnknown, attribution.PlacementPlatform, attribution.PlacementTenant} {
			got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: allowed, Placement: place})
			if err != nil || len(got.Allowed) != 0 {
				t.Fatalf("setting off (placement %v): %+v %v", place, got, err)
			}
		}
		exec(`UPDATE tenants SET settings = jsonb_set(settings, '{scope,unclassified_scans}', '"full"'), scan_approval_policy = 'strict' WHERE id = $1`, tenantA.String())
		for _, place := range []attribution.Placement{attribution.PlacementUnknown, attribution.PlacementPlatform, attribution.PlacementTenant} {
			got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: allowed, Placement: place})
			if err != nil || len(got.Allowed) != 0 {
				t.Fatalf("strict (placement %v): %+v %v", place, got, err)
			}
		}
	})
}
