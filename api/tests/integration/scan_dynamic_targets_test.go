package integration

// Dynamic target selectors (RFC-068) on a migrated database, with the
// production inventory reader, ownership gate and scope exclusions: a run of
// *.x scans the apex and the names the inventory holds under it that the
// tenant authorized, re-read at every run; an inventory-mode CIDR scans the
// addresses inside it that a scope entry covers, never one outside scope
// even though the inventory holds it; another tenant's inventory never adds
// a target; the run records what each selector added.

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanDynamicTargets(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	seedScopeTarget(t, db, tenantA, "domain", "*.dyn.example.com")
	seedScopeTarget(t, db, tenantA, "cidr", "203.0.113.0/28")
	seedApprovedExclusion(t, db, tenantA, "domain", "excl.dyn.example.com")

	seedOwnedAsset(t, db, tenantA, "app.dyn.example.com", "subdomain")  // no record, under the entry: allowed
	seedOwnedAsset(t, db, tenantA, "excl.dyn.example.com", "subdomain") // excluded
	review := seedOwnedAsset(t, db, tenantA, "rev.dyn.example.com", "subdomain")
	automatic(t, db, tenantA, review, attribution.StateNeedsReview) // not confirmed
	rejected := seedOwnedAsset(t, db, tenantA, "rej.dyn.example.com", "subdomain")
	decide(t, db, tenantA, rejected, attribution.StateRejected) // rejected
	archived := seedOwnedAsset(t, db, tenantA, "old.dyn.example.com", "subdomain")
	if _, err := db.ExecContext(ctx, `UPDATE assets SET status = 'archived' WHERE id = $1`, archived.String()); err != nil {
		t.Fatal(err)
	}
	seedOwnedAsset(t, db, tenantA, "203.0.113.5", "ip_address")   // inside the scope entry
	seedOwnedAsset(t, db, tenantA, "203.0.113.100", "ip_address") // inside the scan's range, outside scope
	seedOwnedAsset(t, db, tenantB, "b.dyn.example.com", "subdomain")
	seedOwnedAsset(t, db, tenantB, "203.0.113.6", "ip_address")

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(ownershipGate(db)))
	svc.SetSelectorAssets(postgres.NewScanSelectorRepository(&postgres.DB{DB: db}))

	run := func(t *testing.T, id shared.ID) ([]string, map[string]any) {
		t.Helper()
		r, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: id.String()})
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		got := lastCommandTargets(t, db, tenantA)
		slices.Sort(got)
		var raw []byte
		if err := db.QueryRowContext(ctx, `SELECT context FROM scan_runs WHERE id = $1 AND tenant_id = $2`,
			r.ID.String(), tenantA.String()).Scan(&raw); err != nil {
			t.Fatalf("read run: %v", err)
		}
		var rc map[string]any
		_ = json.Unmarshal(raw, &rc)
		return got, rc
	}

	t.Run("wildcard", func(t *testing.T) {
		sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "dyn " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{"*.dyn.example.com"}, TenantRunner: true,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		got, rc := run(t, sc.ID)
		if want := []string{"app.dyn.example.com", "dyn.example.com"}; !slices.Equal(got, want) {
			t.Fatalf("dispatched %v, want %v", got, want)
		}
		exp, _ := rc[scansvc.RunContextKeyTargetExpansion].([]any)
		if len(exp) != 1 {
			t.Fatalf("run expansion = %v", rc[scansvc.RunContextKeyTargetExpansion])
		}
		e := exp[0].(map[string]any)
		// Four live names of tenant A (not the archived one, never tenant B's).
		if e["selector"] != "*.dyn.example.com" || e["matched"] != float64(4) {
			t.Errorf("expansion = %v, want 4 matched", e)
		}

		// A name found since the last run is scanned by the next one.
		seedOwnedAsset(t, db, tenantA, "new.dyn.example.com", "subdomain")
		if got, _ = run(t, sc.ID); !slices.Contains(got, "new.dyn.example.com") {
			t.Errorf("second run %v does not scan the name found since", got)
		}
	})

	t.Run("cidr inventory mode", func(t *testing.T) {
		sc, err := scan.NewScanWithTargets(tenantA, "cidr "+shared.NewID().String(), []string{"203.0.113.0/24"}, scan.ScanTypeSingle)
		if err != nil {
			t.Fatal(err)
		}
		_ = sc.SetSingleScanner("nuclei", map[string]any{}, 1)
		sc.RunOnTenantRunner = true
		if err := sc.SetTargetOptions(scan.TargetOptions{CIDRMode: scan.CIDRModeInventory}); err != nil {
			t.Fatal(err)
		}
		if err := postgres.NewScanRepository(&postgres.DB{DB: db}).Create(ctx, sc); err != nil {
			t.Fatalf("store scan: %v", err)
		}
		got, _ := run(t, sc.ID)
		if want := []string{"203.0.113.5"}; !slices.Equal(got, want) {
			t.Fatalf("dispatched %v, want %v (never the range, never an address outside scope or of tenant B)", got, want)
		}
	})
}
