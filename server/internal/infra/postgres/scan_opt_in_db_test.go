package postgres

// research/25 D3: the scans whose scanner_config asks for interactsh or
// custom templates, for the opt-ins banner. Tenant-scoped.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanRepository_ListOptInScans_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantA := seedScanTriggerTenant(ctx, t, db)
	tenantB := seedScanTriggerTenant(ctx, t, db)

	newScan := func(tenantID shared.ID, name string, cfg map[string]any) *scan.Scan {
		t.Helper()
		sc, err := scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
		if err != nil {
			t.Fatal(err)
		}
		sc.SetTargets([]string{"example.com"})
		if err := sc.SetSingleScanner("nuclei", cfg, 1); err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, sc); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String())
		})
		return sc
	}
	oast := newScan(tenantA, "oast", map[string]any{"allow_interactsh": true})
	oastStr := newScan(tenantA, "oast-string", map[string]any{"allow_interactsh": "TRUE"})
	tmpl := newScan(tenantA, "templates", map[string]any{"custom_template_ids": []any{shared.NewID().String()}})
	newScan(tenantA, "plain", map[string]any{"allow_interactsh": false, "custom_template_ids": []any{}})
	newScan(tenantA, "odd", map[string]any{"custom_template_ids": "not-a-list"})
	newScan(tenantB, "other tenant", map[string]any{"allow_interactsh": true})

	got, err := repo.ListOptInScans(ctx, tenantA, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := map[shared.ID]bool{oast.ID: true, oastStr.ID: true, tmpl.ID: true}
	if len(got) != len(want) {
		t.Fatalf("listed %d scans, want %d", len(got), len(want))
	}
	for _, s := range got {
		if !want[s.ID] || s.TenantID != tenantA {
			t.Errorf("unexpected scan %s (%s) of tenant %s", s.Name, s.ID, s.TenantID)
		}
	}
	if got, _ := repo.ListOptInScans(ctx, tenantA, 2); len(got) != 2 {
		t.Errorf("limit not applied: %d", len(got))
	}
}
