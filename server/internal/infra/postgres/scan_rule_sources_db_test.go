package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan's and a profile's rule sources are stored and read back; a scan
// that sets none reads as "" (inherit) and a profile as both. Another
// tenant cannot read either.
func TestScanAndProfileRuleSourcesRoundTrip(t *testing.T) {
	db := openScanDB(t)
	ctx := context.Background()
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	wrapped := &DB{DB: db}

	profiles := NewScanProfileRepository(wrapped)
	p, err := scanprofile.NewScanProfile(tenant, "rule sources profile", "", nil, scanprofile.IntensityMedium, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := profiles.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := profiles.GetAccessibleByID(ctx, tenant, p.ID)
	if err != nil || got.RuleSources != scannertemplate.RuleSourcesBoth {
		t.Fatalf("new profile = %+v, %v; want both", got, err)
	}
	if err := got.SetRuleSources("tenant"); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = profiles.GetAccessibleByID(ctx, tenant, p.ID); got.RuleSources != scannertemplate.RuleSourcesTenant {
		t.Fatalf("updated profile = %q, want tenant", got.RuleSources)
	}
	if _, err := profiles.GetAccessibleByID(ctx, other, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read the profile: %v", err)
	}

	scans := NewScanRepository(wrapped)
	sc, err := scan.NewScan(tenant, "rule sources scan", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Targets = []string{"203.0.113.10"}
	sc.ScannerName = "nuclei"
	if err := scans.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	read, err := scans.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil || read.RuleSources != "" {
		t.Fatalf("new scan = %q, %v; want inherit", read.RuleSources, err)
	}
	if err := read.SetRuleSources("platform"); err != nil {
		t.Fatal(err)
	}
	if err := scans.Update(ctx, read); err != nil {
		t.Fatal(err)
	}
	if read, _ = scans.GetByTenantAndID(ctx, tenant, sc.ID); read.RuleSources != scannertemplate.RuleSourcesPlatform {
		t.Fatalf("updated scan = %q, want platform", read.RuleSources)
	}
	_ = read.SetRuleSources("")
	if err := scans.Update(ctx, read); err != nil {
		t.Fatal(err)
	}
	if read, _ = scans.GetByTenantAndID(ctx, tenant, sc.ID); read.RuleSources != "" {
		t.Fatalf("cleared scan = %q, want inherit", read.RuleSources)
	}
	if _, err := scans.GetByTenantAndID(ctx, other, sc.ID); err == nil {
		t.Fatal("another tenant read the scan")
	}

	// The database refuses a value outside the three.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET rule_sources = 'everything' WHERE id = $1`, sc.ID.String()); err == nil {
		t.Fatal("scans.rule_sources accepted an unknown value")
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_profiles SET rule_sources = NULL WHERE id = $1`, p.ID.String()); err == nil {
		t.Fatal("scan_profiles.rule_sources accepted NULL")
	}
}
