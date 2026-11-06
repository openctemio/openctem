package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Dynamic target selectors (RFC-068) read the inventory as the application
// role: the names under a wildcard root and the addresses inside a range,
// pinned to one tenant, with the freshness filters. Requires DATABASE_URL.
func TestScanSelectorRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewScanSelectorRepository(&DB{DB: sqlDB})

	tenant, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenant, other} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "sel-"+id.String()); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id = $1`, id.String())
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		}
	})
	now := time.Now().UTC()
	add := func(tid shared.ID, name, typ, status string, lastSeen time.Time) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, exposure, criticality, last_seen)
			VALUES ($1, $2, $3, $4, $5, 'public', 'medium', $6)`, shared.NewID().String(), tid.String(), name, typ, status, lastSeen); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
	}
	add(tenant, "sel.example.com", "domain", "active", now)
	add(tenant, "api.sel.example.com", "subdomain", "active", now.Add(-time.Hour))
	add(tenant, "old.sel.example.com", "subdomain", "active", now.AddDate(0, 0, -40))
	add(tenant, "stale.sel.example.com", "subdomain", "stale", now.AddDate(0, 0, -2))
	add(tenant, "gone.sel.example.com", "subdomain", "archived", now)
	add(tenant, "notsel.example.com", "domain", "active", now) // a label boundary
	add(tenant, "selxexample.com", "domain", "active", now)    // "_"/"." are not wildcards
	add(tenant, "203.0.113.7", "ip_address", "active", now)    // an address is not a name under the root
	add(tenant, "203.0.113.200", "ip_address", "active", now)  // in the range
	add(tenant, "198.51.100.1", "ip_address", "active", now)   // outside the range
	add(tenant, "203.0.113.0/28", "ip_address", "active", now) // a range-named asset is never cast
	add(other, "leak.sel.example.com", "subdomain", "active", now)
	add(other, "203.0.113.9", "ip_address", "active", now)

	names := func(q scan.SelectorQuery) []string {
		t.Helper()
		got, err := r.ListSelectorAssets(ctx, q)
		if err != nil {
			t.Fatalf("list %+v: %v", q, err)
		}
		out := make([]string, 0, len(got))
		for _, m := range got {
			out = append(out, m.Name)
		}
		return out
	}

	got := names(scan.SelectorQuery{TenantID: tenant, UnderDomain: "SEL.example.com."})
	if want := []string{"sel.example.com", "api.sel.example.com", "old.sel.example.com"}; !slices.Equal(got, want) {
		t.Errorf("under: %v, want %v (freshest first, no stale, archived, other tenant or boundary match)", got, want)
	}
	got = names(scan.SelectorQuery{TenantID: tenant, UnderDomain: "sel.example.com", IncludeStale: true})
	if !slices.Contains(got, "stale.sel.example.com") || slices.Contains(got, "gone.sel.example.com") {
		t.Errorf("include stale: %v, want stale but never archived", got)
	}
	since := now.AddDate(0, 0, -30)
	got = names(scan.SelectorQuery{TenantID: tenant, UnderDomain: "sel.example.com", SeenSince: &since})
	if slices.Contains(got, "old.sel.example.com") || len(got) != 2 {
		t.Errorf("seen since: %v, want the two names seen in the window", got)
	}
	if got = names(scan.SelectorQuery{TenantID: tenant, UnderDomain: "sel.example.com", Limit: 1}); !slices.Equal(got, []string{"sel.example.com"}) {
		t.Errorf("limit 1: %v, want the freshest", got)
	}

	got = names(scan.SelectorQuery{TenantID: tenant, InCIDR: "203.0.113.0/24"})
	slices.Sort(got)
	if want := []string{"203.0.113.200", "203.0.113.7"}; !slices.Equal(got, want) {
		t.Errorf("in cidr: %v, want %v", got, want)
	}
	if got = names(scan.SelectorQuery{TenantID: other, InCIDR: "203.0.113.0/24"}); !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("other tenant in cidr: %v, want only its own address", got)
	}

	for _, bad := range []scan.SelectorQuery{
		{UnderDomain: "sel.example.com"},           // no tenant
		{TenantID: tenant},                         // no selector
		{TenantID: tenant, UnderDomain: "%"},       // a pattern, never match-all
		{TenantID: tenant, UnderDomain: "*.x.com"}, // a pattern
		{TenantID: tenant, InCIDR: "not-a-range"},
	} {
		if _, err := r.ListSelectorAssets(ctx, bad); err == nil {
			t.Errorf("query %+v was accepted", bad)
		}
	}
}

// target_options round-trips through the scans table (migration 001640).
func TestScanRepository_TargetOptionsRoundTrip(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: sqlDB})
	tenant := shared.NewID()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "selopt-"+tenant.String()); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM scans WHERE tenant_id = $1`, tenant.String())
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant.String())
	})
	sc, err := scan.NewScanWithTargets(tenant, "dyn", []string{"*.example.com", "203.0.113.0/24"}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	_ = sc.SetSingleScanner("nuclei", map[string]any{}, 1)
	if err := sc.SetTargetOptions(scan.TargetOptions{CIDRMode: scan.CIDRModeInventory, SeenWithinDays: 7}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TargetOptions != sc.TargetOptions {
		t.Errorf("read %+v, want %+v", got.TargetOptions, sc.TargetOptions)
	}
	_ = got.SetTargetOptions(scan.TargetOptions{IncludeStale: true})
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := repo.GetByTenantAndID(ctx, tenant, sc.ID)
	if again.TargetOptions != (scan.TargetOptions{IncludeStale: true}) {
		t.Errorf("after update %+v", again.TargetOptions)
	}
	// Another tenant never reads it.
	if _, err := repo.GetByTenantAndID(ctx, shared.NewID(), sc.ID); err == nil {
		t.Error("another tenant read the scan")
	}
}
