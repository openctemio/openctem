package postgres

import (
	"context"
	"slices"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The exclusion preview lists, for an address, range or CIDR, the names it
// also excludes because they resolve to a dedicated address inside it (every
// address spelling asset.IPAddresses reads), never names behind a shared
// front end (owner decision 2026-10-30), only the tenant's own names, and
// only inside the caller's data scope. Requires DATABASE_URL.
func TestExclusionPreview_ResolvingNames(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: db}
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	add := func(tid shared.ID, name, typ, props string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, properties)
			VALUES ($1, $2, $3, $4, 'active', $5::jsonb)`, shared.NewID().String(), tid.String(), name, typ, props); err != nil {
			t.Fatal(err)
		}
	}
	add(tenant, "vpn.pv.example.com", "subdomain", `{"ip_addresses": ["203.0.113.7"]}`)
	add(tenant, "mail.pv.example.com", "subdomain", `{"resolved_ips": "198.51.100.1, 203.0.113.7"}`)
	add(tenant, "old.pv.example.com", "subdomain", `{"ip_address": {"address": "203.0.113.7"}}`)
	add(tenant, "api.pv.example.com:443:tcp", "service", `{"ip": "203.0.113.8"}`)
	add(tenant, "shop.pv.example.com", "subdomain", `{"ip_addresses": ["104.16.1.1", "104.16.1.2"]}`)
	add(tenant, "mix.pv.example.com", "subdomain", `{"ip_addresses": ["104.16.1.1", "203.0.113.9"]}`)
	add(tenant, "203.0.113.7", "ip_address", `{"ip_addresses": ["203.0.113.7"]}`) // an address, not a name
	add(tenant, "bad.pv.example.com", "subdomain", `{"ip_addresses": ["not-an-ip", "203.0.113.0/24"]}`)
	add(other, "theirs.pv.example.org", "subdomain", `{"ip_addresses": ["203.0.113.7", "104.16.1.1"]}`)

	cov := NewScopeCoverageRepository(pg)
	items := []scopeapp.BulkExclusionItem{
		{ExclusionType: "ip_address", Pattern: "203.0.113.7"},
		{ExclusionType: "cidr", Pattern: "203.0.113.0/28"},
		{ExclusionType: "ip_address", Pattern: "104.16.1.1"},
		{ExclusionType: "cidr", Pattern: "104.16.0.0/16"},
		{ExclusionType: "ip_range", Pattern: "203.0.113.8-203.0.113.9"},
		{ExclusionType: "domain", Pattern: "*.pv.example.com"},
	}
	m, err := cov.ExclusionMatches(ctx, tenant, nil, items)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		n      int
		sample []string
	}{
		{3, []string{"mail.pv.example.com", "old.pv.example.com", "vpn.pv.example.com"}},
		{5, []string{"api.pv.example.com:443:tcp", "mail.pv.example.com", "mix.pv.example.com", "old.pv.example.com", "vpn.pv.example.com"}},
		{0, nil}, // a shared front end: names behind it stay in scans
		{0, nil},
		{2, []string{"api.pv.example.com:443:tcp", "mix.pv.example.com"}},
		{0, nil}, // a name pattern reaches no name by address
	}
	for i, w := range want {
		if m[i].Names != w.n || (w.n > 0 && !slices.Equal(m[i].NameSample, w.sample)) {
			t.Errorf("%s %s: names = %d %v, want %d %v", items[i].ExclusionType, items[i].Pattern, m[i].Names, m[i].NameSample, w.n, w.sample)
		}
	}
	if m[0].Matched != 1 {
		t.Errorf("the address asset itself: matched = %d", m[0].Matched)
	}
	restricted := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}
	if m, err = cov.ExclusionMatches(ctx, tenant, restricted, items); err != nil || m[0].Names != 0 || m[1].Names != 0 {
		t.Fatalf("a member without scope rows saw %+v (%v)", m, err)
	}
	if m, err = cov.ExclusionMatches(ctx, tenant, &shared.DataScope{TenantID: other, Unrestricted: true}, items); err != nil || m[0].Names != 0 {
		t.Fatalf("a scope of another tenant saw %+v (%v)", m, err)
	}
	if m, err = cov.ExclusionMatches(ctx, other, nil, items); err != nil || m[0].Names != 1 || m[2].Names != 0 {
		t.Fatalf("the other tenant: %+v (%v)", m, err)
	}
}
