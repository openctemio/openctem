package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
)

// The in_cidr filter of buildWhereClause (smart group rules, GET
// /assets?in_cidr=) is a per-tenant lookup: without a tenant it matches
// nothing and binds no range, with one every range is a bound inet and the
// lookup names the tenant ($1).
func TestBuildWhereClause_InCIDRs(t *testing.T) {
	r := &AssetRepository{}
	tenant := "00000000-0000-0000-0000-000000000001"

	for name, f := range map[string]asset.Filter{
		"no tenant":    {InCIDRs: []string{"10.0.0.0/8"}},
		"empty tenant": {TenantID: new(string), InCIDRs: []string{"10.0.0.0/8", "10.1.2.3"}},
	} {
		where, args := r.buildWhereClause(f)
		if !strings.Contains(where, "FALSE") {
			t.Errorf("%s: where = %q, want FALSE (fail closed)", name, where)
		}
		if strings.Contains(where, "asset_ip_addresses") || strings.Contains(where, "a.tenant_id") {
			t.Errorf("%s: where = %q, want no address lookup", name, where)
		}
		for _, a := range args {
			if s, ok := a.(string); ok && strings.HasPrefix(s, "10.") {
				t.Errorf("%s: range %q bound without a tenant", name, s)
			}
		}
	}

	where, args := r.buildWhereClause(asset.Filter{TenantID: &tenant, InCIDRs: []string{"10.0.0.0/8", " 10.1.2.3 ", "not-a-range"}})
	for _, want := range []string{"a.tenant_id = $1", "a.id IN (SELECT x.asset_id FROM asset_ip_addresses x WHERE x.tenant_id = $1::uuid", "$2::inet", "$3::inet"} {
		if !strings.Contains(where, want) {
			t.Errorf("where = %q, want it to contain %q", where, want)
		}
	}
	if strings.Contains(where, "$4") || strings.Contains(where, "ANY(ARRAY(") {
		t.Errorf("where = %q: an unparsable value was bound, or the array form is back", where)
	}
	if len(args) != 3 || args[0] != tenant || args[1] != "10.0.0.0/8" || args[2] != "10.1.2.3/32" {
		t.Errorf("args = %v, want [tenant 10.0.0.0/8 10.1.2.3/32]", args)
	}

	where, _ = r.buildWhereClause(asset.Filter{TenantID: &tenant, InCIDRs: []string{"example.com"}})
	if !strings.Contains(where, "FALSE") || strings.Contains(where, "asset_ip_addresses") {
		t.Errorf("only unparsable ranges: where = %q, want FALSE", where)
	}
}

// A list page reads its ids from assets alone and joins the per-asset
// columns for those ids; a sort on the open-findings count needs that join
// for every row and keeps the one-statement form.
func TestBuildAssetPageQuery(t *testing.T) {
	sel := "SELECT a.id, fc.finding_count FROM assets a LEFT JOIN LATERAL (SELECT 1) fc ON true"
	where := "a.deleted_at IS NULL AND a.tenant_id = $1"

	q := buildAssetPageQuery(sel, where, "a.created_at DESC, a.id", 50, 100)
	want := sel + " WHERE a.id IN (SELECT a.id FROM assets a WHERE " + where +
		" ORDER BY a.created_at DESC, a.id LIMIT 50 OFFSET 100) ORDER BY a.created_at DESC, a.id"
	if q != want {
		t.Errorf("page query =\n%s\nwant\n%s", q, want)
	}

	q = buildAssetPageQuery(sel, where, "COALESCE(fc.finding_count, 0) DESC, a.id", 20, 0)
	want = sel + " WHERE " + where + " ORDER BY COALESCE(fc.finding_count, 0) DESC, a.id LIMIT 20 OFFSET 0"
	if q != want {
		t.Errorf("finding_count sort =\n%s\nwant\n%s", q, want)
	}
}
