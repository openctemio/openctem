package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// SECURITY: path discovery is planned only on a web service an active
// scope entry names (another organization's entry never counts, an address
// needs an exact address entry), with new inventory since its last success,
// and not challenged by an edge protection at its last probe. Requires
// DATABASE_URL.
func TestAssetCoverageReconcile_PathDiscoveryPredicates(t *testing.T) {
	db := openHopDB(t)
	repo := NewAssetCoverageRepository(&DB{DB: db})
	ctx := context.Background()
	h, other := newHopTenant(t, db, 0), newHopTenant(t, db, 0)
	hopExec(t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES
		($1, 'domain', '*.in.example.com', 'active'), ($1, 'ip_address', '198.51.100.7', 'active'),
		($1, 'ip_address', '2001:db8::1', 'active')`, h.tenant)
	hopExec(t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.out.example.com', 'active')`, other.tenant)

	service := func(name string) shared.ID {
		t.Helper()
		id := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, properties)
			VALUES ($1, $2, $3, 'service', 'http', '{}'::jsonb)`, id, h.tenant, name)
		hopExec(t, db, `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, kind, auth_state, sources)
			VALUES (gen_random_uuid(), $1, $2, 'GET', '/index.php', md5($3::text), md5('/index.php'), 'page', 'unknown', '{crawl}')`, h.tenant, id, name)
		return id
	}
	inScope := service("https://app.in.example.com")
	outOfScope := service("https://app.out.example.com") // only another organization's entry names it
	addrNamed := service("https://198.51.100.7")
	addrUnnamed := service("https://198.51.100.8")
	v6Named := service("https://[2001:DB8::1]:8443") // an IPv6 literal is read whole, not cut at its first colon
	v6Unnamed := service("https://[2001:db8::2]")
	edge := service("https://edge.in.example.com")
	unchanged := service("https://old.in.example.com")
	hopExec(t, db, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome) VALUES ($1, $2, 'probe.http', 'failed', 'edge_challenged')`, h.tenant, edge)
	hopExec(t, db, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_success_at) VALUES ($1, $2, 'enumerate.web_paths', 'covered', now() + interval '1 minute')`, h.tenant, unchanged)

	var rules []coverage.Rule
	for _, r := range coverage.RulesFor(asset.AssetTypeService, "http") {
		if r.Capability == coverage.CapabilityEnumerateWebPaths {
			rules = append(rules, r)
		}
	}
	if len(rules) != 1 {
		t.Fatalf("http service path discovery rules: %+v", rules)
	}
	if _, _, err := repo.Reconcile(ctx, h.tenant, rules); err != nil {
		t.Fatal(err)
	}
	state := func(id shared.ID) (string, string) {
		t.Helper()
		var st, reason string
		if err := db.QueryRowContext(ctx, `SELECT state, reason FROM asset_coverage
			WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'enumerate.web_paths'`, h.tenant.String(), id.String()).Scan(&st, &reason); err != nil {
			t.Fatal(err)
		}
		return st, reason
	}
	for name, id := range map[string]shared.ID{"in scope": inScope, "address named by an entry": addrNamed, "IPv6 address named by an entry": v6Named} {
		if st, _ := state(id); st != "due" {
			t.Errorf("%s: %s, want due", name, st)
		}
	}
	for name, c := range map[string]struct {
		id     shared.ID
		reason string
	}{
		"out of scope":          {outOfScope, coverage.RequiresOriginScopeEntry},
		"address without entry": {addrUnnamed, coverage.RequiresOriginScopeEntry},
		"IPv6 without entry":    {v6Unnamed, coverage.RequiresOriginScopeEntry},
		"edge challenged":       {edge, coverage.RequiresEdgeClear},
		"inventory unchanged":   {unchanged, coverage.RequiresInventoryChanged},
	} {
		if st, reason := state(c.id); st != "not_applicable" || reason != c.reason {
			t.Errorf("%s: %s/%s, want not_applicable/%s", name, st, reason, c.reason)
		}
	}
}
