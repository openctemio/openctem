package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A web service reached by IP whose address and port a named web service
// also serves is not template-scanned (no_named_twin): the named virtual
// host or CDN-fronted application answers its bare address with a default
// page. An address service with no named twin, one on another port, and one
// whose only twin belongs to another organization are still scanned; the
// pair is due again once the twin is gone. Requires DATABASE_URL.
func TestAssetCoverageReconcile_NoNamedTwin(t *testing.T) {
	db := openHopDB(t)
	repo := NewAssetCoverageRepository(&DB{DB: db})
	ctx := context.Background()
	h, other := newHopTenant(t, db, 0), newHopTenant(t, db, 0)

	service := func(tenant shared.ID, name, props string) shared.ID {
		t.Helper()
		id := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, properties)
			VALUES ($1, $2, $3, 'service', 'http', $4::jsonb)`, id, tenant, name, props)
		return id
	}
	named := service(h.tenant, "https://app.example.com", `{"port": 443, "ip_addresses": ["203.0.113.10"]}`)
	twin := service(h.tenant, "https://203.0.113.10", `{"port": 443}`)
	otherPort := service(h.tenant, "https://203.0.113.10:8443", `{"port": 8443}`)
	alone := service(h.tenant, "http://203.0.113.20", `{"port": 80}`)
	service(other.tenant, "https://shop.example.net", `{"port": 443, "ip_addresses": ["203.0.113.30"]}`)
	foreignTwin := service(h.tenant, "https://203.0.113.30", `{"port": 443}`)

	var rules []coverage.Rule
	for _, r := range coverage.RulesFor(asset.AssetTypeService, "http") {
		if r.Capability == "vuln.templates" {
			rules = append(rules, r)
		}
	}
	if len(rules) != 1 {
		t.Fatalf("http service vuln.templates rules: %+v", rules)
	}
	state := func(id shared.ID) (string, string) {
		t.Helper()
		var st, reason string
		if err := db.QueryRowContext(ctx, `SELECT state, reason FROM asset_coverage
			WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'vuln.templates'`, h.tenant.String(), id.String()).Scan(&st, &reason); err != nil {
			t.Fatal(err)
		}
		return st, reason
	}
	if _, _, err := repo.Reconcile(ctx, h.tenant, rules); err != nil {
		t.Fatal(err)
	}
	if st, reason := state(twin); st != "not_applicable" || reason != coverage.RequiresNoNamedTwin {
		t.Fatalf("address twin: %s/%s, want not_applicable/%s", st, reason, coverage.RequiresNoNamedTwin)
	}
	for name, id := range map[string]shared.ID{"named": named, "other port": otherPort, "no twin": alone, "foreign twin": foreignTwin} {
		if st, _ := state(id); st != "due" {
			t.Errorf("%s: %s, want due", name, st)
		}
	}

	// The named service goes away: the address service is scanned again.
	hopExec(t, db, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, named)
	if _, _, err := repo.Reconcile(ctx, h.tenant, rules); err != nil {
		t.Fatal(err)
	}
	if st, _ := state(twin); st != "due" {
		t.Fatalf("address service after its twin left: %s, want due", st)
	}
}
