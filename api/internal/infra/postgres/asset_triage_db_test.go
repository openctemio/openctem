package postgres

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Inventory triage (research/124, RFC-054 §15) on the real schema: the scope
// status filter (in scope, not covered, excluded, internal) follows the
// tenant's own entries and exclusions only; the discovery and confidence
// filters; the exclusion preview counts only the tenant's assets inside the
// caller's data scope; and a reset forgets a person's decision. Requires
// DATABASE_URL.
func TestAssetTriage(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: db}
	repo := NewAssetRepository(pg)
	attr := NewAttributionRepository(pg)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	add := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`, id, tid.String(), name, typ)
		return id
	}
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.tri.example.com', 'active'),
		($1, 'cidr', '198.51.100.0/24', 'active'), ($1, 'domain', 'gone.example.net', 'active')`, tenant.String())
	exec(`UPDATE scope_targets SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1 AND pattern = 'gone.example.net'`, tenant.String())
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		VALUES ($1, 'domain', 'skip.tri.example.com', 'test', 'active', 'a', now(), 'r')`, tenant.String())
	// The other tenant's entry covers a name this tenant only discovered.
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.theirs.example.org', 'active')`, other.String())

	inScope := add(tenant, "api.tri.example.com", "subdomain")
	svc := add(tenant, "api.tri.example.com:443:tcp", "service")
	addr := add(tenant, "198.51.100.9", "ip_address")
	notCovered := add(tenant, "cdn.theirs.example.org", "domain")
	expired := add(tenant, "gone.example.net", "domain")
	excluded := add(tenant, "skip.tri.example.com", "subdomain")
	rejected := add(tenant, "no.tri.example.com", "subdomain")
	internal := add(tenant, "10.0.0.5", "ip_address")
	repoAsset := add(tenant, "github.com/acme/app", "repository")
	add(other, "api.tri.example.com", "subdomain")
	if _, err := attr.SaveDecision(ctx, tenant, rejected, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}

	list := func(f asset.Filter) []string {
		t.Helper()
		res, err := repo.List(ctx, f.WithTenantID(tenant.String()), asset.NewListOptions(), pagination.New(1, 100))
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, a := range res.Data {
			ids = append(ids, a.ID().String())
		}
		sort.Strings(ids)
		return ids
	}
	want := func(ids ...string) []string { sort.Strings(ids); return ids }
	cases := map[string][]string{
		"in_scope":    want(inScope, svc, addr),
		"not_covered": want(notCovered, expired),
		"excluded":    want(excluded, rejected),
		"internal":    want(internal, repoAsset),
	}
	for status, w := range cases {
		if got := list(asset.Filter{ScopeStatuses: []string{status}}); !slices.Equal(got, w) {
			t.Errorf("scope_status=%s: %v, want %v", status, got, w)
		}
	}

	// Discovery and confidence filters.
	if err := attr.UpsertEvidence(ctx, tenant, []attribution.Evidence{
		{AssetID: notCovered, Rule: attribution.RuleScanDiscovered, Technique: "subfinder", Source: "scan:1", Weight: 0.6},
		{AssetID: inScope, Rule: attribution.RuleAssertedRoot, Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85},
	}); err != nil {
		t.Fatal(err)
	}
	if err := attr.SaveAutomatic(ctx, tenant, notCovered, attribution.Decision{State: attribution.StateNeedsReview, Confidence: 60, Reason: attribution.RuleScanDiscovered}); err != nil {
		t.Fatal(err)
	}
	if got := list(asset.Filter{DiscoveredBy: []string{"tenant_scan_discovered"}}); !slices.Equal(got, []string{notCovered}) {
		t.Errorf("discovered_by: %v", got)
	}
	if got := list(asset.Filter{DiscoveryTechniques: []string{"cert_transparency"}}); !slices.Equal(got, []string{inScope}) {
		t.Errorf("discovery_technique: %v", got)
	}
	maxC := 70
	if got := list(asset.Filter{MaxConfidence: &maxC}); !slices.Equal(got, want(notCovered, rejected)) {
		t.Errorf("max_confidence: %v (no record counts as 100, a person's decision as 0)", got)
	}
	since := time.Now().Add(-time.Hour)
	if got := list(asset.Filter{CreatedAfter: &since, ScopeStatuses: []string{"not_covered"}}); len(got) != 2 {
		t.Errorf("first_seen_after: %v", got)
	}

	// Exclusion preview: the tenant's assets only, narrowed to the data scope.
	cov := NewScopeCoverageRepository(pg)
	items := []scopeapp.BulkExclusionItem{{ExclusionType: "domain", Pattern: "*.tri.example.com"}, {ExclusionType: "cidr", Pattern: "198.51.100.0/24"}}
	m, err := cov.ExclusionMatches(ctx, tenant, nil, items)
	if err != nil {
		t.Fatal(err)
	}
	if m[0].Matched != 4 || m[1].Matched != 1 {
		t.Fatalf("matches = %+v", m)
	}
	restricted := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}
	if m, err = cov.ExclusionMatches(ctx, tenant, restricted, items); err != nil || m[0].Matched != 0 {
		t.Fatalf("a member without scope rows saw %+v (%v)", m, err)
	}
	if m, err = cov.ExclusionMatches(ctx, tenant, &shared.DataScope{TenantID: other, Unrestricted: true}, items); err != nil || m[0].Matched != 0 {
		t.Fatalf("a scope of another tenant saw %+v (%v)", m, err)
	}

	// Reset: a rejected name with evidence goes back to automatic, its
	// tombstone goes; without evidence the record goes; another tenant's
	// reset changes nothing.
	if err := attr.UpsertEvidence(ctx, tenant, []attribution.Evidence{
		{AssetID: rejected, Rule: attribution.RuleScanDiscovered, Technique: "subfinder", Source: "scan:1", Weight: 0.6}}); err != nil {
		t.Fatal(err)
	}
	if prev, err := attr.ResetDecisions(ctx, other, []string{rejected}); err != nil || len(prev) != 0 {
		t.Fatalf("cross-tenant reset: %v %v", prev, err)
	}
	prev, err := attr.ResetDecisions(ctx, tenant, []string{rejected, notCovered})
	if err != nil || len(prev) != 1 || prev[rejected] != attribution.StateRejected {
		t.Fatalf("reset = %v %v (only the person's decision is reset)", prev, err)
	}
	recs, _ := attr.Records(ctx, tenant, []string{rejected})
	if r := recs[rejected]; r.HumanDecided || r.State == attribution.StateRejected || r.State == "" {
		t.Fatalf("after reset: %+v", r)
	}
	if tomb, _ := attr.Tombstoned(ctx, tenant, []string{"no.tri.example.com"}); len(tomb) != 0 {
		t.Fatal("the tombstone stayed")
	}
	if _, err := attr.SaveDecision(ctx, tenant, internal, attribution.StateMonitorOnly, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := attr.ResetDecisions(ctx, tenant, []string{internal}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := attr.Records(ctx, tenant, []string{internal}); len(recs) != 0 {
		t.Fatalf("a record without evidence stayed: %v", recs)
	}
}
