package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/liveness"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// research/531 D6: a provider address (dependency, provider_shared_front_end)
// is out of the default inventory list and of every total, and listed only
// under its own filter; a name the provider serves (dependency for another
// reason) stays. Another tenant's provider address never counts. Requires
// DATABASE_URL.
func TestProviderAddressesLeaveInventoryAndTotals(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	add := func(tid shared.ID, name, typ, state, reason string) {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, is_internet_accessible)
			VALUES ($1, $2, $3, $4, 'active', true)`, id, tid.String(), name, typ); err != nil {
			t.Fatal(err)
		}
		if state != "" {
			if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason) VALUES ($1, $2, $3, 100, $4)`,
				id, tid.String(), state, reason); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(tenant, "www.example.com", "subdomain", "confirmed", "matches_scope_target")
	add(tenant, "cdn.example.com", "subdomain", "dependency", "tenant_scan_discovered") // served by a provider
	add(tenant, "198.51.100.5", "ip_address", "confirmed", "matches_scope_target")
	add(tenant, "13.107.128.10", "ip_address", "dependency", string(attribution.RuleProviderSharedFrontEnd))
	add(tenant, "3.11.53.20", "ip_address", "dependency", string(attribution.RuleProviderSharedFrontEnd))
	add(other, "13.107.128.11", "ip_address", "dependency", string(attribution.RuleProviderSharedFrontEnd))
	add(other, "198.51.100.9", "ip_address", "confirmed", "matches_scope_target")

	// Totals: the summary's surface counts and the attributed population.
	sum := NewEASMSummaryRepository(&DB{DB: db})
	for _, c := range []context.Context{ctx, shared.WithDiscoveredAssets(ctx)} {
		d, err := sum.Summary(c, tenant, nil, time.Now(), 5)
		if err != nil {
			t.Fatal(err)
		}
		if d.AssetsByType["ip_address"] != 1 || d.AssetsByType["subdomain"] != 2 {
			t.Fatalf("surface counts %v, want 1 address and 2 names", d.AssetsByType)
		}
		if d.AttributionByState["dependency"] != 3 {
			t.Fatalf("attribution counts %v: provider addresses must stay in their state's count", d.AttributionByState)
		}
	}

	// The inventory list: the default population leaves them out, the
	// provider_address filter lists only them, never another tenant's.
	repo := NewAssetRepository(&DB{DB: db})
	list := func(values ...string) []string {
		t.Helper()
		af, _, err := attribution.ParseFilter(values)
		if err != nil {
			t.Fatal(err)
		}
		f := asset.NewFilter().WithTenantID(tenant.String()).WithAttribution(af)
		res, err := repo.List(ctx, f, asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, a := range res.Data {
			names = append(names, a.Name())
		}
		return names
	}
	if got := list(attribution.FilterApproved); len(got) != 3 {
		t.Fatalf("default list = %v, want the two names and the dedicated address", got)
	}
	got := list(attribution.FilterProviderAddress)
	if len(got) != 2 {
		t.Fatalf("provider address filter = %v, want this tenant's two", got)
	}
	for _, n := range got {
		if n == "13.107.128.11" {
			t.Fatal("another tenant's provider address listed")
		}
	}

	// The inventory overview counts.
	rows, err := repo.GetInventoryOverview(ctx, tenant, asset.AccessScope{})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range rows {
		total += r.Total
	}
	if total != 3 {
		t.Fatalf("inventory overview total = %d, want 3", total)
	}
}

// research/531: an inventory search for an address finds the names that
// resolve or resolved to it (their set elements), never another tenant's;
// enrichment and liveness never take a provider address.
func TestProviderAddress_SearchEnrichmentLiveness(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	newAsset := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, tid.String(), name, typ); err != nil {
			t.Fatal(err)
		}
		return id
	}
	element := func(tid shared.ID, assetID, addr string, removed bool) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_attribute_set_elements (tenant_id, asset_id, attribute, source_kind, source_name, element, first_seen, last_seen, removed_at)
			VALUES ($1, $2, 'ip_addresses', 'scan', 'dnsx', $3, now() - interval '2 days', now() - interval '1 day', CASE WHEN $4 THEN now() ELSE NULL END)`,
			tid.String(), assetID, addr, removed); err != nil {
			t.Fatal(err)
		}
	}
	current := newAsset(tenant, "mail.example.com", "subdomain")
	past := newAsset(tenant, "old.example.com", "subdomain")
	newAsset(tenant, "unrelated.example.com", "subdomain")
	foreign := newAsset(other, "theirs.example.org", "subdomain")
	element(tenant, current, "13.107.128.10", false)
	element(tenant, past, "13.107.128.10", true)
	element(other, foreign, "13.107.128.10", false)

	repo := NewAssetRepository(&DB{DB: db})
	for _, q := range []string{"13.107.128.10", " 13.107.128.10 ", "::ffff:13.107.128.10"} {
		res, err := repo.List(ctx, asset.NewFilter().WithTenantID(tenant.String()).WithSearch(q), asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, a := range res.Data {
			got[a.Name()] = true
		}
		if len(got) != 2 || !got["mail.example.com"] || !got["old.example.com"] {
			t.Fatalf("search %q = %v, want the current and the past name only", q, got)
		}
	}

	// A provider address asset: no enrichment request, no liveness row.
	addr := newAsset(tenant, "13.107.128.10", "ip_address")
	own := newAsset(tenant, "198.51.100.5", "ip_address")
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason) VALUES ($1, $2, 'dependency', 100, $3)`,
		addr, tenant.String(), string(attribution.RuleProviderSharedFrontEnd)); err != nil {
		t.Fatal(err)
	}
	addrID, _ := shared.IDFromString(addr)
	ownID, _ := shared.IDFromString(own)
	n, err := NewAssetEnrichmentRequestRepository(&DB{DB: db}).Request(ctx, tenant, []shared.ID{addrID, ownID}, "new_asset", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("enrichment requested for %d assets, want only the dedicated one", n)
	}

	lrepo := NewAssetLivenessRepository(&DB{DB: db})
	obs := []liveness.AssetObservation{
		{AssetID: addrID, Observation: liveness.Observation{Kind: liveness.KindNoAnswer, Observer: "zone:a"}},
		{AssetID: ownID, Observation: liveness.Observation{Kind: liveness.KindNoAnswer, Observer: "zone:a"}},
	}
	if _, err := lrepo.Observe(ctx, tenant, obs, liveness.DefaultThresholds(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM asset_liveness WHERE tenant_id = $1 AND asset_id = $2`,
		tenant.String(), addr).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("liveness tracked a provider address")
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM asset_liveness WHERE tenant_id = $1 AND asset_id = $2`,
		tenant.String(), own).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("liveness of the dedicated address: %d rows, %v", rows, err)
	}
}
