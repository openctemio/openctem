package integration

// Address rows of the review queue (RFC-054 §4.3): the names that resolve
// to an address, its stored network facts, and the sensor name in the
// evidence. Tenant-scoped and narrowed to the caller's data scope.

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReviewAddressStore(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	edge := func(tenant, src, dst shared.ID) {
		exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
			tenant.String(), src.String(), dst.String())
	}
	const addr = "202.160.124.20"
	ip := seedOwnedAsset(t, db, tenantA, addr, "ip_address")
	exec(`UPDATE assets SET properties = '{"asn": 131386, "asn_org": "VNDIRECT Securities Corporation"}' WHERE id = $1`, ip.String())
	apex := seedOwnedAsset(t, db, tenantA, "vndirect.com.vn", "domain")
	www := seedOwnedAsset(t, db, tenantA, "www.vndirect.com.vn", "subdomain")
	edge(tenantA, apex, ip)
	edge(tenantA, www, ip)
	// Tenant B has the same address and a name resolving to it.
	ipB := seedOwnedAsset(t, db, tenantB, addr, "ip_address")
	nameB := seedOwnedAsset(t, db, tenantB, "b-only.example.net", "domain")
	edge(tenantB, nameB, ipB)

	repo := postgres.NewAttributionRepository(&postgres.DB{DB: db})
	got, err := repo.ResolvedFrom(ctx, tenantA, nil, []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got[addr], []string{"vndirect.com.vn", "www.vndirect.com.vn"}) {
		t.Fatalf("resolved_from = %v (tenant B's name must not appear)", got[addr])
	}
	// A restricted member sees only the names in their data scope.
	member := seedActUser(t, db)
	grantScope(t, db, tenantA, member, www)
	got, err = repo.ResolvedFrom(ctx, tenantA, &member, []string{addr})
	if err != nil || !slices.Equal(got[addr], []string{"www.vndirect.com.vn"}) {
		t.Fatalf("restricted resolved_from = %v %v", got[addr], err)
	}
	props, err := repo.AddressProps(ctx, tenantA, []string{addr})
	if err != nil || props[addr]["asn_org"] != "VNDIRECT Securities Corporation" {
		t.Fatalf("props = %v %v", props, err)
	}

	// The evidence names the tenant's own sensor; another tenant's sensor is
	// never named.
	sensorA, sensorB := shared.NewID(), shared.NewID()
	for _, s := range []struct {
		id     shared.ID
		tenant shared.ID
		name   string
	}{{sensorA, tenantA, "edge-hanoi-01"}, {sensorB, tenantB, "b-secret-sensor"}} {
		exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix, created_at, updated_at)
			VALUES ($1, $2, $3, 'worker', 'active', 'online', $4, $5, now(), now())`,
			s.id.String(), s.tenant.String(), s.name, "hash-"+s.id.String(), "p-"+s.id.String()[:4])
	}
	automatic(t, db, tenantA, ip, attribution.StateNeedsReview)
	exec(`INSERT INTO easm_evidence (id, tenant_id, asset_id, rule, technique, source, weight, first_observed_at, observed)
		VALUES ($1, $2, $3, 'tenant_scan_discovered', 'scan', $4, 0.5, now(), '{}'),
		       ($5, $2, $3, 'tenant_scan_discovered', 'scan', $6, 0.5, now(), '{}')`,
		shared.NewID().String(), tenantA.String(), ip.String(), "sensor:"+sensorA.String(),
		shared.NewID().String(), "sensor:"+sensorB.String())
	page, err := repo.ListForReview(ctx, tenantA, nil, easm.ReviewQuery{
		States: []attribution.State{attribution.StateNeedsReview}, Limit: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, it := range page.Items {
		for _, e := range it.Evidence {
			labels[e.Source] = e.SourceLabel
		}
	}
	if labels["sensor:"+sensorA.String()] != "edge-hanoi-01" {
		t.Fatalf("own sensor label = %q", labels["sensor:"+sensorA.String()])
	}
	if l := labels["sensor:"+sensorB.String()]; l == "b-secret-sensor" || l == "" {
		t.Fatalf("another tenant's sensor label = %q", l)
	}
}
