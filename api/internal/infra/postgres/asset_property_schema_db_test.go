package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IP lookups read ip_addresses and every synonym of it (RFC-042 §6.3.9), so
// a row written before the property normalisation is still found; they
// never cross tenants. And a resolves_to edge seen again moves its
// last_verified forward without touching another tenant's edge.
func TestAssetPropertySchema_IPLookupsAndEdgeRefresh(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	pdb := &DB{DB: db}
	repo := NewAssetRepository(pdb)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	suffix := shared.NewID().String()[:8]

	insert := func(tn shared.ID, name, typ, props string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, properties)
			VALUES ($1, $2, $3, $4, 'active', $5::jsonb)`, id.String(), tn.String(), name, typ, props); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
		return id
	}
	canonical := insert(tenant, "canon-"+suffix, "host", `{"ip_addresses": ["10.251.0.1"]}`)
	legacyIP := insert(tenant, "legacy-ip-"+suffix, "host", `{"ip": "10.251.0.2"}`)
	legacyList := insert(tenant, "legacy-list-"+suffix, "host", `{"resolved_ips": ["10.251.0.3"]}`)
	block := insert(tenant, "block-"+suffix, "host", `{"ip_address": {"address": "10.251.0.4"}}`)
	foreign := insert(other, "foreign-"+suffix, "host", `{"ip_addresses": ["10.251.0.5"]}`)

	for ip, want := range map[string]shared.ID{
		"10.251.0.1": canonical, "10.251.0.2": legacyIP, "10.251.0.3": legacyList, "10.251.0.4": block,
	} {
		a, err := repo.FindByIP(ctx, tenant, ip)
		if err != nil || a == nil || a.ID() != want {
			t.Errorf("FindByIP(%s) = %v, %v; want %s", ip, a, err, want)
		}
		byIPs, err := repo.FindByIPs(ctx, tenant, []string{ip})
		if err != nil || len(byIPs[ip]) != 1 || byIPs[ip][0].ID() != want {
			t.Errorf("FindByIPs(%s) = %v, %v", ip, byIPs, err)
		}
	}
	// Another tenant's address is never found.
	if a, err := repo.FindByIP(ctx, tenant, "10.251.0.5"); err != nil || a != nil {
		t.Errorf("FindByIP crossed tenants: %v, %v", a, err)
	}
	if byIPs, err := repo.FindByIPs(ctx, tenant, []string{"10.251.0.5"}); err != nil || len(byIPs["10.251.0.5"]) != 0 {
		t.Errorf("FindByIPs crossed tenants: %v, %v", byIPs, err)
	}
	if a, err := repo.FindByIP(ctx, other, "10.251.0.5"); err != nil || a == nil || a.ID() != foreign {
		t.Errorf("other tenant FindByIP = %v, %v", a, err)
	}

	// Edges: an insert counts, a repeat without a newer sighting is a no-op,
	// a repeat with one refreshes last_verified.
	rels := NewAssetRelationshipRepository(pdb)
	dom := insert(tenant, "dom-"+suffix+".example.com", "domain", `{}`)
	ipA := insert(tenant, "10.251.0.9", "ip_address", `{}`)
	otherDom := insert(other, "dom-"+suffix+".example.com", "domain", `{}`)
	otherIP := insert(other, "10.251.0.9", "ip_address", `{}`)
	edge := func(tn, src, dst shared.ID, verify bool) *asset.Relationship {
		r, err := asset.NewRelationship(tn, src, dst, asset.RelTypeResolvesTo)
		if err != nil {
			t.Fatal(err)
		}
		if verify {
			r.Verify()
		}
		return r
	}
	if n, err := rels.CreateBatchIgnoreConflicts(ctx, []*asset.Relationship{edge(tenant, dom, ipA, true), edge(other, otherDom, otherIP, true)}); err != nil || n != 2 {
		t.Fatalf("insert: %d, %v", n, err)
	}
	lastVerified := func(src shared.ID) time.Time {
		t.Helper()
		var v time.Time
		if err := db.QueryRowContext(ctx, `SELECT last_verified FROM asset_relationships WHERE source_asset_id = $1`, src.String()).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	first, otherFirst := lastVerified(dom), lastVerified(otherDom)
	if n, err := rels.CreateBatchIgnoreConflicts(ctx, []*asset.Relationship{edge(tenant, dom, ipA, false)}); err != nil || n != 0 {
		t.Fatalf("repeat without a sighting: %d, %v", n, err)
	}
	if !lastVerified(dom).Equal(first) {
		t.Error("a repeat without a sighting changed last_verified")
	}
	time.Sleep(5 * time.Millisecond)
	if n, err := rels.CreateBatchIgnoreConflicts(ctx, []*asset.Relationship{edge(tenant, dom, ipA, true)}); err != nil || n != 0 {
		t.Fatalf("repeat with a sighting: %d, %v", n, err)
	}
	if !lastVerified(dom).After(first) {
		t.Error("a new sighting did not refresh last_verified")
	}
	if !lastVerified(otherDom).Equal(otherFirst) {
		t.Error("another tenant's edge changed")
	}
}

// Facets carry the property schema's label, the one the detail view shows.
func TestFormatPropertyLabel_UsesTheSchema(t *testing.T) {
	for key, want := range map[string]string{
		"ip_addresses":    "IP addresses",
		"asn_org":         "ASN organization",
		"vendor_firmware": "Vendor Firmware",
	} {
		if got := formatPropertyLabel(key); got != want {
			t.Errorf("formatPropertyLabel(%q) = %q, want %q", key, got, want)
		}
	}
}
