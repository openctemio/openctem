package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The address auto add reads only tenants with an AS seed: a tenant with an
// organization-name seed alone, or none, is not listed, and each listed
// tenant appears once whatever its number of seeds.
func TestEASMNetworkSeedRepository_TenantsWithASNSeeds(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'seed-tenants', $2)`, id.String(), "st-"+id.String()[24:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	seed := func(tn shared.ID, kind, value string) {
		exec(`INSERT INTO easm_network_seeds (tenant_id, kind, value) VALUES ($1, $2, $3)`, tn.String(), kind, value)
	}
	withASN, orgOnly, none := tenant(), tenant(), tenant()
	seed(withASN, "asn", "AS64500")
	seed(withASN, "asn", "AS64501")
	seed(orgOnly, "org_name", "Example Org")

	got, err := NewEASMNetworkSeedRepository(&DB{DB: db}).TenantsWithASNSeeds(ctx, 100000)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, id := range got {
		count[id.String()]++
	}
	if count[withASN.String()] != 1 {
		t.Fatalf("tenant with two AS seeds listed %d times, want once", count[withASN.String()])
	}
	if count[orgOnly.String()] != 0 || count[none.String()] != 0 {
		t.Fatal("a tenant without an AS seed was listed")
	}

	// The auto add log is per tenant: what one tenant recorded is never seen
	// by another, and recording twice keeps one row.
	log := NewEASMAddressAutoAddRepository(&DB{DB: db})
	if err := log.Record(ctx, withASN, []string{"203.0.113.0/24", "203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Record(ctx, withASN, []string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	if seen, err := log.Seen(ctx, withASN, []string{"203.0.113.0/24", "198.51.100.1"}); err != nil || !seen["203.0.113.0/24"] || seen["198.51.100.1"] {
		t.Fatalf("own tenant: %v %v", seen, err)
	}
	if seen, err := log.Seen(ctx, orgOnly, []string{"203.0.113.0/24"}); err != nil || len(seen) != 0 {
		t.Fatalf("another tenant sees the log: %v %v", seen, err)
	}
}
