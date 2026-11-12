package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Hosting facts against the real schema: the asset's own facts, and the CNAME
// targets of the tenant's names that resolve to an address; another tenant's
// names never count. Requires DATABASE_URL.
func TestSoftwareMatchRepository_HostingFacts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewSoftwareMatchRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	ins := func(tn shared.ID, name, typ, props string) shared.ID {
		id := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, properties) VALUES ($1, $2, $3, $4, 'active', $5::jsonb)`,
			id.String(), tn.String(), name, typ, props); err != nil {
			t.Fatal(err)
		}
		return id
	}
	svc := ins(tenant, "203.0.113.114:22/tcp", "service", `{"cdn":""}`)
	ins(tenant, "promo.acme.example", "subdomain", `{"cname_target":"dns.ladipage.com","ip_addresses":["203.0.113.114"]}`)
	ins(tenant, "unrelated.acme.example", "subdomain", `{"ip_addresses":["198.51.100.1"]}`)
	ins(other, "theirs.example", "subdomain", `{"ip_addresses":["203.0.113.114"]}`)
	web := ins(tenant, "https://shop.acme.example", "service", `{"host":"shop.acme.example","cname_target":"x.cdn.example","ip_addresses":["198.51.100.9"],"cdn":"cloudflare"}`)
	theirSvc := ins(other, "203.0.113.114:22/tcp", "service", `{}`)

	facts, err := r.HostingFacts(ctx, tenant, []shared.ID{svc, web, theirSvc})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := facts[theirSvc]; ok {
		t.Fatal("another tenant's asset read")
	}
	f := facts[svc]
	if len(f.NameCNAMEs) != 1 || f.NameCNAMEs[0] != "dns.ladipage.com" {
		t.Fatalf("names reaching the address = %v (another tenant's name must not count)", f.NameCNAMEs)
	}
	w := facts[web]
	if w.Host != "shop.acme.example" || w.CNAME != "x.cdn.example" || w.CDN != "cloudflare" || len(w.Addresses) != 1 {
		t.Fatalf("web facts = %+v", w)
	}
}
