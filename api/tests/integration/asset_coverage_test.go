package integration

// Asset coverage (docs/rfcs/RFC-093-asset-coverage.md) on a migrated
// database: the ledger follows the registry's coverage policy for every
// asset (rows for every applicable rule, preconditions as not_applicable),
// reconciling is idempotent and re-evaluates preconditions, and the
// explanation is tenant- and data-scope-isolated.

import (
	"context"
	"errors"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type covRig struct {
	t      *testing.T
	r      *v2Rig
	repo   *postgres.AssetCoverageRepository
	svc    *coverageapp.Service
	assets *assetapp.AssetService
}

func newCovRig(t *testing.T) *covRig {
	t.Helper()
	g := &covRig{t: t}
	g.r = newV2RigWith(t, ingest.DefaultBlindingGuard(), func(_ *ingest.Service, db *postgres.DB) {
		g.repo = postgres.NewAssetCoverageRepository(db)
		g.svc = coverageapp.NewService(g.repo, logger.NewNop())
		g.assets = assetapp.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
		g.assets.SetCoverage(g.repo)
	})
	return g
}

func (g *covRig) asset(tn v2Tenant, name, typ, sub, props string) shared.ID {
	g.t.Helper()
	id := shared.NewID()
	var subArg any
	if sub != "" {
		subArg = sub
	}
	if props == "" {
		props = "{}"
	}
	if _, err := g.r.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, properties) VALUES ($1, $2, $3, $4, $5, $6)`,
		id.String(), tn.tenant.String(), name, typ, subArg, props); err != nil {
		g.t.Fatalf("seed %s: %v", name, err)
	}
	return id
}

func (g *covRig) rel(tn v2Tenant, src, dst shared.ID, typ string) {
	g.t.Helper()
	if _, err := g.r.db.Exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, $4)`,
		tn.tenant.String(), src.String(), dst.String(), typ); err != nil {
		g.t.Fatal(err)
	}
}

func (g *covRig) states(tn v2Tenant, id shared.ID) map[string]string {
	g.t.Helper()
	rows, err := g.repo.ListForAsset(context.Background(), tn.tenant, id)
	if err != nil {
		g.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Capability] = string(r.State) + ":" + r.Reason
	}
	return out
}

func TestAssetCoverage_ReconcileFollowsPolicy(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	b := g.r.newTenant()

	if _, err := g.r.db.Exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.cov.test')`, a.tenant.String()); err != nil {
		t.Fatal(err)
	}
	apex := g.asset(a, "cov.test", "domain", "", "")
	foreign := g.asset(a, "other.test", "domain", "", "")
	live := g.asset(a, "www.cov.test", "subdomain", "", "")
	dead := g.asset(a, "old.cov.test", "subdomain", "", "")
	ip := g.asset(a, "203.0.113.20", "ip_address", "", "")
	g.rel(a, live, ip, "resolves_to")
	// A name resolved by DNS only (records stored, no relation yet).
	byDNS := g.asset(a, "dns.cov.test", "subdomain", "",
		`{"dns_records": [{"name": "dns.cov.test", "type": "A", "value": "203.0.113.21"}]}`)
	cnameOnly := g.asset(a, "alias.cov.test", "subdomain", "",
		`{"dns_records": [{"name": "alias.cov.test", "type": "CNAME", "value": "gone.cov.test"}]}`)
	web := g.asset(a, "203.0.113.20:443:tcp", "service", "open_port", `{"port": 443}`)
	ssh := g.asset(a, "203.0.113.20:22:tcp", "service", "open_port", `{"port": 22}`)
	origin := g.asset(a, "https://www.cov.test", "service", "http", "")
	bOnly := g.asset(b, "www.cov.test", "subdomain", "", "")

	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id   shared.ID
		cap_ string
		want string
	}{
		{apex, "discover.subdomains", "due:"},
		{apex, "resolve.dns", "due:"},
		{foreign, "discover.subdomains", "not_applicable:scope_entry"},
		{foreign, "resolve.dns", "due:"},
		{live, "probe.http", "due:"},
		{live, "scan.ports", "due:"},
		{dead, "probe.http", "not_applicable:resolves"},
		{dead, "resolve.dns", "due:"},
		{ip, "scan.ports", "due:"},
		{web, "probe.http", "due:"},
		{ssh, "probe.http", "not_applicable:web_port"},
		{origin, "vuln.templates", "due:"},
		{byDNS, "probe.http", "due:"},
		{cnameOnly, "probe.http", "not_applicable:resolves"},
	} {
		if got := g.states(a, c.id)[c.cap_]; got != c.want {
			t.Errorf("%s %s = %q, want %q", c.id, c.cap_, got, c.want)
		}
	}
	if n := len(g.states(a, ip)); n != 2 {
		t.Errorf("address rows = %d, want 2 (lookup.asn, scan.ports)", n)
	}
	// Tenant isolation: reconciling A writes nothing for B.
	if s := g.states(b, bOnly); len(s) != 0 {
		t.Errorf("tenant B got rows from A's reconcile: %v", s)
	}
	if rows, _ := g.repo.ListForAsset(ctx, b.tenant, live); len(rows) != 0 {
		t.Error("tenant B lists A's coverage rows")
	}

	// Idempotent: a second pass adds and changes nothing.
	if n, err := g.svc.RunTenant(ctx, a.tenant); err != nil || n != 0 {
		t.Fatalf("second pass changed %d rows (%v)", n, err)
	}
	// A precondition that starts to hold makes the pair due; one that stops
	// holding makes it not applicable.
	g.rel(a, dead, ip, "resolves_to")
	if _, err := g.r.db.Exec(`DELETE FROM asset_relationships WHERE source_asset_id = $1`, live.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if got := g.states(a, dead)["probe.http"]; got != "due:" {
		t.Errorf("newly resolving name probe.http = %q", got)
	}
	if got := g.states(a, live)["probe.http"]; got != "not_applicable:resolves" {
		t.Errorf("no longer resolving name probe.http = %q", got)
	}

	// The explanation: one entry per rule, rows the policy does not list
	// (none here), never-planned rules shown as such.
	v, err := g.assets.GetCoverage(ctx, a.tenant.String(), web.String())
	if err != nil || len(v.Entries) != 1 || v.Entries[0].Capability != "probe.http" || v.Entries[0].State != coverage.StateDue {
		t.Fatalf("explanation = %+v, %v", v, err)
	}
	// Another tenant, and a member outside the data scope, get not found.
	if _, err := g.assets.GetCoverage(ctx, b.tenant.String(), web.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant read coverage: %v", err)
	}
	pg := &postgres.DB{DB: g.r.db}
	g.assets.SetDataScope(datascope.New(postgres.NewDataScopeRepository(pg), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop()))
	member := seedActUser(t, g.r.db)
	if _, err := g.assets.GetCoverage(asCaller(ctx, datascope.Caller{UserID: member.String()}), a.tenant.String(), web.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope member read coverage: %v", err)
	}
}
