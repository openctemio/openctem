package postgres

// Domain membership and the findings asset filters against a real database
// (docs/architecture/asset-domain-membership.md): asset_domain reaches every
// asset kind that belongs to the domain (a name, the address it resolves to,
// the service on that address, a certificate, a web application), never a
// CDN or shared-hosting address, never another tenant's assets; *.x leaves
// x out; an edge removal drops the dependents; asset_name patterns escape
// LIKE metacharacters; asset_type narrows by the stored type. Skipped unless
// DATABASE_URL names a migrated test database.

import (
	"context"
	"net/url"
	"sort"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

type domainFixture struct {
	db      *DB
	repo    *AssetDomainMembershipRepository
	tenant  shared.ID
	other   shared.ID
	byTitle map[string]string // finding title -> asset id
}

func (fx *domainFixture) asset(t *testing.T, tenant shared.ID, typ, name, props, title string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := fx.db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type, properties) VALUES ($1, $2, $3, $4::jsonb) RETURNING id::text`,
		tenant.String(), name, typ, props).Scan(&id); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	if title != "" {
		if _, err := fx.db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, message, tool_name, source, fingerprint, severity, title)
			VALUES ($1, $2::uuid, 'm', 'nuclei', 'dast', md5($4), 'high', $3)`, tenant.String(), id, title, id+title); err != nil {
			t.Fatalf("seed finding %s: %v", title, err)
		}
		if tenant == fx.tenant {
			fx.byTitle[title] = id
		}
	}
	return id
}

func (fx *domainFixture) edge(t *testing.T, tenant shared.ID, src, typ, dst string) {
	t.Helper()
	if _, err := fx.db.ExecContext(context.Background(), `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, $4)`,
		tenant.String(), src, dst, typ); err != nil {
		t.Fatalf("seed edge %s: %v", typ, err)
	}
}

func (fx *domainFixture) drain(t *testing.T) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		res, err := fx.repo.ProcessQueue(context.Background(), 500)
		if err != nil {
			t.Fatalf("process queue: %v", err)
		}
		if res.Claimed == 0 {
			return
		}
	}
	t.Fatal("queue did not drain")
}

// titles lists the tenant's findings matching the flat params, as a
// restricted-free member of the tenant.
func (fx *domainFixture) titles(t *testing.T, params url.Values) []string {
	t.Helper()
	spec, err := filterspec.ParseValues(params, vulnerability.FindingFields, filterspec.Options{})
	if err != nil {
		t.Fatalf("parse %v: %v", params, err)
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: fx.tenant, UserID: shared.NewID(), IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		t.Fatalf("compile %v: %v", params, err)
	}
	return queryTitles(t, fx.db, w)
}

// queryTitles runs a compiled findings filter and returns the titles, sorted.
func queryTitles(t *testing.T, db *DB, w *filterspec.Where) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT title FROM findings WHERE "+w.SQL, w.Args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func sameTitles(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}

func newDomainFixture(t *testing.T) *domainFixture {
	t.Helper()
	db := openRoleRaceDB(t)
	ctx := context.Background()
	fx := &domainFixture{db: db, repo: NewAssetDomainMembershipRepository(db), byTitle: map[string]string{}}
	fx.tenant, fx.other = seedTenant(ctx, t, db), seedTenant(ctx, t, db)
	a, b := fx.tenant, fx.other

	api := fx.asset(t, a, "subdomain", "api.example.com.vn", `{}`, "api")
	fx.asset(t, a, "domain", "example.com.vn", `{}`, "apex")
	ip := fx.asset(t, a, "ip_address", "203.0.113.10", `{}`, "ip")
	svc := fx.asset(t, a, "service", "203.0.113.10:443:tcp", `{}`, "svc-on-ip")
	fx.edge(t, a, api, "resolves_to", ip)
	fx.edge(t, a, ip, "exposes", svc)

	// A CDN edge address: a member's name resolves to it, it is never a member.
	www := fx.asset(t, a, "subdomain", "www.example.com.vn", `{}`, "")
	cdn := fx.asset(t, a, "ip_address", "104.16.1.1", `{}`, "cdn-ip")
	cdnSvc := fx.asset(t, a, "service", "104.16.1.1:443:tcp", `{}`, "svc-on-cdn")
	fx.edge(t, a, www, "resolves_to", cdn)
	fx.edge(t, a, cdn, "exposes", cdnSvc)

	// Shared hosting: names of three registrable domains resolve to it.
	shared := fx.asset(t, a, "ip_address", "198.51.100.7", `{}`, "shared-ip")
	for _, n := range []string{"a.example.com.vn", "b.other-one.com", "c.other-two.org"} {
		fx.edge(t, a, fx.asset(t, a, "subdomain", n, `{}`, ""), "resolves_to", shared)
	}

	fx.asset(t, a, "certificate", "ab12cd34", `{"subject_cn":"*.example.com.vn","sans":["*.example.com.vn","EXAMPLE.com.vn"]}`, "cert")
	fx.asset(t, a, "application", "https://portal.example.com.vn/login", `{}`, "app")
	fx.asset(t, a, "repository", "github.com/example/app", `{}`, "repo")
	fx.asset(t, a, "subdomain", "xn--v-bga.example.com.vn", `{}`, "puny")
	fx.asset(t, a, "subdomain", "100%_off.example.org", `{}`, "pct")
	fx.asset(t, a, "subdomain", "100ab.example.org", `{}`, "noesc")
	fx.asset(t, a, "subdomain", "example.com.vn.evil.example", `{}`, "lookalike")

	// Tenant B holds the same names: never part of A's answers.
	bAPI := fx.asset(t, b, "subdomain", "api.example.com.vn", `{}`, "b-api")
	bIP := fx.asset(t, b, "ip_address", "203.0.113.10", `{}`, "b-ip")
	fx.edge(t, b, bAPI, "resolves_to", bIP)
	// An edge row of tenant A whose source is tenant B's name (corrupt or
	// forged data): A's address must not inherit B's name.
	bName := fx.asset(t, b, "subdomain", "x.example.com.vn", `{}`, "")
	aIP := fx.asset(t, a, "ip_address", "203.0.113.99", `{}`, "ip-via-other-tenant")
	if _, err := fx.db.ExecContext(context.Background(), `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		a.String(), bName, aIP); err != nil {
		t.Logf("cross-tenant edge refused by the schema: %v", err)
	}

	fx.drain(t)
	return fx
}

func TestAssetDomainFilterReachesEveryKind(t *testing.T) {
	fx := newDomainFixture(t)
	all := []string{"api", "apex", "ip", "svc-on-ip", "cert", "app", "puny"}
	sameTitles(t, "asset_domain=example.com.vn", fx.titles(t, url.Values{"asset_domain": {"example.com.vn"}}), all...)
	sameTitles(t, "upper case, trailing dot", fx.titles(t, url.Values{"asset_domain": {"Example.COM.vn."}}), all...)
	sameTitles(t, "*.x leaves x out", fx.titles(t, url.Values{"asset_domain": {"*.example.com.vn"}}),
		"api", "ip", "svc-on-ip", "app", "puny")
	sameTitles(t, "a unicode label matches its punycode", fx.titles(t, url.Values{"asset_domain": {"vé.example.com.vn"}}), "puny")
	sameTitles(t, "not in", fx.titles(t, url.Values{"asset_domain_not": {"example.com.vn"}, "asset_type": {"ip_address"}}),
		"cdn-ip", "shared-ip", "ip-via-other-tenant")
	var foreign int
	if err := fx.db.QueryRowContext(context.Background(), `SELECT count(*) FROM asset_domain_memberships m JOIN assets x ON x.id = m.asset_id
		WHERE m.tenant_id IN ($1, $2) AND x.tenant_id <> m.tenant_id`, fx.tenant.String(), fx.other.String()).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatalf("membership rows of another tenant's asset: %d (%v)", foreign, err)
	}
}

func TestAssetDomainEdgeRemovalDropsDependents(t *testing.T) {
	fx := newDomainFixture(t)
	ctx := context.Background()
	if _, err := fx.db.ExecContext(ctx, `DELETE FROM asset_relationships WHERE tenant_id = $1 AND target_asset_id = $2 AND relationship_type = 'resolves_to'`,
		fx.tenant.String(), fx.byTitle["ip"]); err != nil {
		t.Fatal(err)
	}
	fx.drain(t)
	sameTitles(t, "after the name stopped resolving", fx.titles(t, url.Values{"asset_domain": {"*.example.com.vn"}}), "api", "app", "puny")
	// A rename moves the name out of the domain.
	if _, err := fx.db.ExecContext(ctx, `UPDATE assets SET name = 'api.elsewhere.example' WHERE id = $1`, fx.byTitle["api"]); err != nil {
		t.Fatal(err)
	}
	fx.drain(t)
	sameTitles(t, "after a rename", fx.titles(t, url.Values{"asset_domain": {"*.example.com.vn"}}), "app", "puny")
}

func TestAssetDomainRefusesPublicSuffix(t *testing.T) {
	for _, v := range []string{"com.vn", "com", "*.com", "10.0.0.1", "a b.com", ""} {
		if _, err := filterspec.ParseValues(url.Values{"asset_domain": {v}}, vulnerability.FindingFields, filterspec.Options{}); err == nil && v != "" {
			t.Errorf("asset_domain=%q accepted", v)
		}
	}
}

func TestAssetNameAndTypeFilters(t *testing.T) {
	fx := newDomainFixture(t)
	sameTitles(t, "LIKE metacharacters are literal", fx.titles(t, url.Values{"asset_name": {"100%_*"}}), "pct")
	sameTitles(t, "glob", fx.titles(t, url.Values{"asset_name": {"*.example.com.vn"}}), "api", "puny")
	sameTitles(t, "type", fx.titles(t, url.Values{"asset_type": {"certificate,repository"}}), "cert", "repo")
	sameTitles(t, "type not", fx.titles(t, url.Values{"asset_type_not": {"subdomain,ip_address,service"}}), "apex", "cert", "app", "repo")
}

// A restricted member sees only the findings of assets in their data scope:
// the domain filter never widens it, even though the service's membership
// comes from a name and an address outside the scope.
func TestAssetDomainFilterKeepsDataScope(t *testing.T) {
	fx := newDomainFixture(t)
	ctx := context.Background()
	user := seedUser(ctx, t, fx.db)
	if _, err := fx.db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), fx.tenant.String(), fx.byTitle["svc-on-ip"]); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	spec, err := filterspec.ParseValues(url.Values{"asset_domain": {"example.com.vn"}}, vulnerability.FindingFields, filterspec.Options{})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: fx.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: fx.tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		t.Fatal(err)
	}
	got := queryTitles(t, fx.db, w)
	sameTitles(t, "restricted member", got, "svc-on-ip")
}
