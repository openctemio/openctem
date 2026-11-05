package postgres

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

func (f *webFixture) httpOrigin(t *testing.T, tenant shared.ID, name string) shared.ID {
	t.Helper()
	id := f.origin
	if name != "https://a.example.com" || tenant != f.tenant {
		id = f.seedOrigin(t, tenant, name)
	}
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE assets SET sub_type = 'http' WHERE tenant_id = $1 AND id = $2`, tenant.String(), id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

// SECURITY: the ledger is the one record every caller of path discovery
// claims. A second claim of an origin within 30 days is refused whoever
// asks; the daily budget sums the grants and the per-host budget of a run
// is shared by its origins on a host; another organization's origins,
// scope entries and grants never count; the facts the gate reads (scope
// entry, edge, inventory) come from the organization's own rows.
func TestWebPathLedger_ClaimsAndFacts(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	repo := NewWebPathLedgerRepository(f.db)
	other := seedTestTenant(ctx, t, f.sqlDB)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	a := f.httpOrigin(t, f.tenant, "https://a.example.com")
	a8 := f.httpOrigin(t, f.tenant, "https://a.example.com:8443")
	b := f.httpOrigin(t, f.tenant, "https://b.example.com")
	_ = a
	_ = a8
	_ = b
	f.httpOrigin(t, other, "https://a.example.com") // another organization's origin of the same name
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.example.com', 'active')`, f.tenant.String())
	f.record(t, f.tenant, a, obs(t, ctis.Endpoint{Origin: "https://a.example.com", Path: "/index.php", StatusCode: 200}))

	facts, err := repo.PathOriginFacts(ctx, f.tenant, []string{"https://a.example.com", "https://b.example.com", "https://missing.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	fa, fb := facts["https://a.example.com"], facts["https://b.example.com"]
	if _, ok := facts["https://missing.example.com"]; ok || len(facts) != 2 {
		t.Fatalf("facts %v: an origin the organization does not have is present", facts)
	}
	if !fa.ScopeEntry || !fa.InventoryChanged || !fa.EdgeClear || fa.AssetID != a || fa.Host != "a.example.com" || !fa.LastDispatch.IsZero() {
		t.Fatalf("a: %+v", fa)
	}
	if !fb.ScopeEntry || fb.InventoryChanged {
		t.Fatalf("b has no endpoint: %+v", fb)
	}
	// Another organization has no scope entry: its same-named origin is not in scope for it.
	of, err := repo.PathOriginFacts(ctx, other, []string{"https://a.example.com"})
	if err != nil || of["https://a.example.com"].ScopeEntry {
		t.Fatalf("another organization's facts %+v %v: this organization's scope entry counted", of, err)
	}
	if of["https://a.example.com"].AssetID == a {
		t.Fatal("another organization's origin resolved to this organization's asset")
	}

	run := shared.NewID()
	claim := func(origin string, run *shared.ID, requested, perHost, daily int) (int, string) {
		t.Helper()
		g, why, err := repo.ClaimPathOrigin(ctx, coverage.PathClaim{TenantID: f.tenant, Origin: origin, RunID: run,
			Requested: requested, PerHost: perHost, Daily: daily})
		if err != nil {
			t.Fatal(err)
		}
		return g, why
	}
	if g, why := claim("https://a.example.com", &run, 300, 300, 640); g != 300 || why != "" {
		t.Fatalf("first claim %d %q", g, why)
	}
	// The same origin from any caller: refused within 30 days.
	if g, why := claim("https://a.example.com", nil, 300, 300, 640); g != 0 || why != coverage.ReasonPathRanRecently {
		t.Fatalf("second claim %d %q", g, why)
	}
	// Another port of the host in the same run: the run's host budget is spent.
	if g, why := claim("https://a.example.com:8443", &run, 300, 300, 640); g != 0 || why != coverage.ReasonHostBudgetSpent {
		t.Fatalf("host budget: %d %q", g, why)
	}
	// The daily budget holds 640: 340 are left for the next origin, then 40 are under the smallest grant.
	if g, why := claim("https://b.example.com", &run, 300, 300, 640); g != 300 || why != "" {
		t.Fatalf("b: %d %q", g, why)
	}
	if g, why := claim("https://a.example.com:8443", nil, 300, 300, 640); g != 0 || why != coverage.ReasonDailyBudgetSpent {
		t.Fatalf("daily: %d %q (40 left is under the smallest grant)", g, why)
	}
	// Not an origin of the organization.
	if g, why := claim("https://missing.example.com", nil, 300, 300, 640); g != 0 || why != coverage.ReasonNotAnOrigin {
		t.Fatalf("missing: %d %q", g, why)
	}
	granted, err := repo.PathRequestsGrantedSince(ctx, f.tenant, f.nowMinusDay())
	if err != nil || granted != 600 {
		t.Fatalf("granted %d %v, want 600", granted, err)
	}
	// Another organization's grants never count for this one, nor this one's for it.
	if og, err := repo.PathRequestsGrantedSince(ctx, other, f.nowMinusDay()); err != nil || og != 0 {
		t.Fatalf("another organization's grants %d %v", og, err)
	}
	if g, why := func() (int, string) {
		g, why, err := repo.ClaimPathOrigin(ctx, coverage.PathClaim{TenantID: other, Origin: "https://a.example.com", Requested: 300, PerHost: 300, Daily: 640})
		if err != nil {
			t.Fatal(err)
		}
		return g, why
	}(); g != 300 || why != "" {
		t.Fatalf("another organization's claim of the same name: %d %q, want its own", g, why)
	}
	// The last dispatch shows in the facts; inventory seen before it is no change.
	facts, _ = repo.PathOriginFacts(ctx, f.tenant, []string{"https://a.example.com"})
	if facts["https://a.example.com"].LastDispatch.IsZero() || facts["https://a.example.com"].InventoryChanged {
		t.Fatalf("after the claim: %+v", facts["https://a.example.com"])
	}
	// An edge that challenged the last probe, in the facts.
	exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome) VALUES ($1, $2, 'probe.http', 'failed', 'edge_blocked')`, f.tenant.String(), b.String())
	facts, _ = repo.PathOriginFacts(ctx, f.tenant, []string{"https://b.example.com"})
	if facts["https://b.example.com"].EdgeClear {
		t.Fatal("an edge-blocked origin reads as clear")
	}
}

func (f *webFixture) nowMinusDay() time.Time { return time.Now().Add(-24 * time.Hour) }

// Path discovery's own guesses are not the organization's inventory: a path
// only guesses found, on two origins, is not a sibling path offered to a
// third, and an origin's own guess is not an input of its own list. The
// counts are reused between claims, and per tenant.
func TestWebDiscoveryDerivedInput_GuessesAreNotInputs(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	repo := NewWebDiscoveryRepository(f.db)
	a := f.httpOrigin(t, f.tenant, "https://a.example.com")
	b := f.httpOrigin(t, f.tenant, "https://b.example.com")
	c := f.httpOrigin(t, f.tenant, "https://c.example.com")
	d := f.httpOrigin(t, f.tenant, "https://d.example.com")
	crawl := func(origin, path string) webendpoint.Observation {
		return obs(t, ctis.Endpoint{Origin: origin, Path: path, StatusCode: 200})
	}
	f.record(t, f.tenant, a, crawl("https://a.example.com", "/real"))
	f.record(t, f.tenant, b, crawl("https://b.example.com", "/shared-real"))
	f.record(t, f.tenant, c, crawl("https://c.example.com", "/shared-real"))
	f.record(t, f.tenant, d, crawl("https://d.example.com", "/only-here"))
	// Guesses: /guessed on b and c, /own-guess on a.
	for _, o := range []struct {
		id        shared.ID
		origin, p string
	}{{b, "https://b.example.com", "/guessed"}, {c, "https://c.example.com", "/guessed"}, {a, "https://a.example.com", "/own-guess"}} {
		if _, err := f.sqlDB.ExecContext(ctx, `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, kind, auth_state, sources)
			VALUES (gen_random_uuid(), $1, $2, 'GET', $3::text, md5('GET' || $3::text), md5($3::text), 'page', 'unknown', '{guess}')`, f.tenant.String(), o.id.String(), o.p); err != nil {
			t.Fatal(err)
		}
	}
	in, err := repo.DerivedInput(ctx, f.tenant, "https://a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range in.Own {
		if r.Template == "/own-guess" {
			t.Fatalf("an origin's own guess is an input of its list: %+v", in.Own)
		}
	}
	if len(in.Own) != 1 || in.Own[0].Template != "/real" {
		t.Fatalf("own %+v", in.Own)
	}
	var sib []string
	for _, s := range in.Siblings {
		sib = append(sib, s.Template)
	}
	if strings.Join(sib, ",") != "/shared-real" {
		t.Fatalf("siblings %v, want only /shared-real (a guess on two origins is not served by the organization)", sib)
	}
	// The counts are reused: a path another origin serves from now on is not
	// seen until the cache expires; the organization's counts stay its own.
	f.record(t, f.tenant, d, crawl("https://d.example.com", "/shared-real"))
	in2, _ := repo.DerivedInput(ctx, f.tenant, "https://a.example.com")
	if len(in2.Siblings) != 1 || in2.Siblings[0].Origins != 2 {
		t.Fatalf("cached siblings %+v", in2.Siblings)
	}
	fresh, _ := NewWebDiscoveryRepository(f.db).DerivedInput(ctx, f.tenant, "https://a.example.com")
	if len(fresh.Siblings) != 1 || fresh.Siblings[0].Origins != 3 {
		t.Fatalf("fresh siblings %+v", fresh.Siblings)
	}
}

// The lookups path discovery makes on every claim use their indexes: the
// origin by name (expression index) and the organization's endpoints. Seeded
// with enough rows that a sequential scan would not be chosen.
func TestWebPathDiscovery_LookupsUseIndexes(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	if _, err := f.sqlDB.ExecContext(ctx, `
		INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status, exposure)
		SELECT gen_random_uuid(), $1, 'https://h' || g || '.example.com', 'service', 'http', 'active', 'public'
		FROM generate_series(1, 20000) g`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sqlDB.ExecContext(ctx, `
		INSERT INTO assets (id, tenant_id, name, asset_type, status, exposure)
		SELECT gen_random_uuid(), $1, 'host' || g, 'domain', 'active', 'public'
		FROM generate_series(1, 20000) g`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sqlDB.ExecContext(ctx, `ANALYZE assets`); err != nil {
		t.Fatal(err)
	}
	rows, err := f.sqlDB.QueryContext(ctx, `EXPLAIN SELECT a.id FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_type = 'service' AND a.sub_type = 'http'
		  AND lower(rtrim(a.name, '/')) = $2 LIMIT 8`, f.tenant.String(), "https://h777.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, l)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "idx_assets_web_origin_name") {
		t.Fatalf("the origin lookup does not use its expression index:\n%s", strings.Join(plan, "\n"))
	}
}

// SECURITY: a guessed backup, archive or dump file is a verification
// candidate without a catalog entry, for its own organization only; a guessed
// page or config file, and a crawled file with no catalog entry, are not. The
// SQL's label list is the domain's.
func TestWebVerifyCandidates_GuessedBackupFiles(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	other := seedTestTenant(ctx, t, f.sqlDB)
	foreign := f.seedOrigin(t, other, "https://other.example.com")
	vr := NewWebVerifyRepository(f.db)
	if !strings.Contains(verifiableSQL, "ARRAY['"+strings.Join(webendpoint.GuessedVerifyLabels, "', '")+"']") {
		t.Fatalf("the SQL's guessed labels are not webendpoint.GuessedVerifyLabels %v", webendpoint.GuessedVerifyLabels)
	}
	add := func(tenant, origin shared.ID, path, sources string) {
		t.Helper()
		label := webendpoint.ExtLabel(path)
		labels := "{}"
		if label != "" {
			labels = "{" + label + "}"
		}
		if _, err := f.sqlDB.ExecContext(ctx, `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash,
				kind, auth_state, sources, labels, state, in_scope, last_status)
			VALUES (gen_random_uuid(), $1, $2, 'GET', $3::text, md5('GET' || $3::text), md5($3::text), 'page', 'unknown', $4::text[], $5::text[], 'active', true, 200)`,
			tenant.String(), origin.String(), path, sources, labels); err != nil {
			t.Fatal(err)
		}
	}
	add(f.tenant, f.origin, "/site.zip", "{guess}")
	add(f.tenant, f.origin, "/dump.sql", "{guess}")
	add(f.tenant, f.origin, "/admin.php", "{guess}")   // a page
	add(f.tenant, f.origin, "/app.yml", "{guess}")     // config
	add(f.tenant, f.origin, "/crawled.zip", "{crawl}") // not guessed
	add(other, foreign, "/other.zip", "{guess}")

	cs, err := vr.Candidates(ctx, f.tenant, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cs {
		if !c.Guessed || c.CatalogKey != "" {
			t.Errorf("candidate %+v", c)
		}
		got = append(got, c.PathTemplate)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"/dump.sql", "/site.zip"}) {
		t.Fatalf("candidates %v, want the guessed backup files of this organization only", got)
	}
}
