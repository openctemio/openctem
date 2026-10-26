package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/webverify"
	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// Web content intelligence against the real schema: platform labels, the
// three web change kinds with tenant and data-scope narrowing, immediate
// alerts with fingerprint expiry and the budget, and the verification
// ledger. Requires DATABASE_URL.

type webFixture struct {
	ctx    context.Context
	sqlDB  *sql.DB
	db     *DB
	repo   *WebEndpointRepository
	tenant shared.ID
	origin shared.ID
}

func newWebFixture(t *testing.T) *webFixture {
	t.Helper()
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	f := &webFixture{ctx: ctx, sqlDB: sqlDB, db: db, repo: NewWebEndpointRepository(db), tenant: seedTestTenant(ctx, t, sqlDB)}
	f.origin = f.seedOrigin(t, f.tenant, "https://a.example.com")
	return f
}

func (f *webFixture) seedOrigin(t *testing.T, tenant shared.ID, name string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := f.sqlDB.ExecContext(f.ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, exposure) VALUES ($1, $2, $3, 'service', 'active', 'public')`,
		id.String(), tenant.String(), name); err != nil {
		t.Fatalf("seed origin: %v", err)
	}
	return id
}

func obs(t *testing.T, e ctis.Endpoint) webendpoint.Observation {
	t.Helper()
	if e.Origin == "" {
		e.Origin = "https://a.example.com"
	}
	if e.Method == "" {
		e.Method = "GET"
	}
	o, err := webendpoint.Observe(e)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (f *webFixture) record(t *testing.T, tenant, origin shared.ID, o ...webendpoint.Observation) {
	t.Helper()
	if _, err := f.repo.Record(f.ctx, tenant, origin, o, webendpoint.Provenance{Tool: "test"}); err != nil {
		t.Fatalf("record: %v", err)
	}
}

func (f *webFixture) changes(t *testing.T, tenant shared.ID, scope *shared.DataScope) *easmchange.Page {
	t.Helper()
	now := time.Now().UTC()
	p, err := NewEASMChangeRepository(f.db).ListChanges(f.ctx, tenant, scope,
		easmchange.Query{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWebEndpointLabelsPersist(t *testing.T) {
	f := newWebFixture(t)
	f.record(t, f.tenant, f.origin,
		obs(t, ctis.Endpoint{Path: "/backup.sql"}),
		obs(t, ctis.Endpoint{Path: "/login", Method: "POST", Params: []ctis.EndpointParam{{Location: ctis.ParamLocationForm, Name: "password"}}}))
	var n int
	if err := f.sqlDB.QueryRowContext(f.ctx, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1 AND
		((path_template = '/backup.sql' AND labels = '{ext:dbdump}') OR (path_template = '/login' AND labels = '{auth:login}'))`,
		f.tenant.String()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("labels persisted on %d rows, err %v", n, err)
	}
	// A person's label survives a re-sighting; platform labels are merged in.
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_endpoints SET labels = '{mine}', last_seen_at = now() - interval '2 hours' WHERE tenant_id = $1 AND path_template = '/backup.sql'`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.tenant, f.origin, obs(t, ctis.Endpoint{Path: "/backup.sql"}))
	if err := f.sqlDB.QueryRowContext(f.ctx, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1 AND path_template = '/backup.sql' AND labels = '{ext:dbdump,mine}'`, f.tenant.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("labels not merged: %d %v", n, err)
	}
}

func TestWebChangeKindsIsolationScopeAndExclusion(t *testing.T) {
	f := newWebFixture(t)
	other := seedTestTenant(f.ctx, t, f.sqlDB)
	foreign := f.seedOrigin(t, other, "https://a.example.com")

	// First sighting: a critical catalog path (web_sensitive_new), an
	// authenticated API endpoint, and a path under an exclusion.
	api := obs(t, ctis.Endpoint{Path: "/api/v1/users", Kind: ctis.EndpointKindAPI, Auth: ctis.EndpointAuthRequired, StatusCode: 200})
	hidden := obs(t, ctis.Endpoint{Path: "/.env", StatusCode: 200})
	hidden.OutOfScope = true
	f.record(t, f.tenant, f.origin, obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200}), api, hidden)
	f.record(t, other, foreign, obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200}))

	// Second sighting: the API loses authentication, and gains a credential parameter.
	api2 := obs(t, ctis.Endpoint{Path: "/api/v1/users", Kind: ctis.EndpointKindAPI, Auth: ctis.EndpointAuthNone, StatusCode: 200,
		Params: []ctis.EndpointParam{{Location: ctis.ParamLocationQuery, Name: "access_token"}}})
	f.record(t, f.tenant, f.origin, api2)

	page := f.changes(t, f.tenant, nil)
	got := map[easmchange.Kind]int{}
	for _, c := range page.Items {
		got[c.Kind]++
		if c.AssetName != "https://a.example.com" {
			t.Errorf("unexpected asset %q", c.AssetName)
		}
		if c.New == "/.env" || c.Detail == "GET /.env" {
			t.Errorf("an excluded path was reported: %+v", c)
		}
	}
	if got[easmchange.KindWebSensitiveNew] != 1 || got[easmchange.KindWebAuthLost] != 1 || got[easmchange.KindWebParamAddedSensitive] != 1 {
		t.Fatalf("kinds = %v", got)
	}
	// Cross-tenant: the other tenant sees only its own origin's change.
	op := f.changes(t, other, nil)
	if op.Counts[easmchange.KindWebSensitiveNew] != 1 || op.Counts[easmchange.KindWebAuthLost] != 0 {
		t.Fatalf("other tenant counts = %v", op.Counts)
	}

	// Data scope: a member without access sees nothing; with access to the origin, its changes.
	user := seedUser(f.ctx, t, f.db)
	scope := &shared.DataScope{TenantID: f.tenant, UserID: user}
	if p := f.changes(t, f.tenant, scope); p.Counts[easmchange.KindWebSensitiveNew] != 0 || p.Counts[easmchange.KindWebAuthLost] != 0 {
		t.Fatalf("member without scope sees web changes: %v", p.Counts)
	}
	if _, err := f.sqlDB.ExecContext(f.ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), f.tenant.String(), f.origin.String()); err != nil {
		t.Fatal(err)
	}
	if p := f.changes(t, f.tenant, scope); p.Counts[easmchange.KindWebSensitiveNew] != 1 || p.Counts[easmchange.KindWebAuthLost] != 1 {
		t.Fatalf("scoped member counts = %v", p.Counts)
	}
}

func (f *webFixture) outboxCount(t *testing.T, tenant shared.ID) int {
	t.Helper()
	var n int
	if err := f.sqlDB.QueryRowContext(f.ctx, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND aggregate_type = 'web_endpoint'`, tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWebAlertsImmediateFingerprintBudgetAndExclusion(t *testing.T) {
	f := newWebFixture(t)
	base := NewEASMAlerter(f.db)
	f.repo.SetAlerter(NewWebAlerter(base))

	// An excluded critical path never alerts; an in-scope one does.
	hidden := obs(t, ctis.Endpoint{Path: "/.env", StatusCode: 200})
	hidden.OutOfScope = true
	f.record(t, f.tenant, f.origin, hidden)
	if n := f.outboxCount(t, f.tenant); n != 0 {
		t.Fatalf("excluded path alerted: %d", n)
	}
	git := obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200})
	f.record(t, f.tenant, f.origin, git)
	if n := f.outboxCount(t, f.tenant); n != 1 {
		t.Fatalf("critical path alerts = %d, want 1", n)
	}
	// Gone and back within the fingerprint lifetime: no second alert.
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_endpoints SET state = 'gone' WHERE tenant_id = $1`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.tenant, f.origin, git)
	if n := f.outboxCount(t, f.tenant); n != 1 {
		t.Fatalf("flapping endpoint alerted again: %d", n)
	}
	// After the lifetime it alerts again.
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_alert_fingerprints SET last_alerted_at = now() - interval '40 days' WHERE tenant_id = $1`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_endpoints SET state = 'gone' WHERE tenant_id = $1`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.tenant, f.origin, git)
	if n := f.outboxCount(t, f.tenant); n != 2 {
		t.Fatalf("expired fingerprint alerts = %d, want 2", n)
	}

	// An origin nobody confirmed gets no immediate alert.
	pending := f.seedOrigin(t, f.tenant, "https://pending.example.com")
	if _, err := f.sqlDB.ExecContext(f.ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 50)`, pending.String(), f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.tenant, pending, obs(t, ctis.Endpoint{Origin: "https://pending.example.com", Path: "/.git/config", StatusCode: 200}))
	if n := f.outboxCount(t, f.tenant); n != 2 {
		t.Fatalf("unconfirmed origin alerted: %d", n)
	}

	// The hourly budget caps immediate alerts.
	small := newWebFixture(t)
	small.repo.SetAlerter(NewWebAlerter(NewEASMAlerter(small.db).WithHourlyBudget(1)))
	small.record(t, small.tenant, small.origin,
		obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200}),
		obs(t, ctis.Endpoint{Path: "/.svn/entries", StatusCode: 200}))
	if n := small.outboxCount(t, small.tenant); n != 1 {
		t.Fatalf("budget 1 alerted %d", n)
	}
}

func TestWebVerifyRepositoryTenantScopeAndDelta(t *testing.T) {
	f := newWebFixture(t)
	other := seedTestTenant(f.ctx, t, f.sqlDB)
	foreign := f.seedOrigin(t, other, "https://a.example.com")
	vr := NewWebVerifyRepository(f.db)
	keys := []string{"vcs.git", "config.env"}

	ok := obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200})
	notFound := obs(t, ctis.Endpoint{Path: "/.env", StatusCode: 404})
	excluded := obs(t, ctis.Endpoint{Path: "/.git/HEAD", StatusCode: 200})
	excluded.OutOfScope = true
	f.record(t, f.tenant, f.origin, ok, notFound, excluded)
	f.record(t, other, foreign, obs(t, ctis.Endpoint{Path: "/.git/config", StatusCode: 200}))

	cs, err := vr.Candidates(f.ctx, f.tenant, keys, 10)
	if err != nil || len(cs) != 1 || cs[0].PathTemplate != "/.git/config" || cs[0].OriginAssetID != f.origin {
		t.Fatalf("candidates = %+v err %v (2xx, in scope, own tenant only)", cs, err)
	}
	ts, _ := vr.TenantsWithCandidates(f.ctx, keys, 100)
	seenOwn, seenOther := false, false
	for _, id := range ts {
		seenOwn = seenOwn || id == f.tenant
		seenOther = seenOther || id == other
	}
	if !seenOwn || !seenOther {
		t.Fatalf("tenants = %v", ts)
	}

	// Another tenant's endpoint id cannot be written into this tenant's ledger.
	foreignCands, _ := vr.Candidates(f.ctx, other, keys, 10)
	run := shared.NewID()
	if err := vr.RecordPlanned(f.ctx, f.tenant, []webverify.Planned{{EndpointID: foreignCands[0].EndpointID, ResponseSig: "x", CatalogKey: "vcs.git", RunID: &run}}); err != nil {
		t.Fatal(err)
	}
	if n, _ := vr.RunPlannedSince(f.ctx, f.tenant, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("foreign endpoint recorded in this tenant's ledger: %d", n)
	}

	// Delta gating: planned for this signature, it is not a candidate again;
	// a response change makes it one.
	if err := vr.RecordPlanned(f.ctx, f.tenant, []webverify.Planned{{EndpointID: cs[0].EndpointID, ResponseSig: cs[0].ResponseSig, CatalogKey: "vcs.git", RunID: &run}}); err != nil {
		t.Fatal(err)
	}
	if again, _ := vr.Candidates(f.ctx, f.tenant, keys, 10); len(again) != 0 {
		t.Fatalf("verified endpoint is a candidate again: %+v", again)
	}
	if n, _ := vr.RunPlannedSince(f.ctx, f.tenant, time.Now().Add(-time.Hour)); n != 1 {
		t.Fatalf("budget count = %d", n)
	}
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_endpoints SET response_sig = 'changed' WHERE tenant_id = $1 AND id = $2`, f.tenant.String(), cs[0].EndpointID.String()); err != nil {
		t.Fatal(err)
	}
	if again, _ := vr.Candidates(f.ctx, f.tenant, keys, 10); len(again) != 1 {
		t.Fatalf("a changed endpoint must be verified again, got %d", len(again))
	}
	// The planner writes no finding or exposure.
	var n int
	_ = f.sqlDB.QueryRowContext(f.ctx, `SELECT (SELECT count(*) FROM findings WHERE tenant_id = $1) + (SELECT count(*) FROM exposure_events WHERE tenant_id = $1)`, f.tenant.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("verification planning wrote %d findings/exposures", n)
	}
}
