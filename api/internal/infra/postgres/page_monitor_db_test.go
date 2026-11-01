package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	pagemonapp "github.com/openctemio/openctem/api/internal/app/pagemon"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// pmScope is the caller's data scope for the service: Resolve returns the
// scope; AssertAsset admits the assets in allowed (nil = every asset).
type pmScope struct {
	scope   *shared.DataScope
	allowed map[shared.ID]bool
}

func (p pmScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return p.scope, nil }
func (p pmScope) AssertAsset(_ context.Context, _, id shared.ID) error {
	if p.allowed != nil && !p.allowed[id] {
		return shared.ErrNotFound
	}
	return nil
}
func (p pmScope) AssertAssetRef(ctx context.Context, t, id shared.ID) error {
	return p.AssertAsset(ctx, t, id)
}

type pmExposures struct{ events []*exposuredom.ExposureEvent }

func (e *pmExposures) BulkUpsert(_ context.Context, ev []*exposuredom.ExposureEvent) error {
	e.events = append(e.events, ev...)
	return nil
}

type pmDispatcher struct {
	got    []string
	refuse map[string]string
}

func (d *pmDispatcher) StartCoverage(_ context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error) {
	d.got = append(d.got, in.Targets...)
	run := shared.NewID()
	res := &scanapp.CoverageResult{RunID: &run, Tool: "httpx"}
	for _, t := range in.Targets {
		if code, ok := d.refuse[t]; ok {
			res.Refused = append(res.Refused, scanapp.RefusedTarget{Target: t, Code: code})
		} else {
			res.Kept = append(res.Kept, t)
		}
	}
	return res, nil
}

const pmPageV1 = `<html><head><script src="/static/app.11aa22bb.js"></script>
<script src="https://cdn.trusted-vendor.example/lib.js" integrity="sha384-x"></script></head><body>Shop</body></html>`

const pmPageV2 = `<html><head><script src="/static/app.11aa22bb.js"></script>
<script src="https://cdn.trusted-vendor.example/lib.js" integrity="sha384-x"></script>
<script src="https://skimmer.example.net/c.js"></script></head><body>Shop</body></html>`

func pmCapture(u, body string, at time.Time) pagemon.Item {
	return pagemon.Item{Raw: []any{map[string]any{
		"url": u, "status_code": float64(200), "content_type": "text/html", "body": body, "fetched_at": at.Format(time.RFC3339),
	}}}
}

// Page monitoring end to end against the real schema: watches, ingest,
// change detection, alerts, derived scripts, dispatch, data scope and tenant
// isolation. Requires DATABASE_URL.
func TestPageMonitorRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewPageMonitorRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	origin := func(tn shared.ID, name string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status) VALUES ($1, $2, $3, 'service', 'http', 'active')`,
			id.String(), tn.String(), name)
		return id
	}
	shop := origin(tenant, "https://shop.example.com")
	blog := origin(tenant, "https://blog.example.com")
	foreignShop := origin(other, "https://shop.example.com")
	_ = foreignShop

	now := time.Now().UTC().Truncate(time.Second)
	expo := &pmExposures{}
	svc := pagemonapp.NewService(repo, pmScope{}, nil)
	svc.SetAlerts(expo, NewEASMDNSRepository(db))
	svc.SetClock(func() time.Time { return now })

	// Watches: only on a known origin of the tenant.
	w, err := svc.CreateWatch(ctx, tenant, nil, pagemonapp.WatchInput{URL: "HTTPS://Shop.Example.com/login"})
	if err != nil || w.URL != "https://shop.example.com/login" || w.AssetID != shop || w.Mode != pagemon.ModeJS {
		t.Fatalf("create: %v %+v", err, w)
	}
	if _, err := svc.CreateWatch(ctx, tenant, nil, pagemonapp.WatchInput{URL: "https://shop.example.com/login"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := svc.CreateWatch(ctx, tenant, nil, pagemonapp.WatchInput{URL: "https://unknown.example.org/"}); !errors.Is(err, pagemonapp.ErrNoOrigin) {
		t.Fatalf("unknown origin: %v", err)
	}
	// An origin outside the caller's scope answers like an unknown one.
	narrow := pagemonapp.NewService(repo, pmScope{allowed: map[shared.ID]bool{shop: true}}, nil)
	if _, err := narrow.CreateWatch(ctx, tenant, nil, pagemonapp.WatchInput{URL: "https://blog.example.com/"}); !errors.Is(err, pagemonapp.ErrNoOrigin) {
		t.Fatalf("out of scope origin: %v", err)
	}
	blogWatch, err := svc.CreateWatch(ctx, tenant, nil, pagemonapp.WatchInput{URL: "https://blog.example.com/", Mode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := narrow.UpdateWatch(ctx, tenant, blogWatch.ID.String(), pagemonapp.WatchUpdate{CadenceHours: 12}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out of scope update: %v", err)
	}
	// Another tenant cannot see or change the watch.
	if _, err := svc.UpdateWatch(ctx, other, w.ID.String(), pagemonapp.WatchUpdate{CadenceHours: 12}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if _, err := svc.DeleteWatch(ctx, other, w.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}

	// Ingest: baseline, then a change with a new third-party script host.
	taken, skipped := svc.RecordReport(ctx, tenant, "httpx", []pagemon.Item{pmCapture("https://shop.example.com/login", pmPageV1, now)})
	if taken != 1 || skipped != 0 {
		t.Fatalf("baseline: %d %d", taken, skipped)
	}
	// A report of another tenant carrying this tenant's URL is not taken.
	if taken, _ := svc.RecordReport(ctx, other, "httpx", []pagemon.Item{pmCapture("https://shop.example.com/login", pmPageV2, now)}); taken != 0 {
		t.Fatal("another tenant's report was taken")
	}
	changes, total, err := svc.ListChanges(ctx, tenant, pagemon.ChangeFilter{})
	if err != nil || total != 0 || len(changes) != 0 {
		t.Fatalf("baseline made a change: %v %d", err, total)
	}
	// The page's first-party script became a derived watch.
	ws, err := svc.ListWatches(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var derived *pagemon.Watch
	for i := range ws {
		if ws[i].Source == pagemon.SourceDerived {
			derived = &ws[i]
		}
	}
	if derived == nil || derived.URL != "https://shop.example.com/static/app.11aa22bb.js" || derived.ParentID == nil || *derived.ParentID != w.ID {
		t.Fatalf("derived: %+v", ws)
	}
	if _, err := svc.DeleteWatch(ctx, tenant, derived.ID.String()); !errors.Is(err, pagemonapp.ErrDerived) {
		t.Fatalf("derived delete: %v", err)
	}

	later := now.Add(time.Hour)
	svc.SetClock(func() time.Time { return later })
	if taken, _ := svc.RecordReport(ctx, tenant, "httpx", []pagemon.Item{pmCapture("https://shop.example.com/login", pmPageV2, later)}); taken != 1 {
		t.Fatal("change not taken")
	}
	changes, total, err = svc.ListChanges(ctx, tenant, pagemon.ChangeFilter{})
	if err != nil || total != 1 || changes[0].Severity != pagemon.SeverityHigh || changes[0].Summary.NewThirdPartyHosts != 1 {
		t.Fatalf("change: %v %d %+v", err, total, changes)
	}
	if len(expo.events) != 1 || expo.events[0].EventType() != exposuredom.EventTypeThirdPartyScriptAdded ||
		expo.events[0].Fingerprint() != pagemonapp.ThirdPartyFingerprint(tenant, "https://shop.example.com/login", "skimmer.example.net") {
		t.Fatalf("exposure: %+v", expo.events)
	}
	got, err := svc.GetChange(ctx, tenant, changes[0].ID.String())
	if err != nil || got.Diff == nil || len(got.Diff.ScriptsAdded) != 1 || got.Diff.ScriptsAdded[0].Host != "skimmer.example.net" {
		t.Fatalf("detail: %v %+v", err, got)
	}
	if _, err := svc.GetChange(ctx, other, changes[0].ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant change read: %v", err)
	}
	if c, total, _ := svc.ListChanges(ctx, other, pagemon.ChangeFilter{}); total != 0 || len(c) != 0 {
		t.Fatal("another tenant lists the change")
	}
	if c, _, _ := svc.ListChanges(ctx, tenant, pagemon.ChangeFilter{MinSeverity: pagemon.SeverityHigh, WatchID: &w.ID}); len(c) != 1 {
		t.Fatal("filter by watch and severity")
	}

	// Data scope on lists: a member sees changes and watches of assets in
	// their scope only.
	user := seedGroupsUser(ctx, t, sqlDB, "pagemon-scope-"+shared.NewID().String()[:8]+".test")
	addTenantMember(ctx, t, sqlDB, tenant, user)
	restricted := &shared.DataScope{TenantID: tenant, UserID: user}
	scoped := pagemonapp.NewService(repo, pmScope{scope: restricted}, nil)
	if c, total, _ := scoped.ListChanges(ctx, tenant, pagemon.ChangeFilter{}); total != 0 || len(c) != 0 {
		t.Fatal("out-of-scope change listed")
	}
	if l, _ := scoped.ListWatches(ctx, tenant); len(l) != 0 {
		t.Fatal("out-of-scope watch listed")
	}
	if _, err := scoped.GetChange(ctx, tenant, changes[0].ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal("out-of-scope change read")
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), tenant.String(), shop.String())
	if _, total, _ := scoped.ListChanges(ctx, tenant, pagemon.ChangeFilter{}); total != 1 {
		t.Fatal("in-scope change not listed")
	}
	if l, _ := scoped.ListWatches(ctx, tenant); len(l) != 2 { // the page and its derived script
		t.Fatalf("in-scope watches: %d", len(l))
	}

	// The skimmer goes away: the exposure resolves itself.
	if err := NewExposureRepository(db).BulkUpsert(ctx, expo.events); err != nil {
		t.Fatal(err)
	}
	svc.RecordReport(ctx, tenant, "httpx", []pagemon.Item{pmCapture("https://shop.example.com/login", pmPageV1, later.Add(time.Hour))})
	var state string
	if err := sqlDB.QueryRowContext(ctx, `SELECT state FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`,
		tenant.String(), expo.events[0].Fingerprint()).Scan(&state); err != nil || state != "resolved" {
		t.Fatalf("exposure state %q %v", state, err)
	}

	// Snapshots: at most five per watch.
	for i := range 8 {
		body := strings.Replace(pmPageV1, "Shop", "Shop", 1) + strings.Repeat(`<script src="/x`+string(rune('a'+i))+`.js"></script>`, 1)
		svc.RecordReport(ctx, tenant, "httpx", []pagemon.Item{pmCapture("https://shop.example.com/login", body, later.Add(time.Duration(2+i)*time.Hour))})
	}
	var n int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM web_snapshots WHERE tenant_id = $1 AND watch_id = $2`, tenant.String(), w.ID.String()).Scan(&n); err != nil || n != pagemon.SnapshotsKept {
		t.Fatalf("snapshots kept: %d %v", n, err)
	}
	reread, _ := repo.GetWatch(ctx, tenant, w.ID)
	if !reread.Dynamic {
		t.Error("a watch that changed on every fetch is not marked dynamic")
	}
	if c, _, _ := svc.ListChanges(ctx, tenant, pagemon.ChangeFilter{}); len(c) >= 10 {
		t.Error("muted changes listed without muted=true")
	}

	// A failed fetch records the status without a snapshot.
	fail := pagemon.Item{Raw: []any{map[string]any{"url": "https://blog.example.com/", "status_code": float64(503)}}}
	svc.RecordReport(ctx, tenant, "httpx", []pagemon.Item{fail})
	bw, _ := repo.GetWatch(ctx, tenant, blogWatch.ID)
	if bw.State != pagemon.StateFailed || bw.LastStatus != 503 {
		t.Fatalf("failed fetch: %+v", bw)
	}

	// Dispatch: waiting without the capability, refused URLs blocked, kept
	// ones due again after their cadence.
	disp := &pmDispatcher{refuse: map[string]string{"https://blog.example.com/": "not_owned"}}
	exec(`UPDATE web_watches SET next_due_at = $2 WHERE tenant_id = $1`, tenant.String(), later)
	runAt := later.Add(10 * time.Hour)
	svc.SetClock(func() time.Time { return runAt })
	svc.SetDispatch(disp, nil, func() bool { return false })
	if n, err := svc.Run(ctx, func(id shared.ID) bool { return id != tenant }); err != nil || n != 0 {
		t.Fatalf("run without capability: %d %v", n, err)
	}
	if got, _ := repo.GetWatch(ctx, tenant, w.ID); got.State != pagemon.StateWaiting || len(disp.got) != 0 {
		t.Fatalf("waiting: %+v %v", got.State, disp.got)
	}
	exec(`UPDATE web_watches SET next_due_at = $2 WHERE tenant_id = $1`, tenant.String(), later)
	svc.SetDispatch(disp, nil, func() bool { return true })
	n, err = svc.Run(ctx, func(id shared.ID) bool { return id != tenant })
	if err != nil || n != 3 || len(disp.got) != 4 { // the page, its two scripts, the blog
		t.Fatalf("run: %d %v %v", n, err, disp.got)
	}
	bw, _ = repo.GetWatch(ctx, tenant, blogWatch.ID)
	if bw.State != pagemon.StateBlocked || !strings.Contains(bw.LastError, "not_owned") || !bw.NextDueAt.After(runAt) {
		t.Fatalf("blocked: %+v", bw)
	}
	pw, _ := repo.GetWatch(ctx, tenant, w.ID)
	if !pw.NextDueAt.Equal(runAt.Add(24 * time.Hour)) {
		t.Fatalf("next due %v", pw.NextDueAt)
	}

	// Suggestions: the root pages and the login endpoint, not what is watched.
	exec(`INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, kind, labels)
		VALUES ($1, $2, $3, 'GET', '/account/signin', $4, $4, 'page', '{auth:login}')`,
		shared.NewID().String(), tenant.String(), shop.String(), strings.Repeat("a", 64))
	exec(`INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, kind, labels)
		VALUES ($1, $2, $3, 'GET', '/u/{id}', $4, $4, 'page', '{auth:login}')`,
		shared.NewID().String(), tenant.String(), shop.String(), strings.Repeat("b", 64))
	sugg, err := svc.Suggestions(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, s := range sugg {
		reasons[s.URL] = s.Reason
	}
	if reasons["https://shop.example.com/"] != pagemon.ReasonRoot || reasons["https://shop.example.com/account/signin"] != pagemon.ReasonLogin {
		t.Fatalf("suggestions: %+v", sugg)
	}
	if _, ok := reasons["https://blog.example.com/"]; ok {
		t.Error("a watched root is suggested")
	}
	for u := range reasons {
		if strings.Contains(u, "{") {
			t.Errorf("template suggested: %s", u)
		}
	}
	if s, _ := scoped.Suggestions(ctx, tenant); len(s) != 2 {
		t.Errorf("scoped suggestions: %+v", s)
	}
	if s, _ := svc.Suggestions(ctx, other); len(s) != 1 || s[0].AssetID != foreignShop {
		t.Errorf("other tenant suggestions: %+v", s)
	}

	// Deleting the page removes its derived script, snapshots and changes;
	// deleting an asset removes its watches.
	if _, err := svc.DeleteWatch(ctx, tenant, w.ID.String()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"web_snapshots", "web_changes"} {
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id = $1 AND watch_id = $2`, tenant.String(), w.ID.String()).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s left: %d %v", table, n, err)
		}
	}
	if _, err := repo.GetWatch(ctx, tenant, derived.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal("derived watch left")
	}
	exec(`DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, tenant.String(), blog.String())
	if _, err := repo.GetWatch(ctx, tenant, blogWatch.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatal("watch of a deleted asset left")
	}
	// Retention sweep runs across tenants by age only.
	if _, err := repo.DeleteChangesBefore(ctx, time.Now().Add(-pagemon.ChangeRetention)); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}
