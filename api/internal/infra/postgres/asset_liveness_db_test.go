package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	livenessapp "github.com/openctemio/openctem/api/internal/app/liveness"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/liveness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type livenessSettings struct{ close bool }

func (s livenessSettings) GetAssetLifecycleSettings(context.Context, string) (*tenantdom.AssetLifecycleSettings, error) {
	return &tenantdom.AssetLifecycleSettings{Liveness: &tenantdom.AssetLivenessSettings{CloseFindingsWhenGone: s.close}}, nil
}

// Asset liveness on the real schema: NXDOMAIN evidence from two observers
// over four days makes a name gone once the dangling check ran clean; its
// service follows it; their open findings close as resolved / obsolete_asset
// with timeline entries and audit rows; a dangling name, a pinned asset,
// another tenant's asset and a name seen by one observer stay. When the name
// resolves again the findings reopen to their old status, not as a
// regression, with the SLA deadline kept; a finding a person closed after
// the liveness close is not reopened. Requires DATABASE_URL.
func TestAssetLiveness(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetLivenessRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	asset := func(tid shared.ID, name, typ, sub string) shared.ID {
		t.Helper()
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status) VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'active')`,
			id.String(), tid.String(), name, typ, sub)
		return id
	}
	finding := func(tid, assetID shared.ID, status, severity string) string {
		t.Helper()
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, sla_deadline)
			VALUES ($1, $2, $3, 'dast', 'tool', 'msg', $4, $5, $6, '2026-12-01T00:00:00Z')`,
			id, tid.String(), assetID.String(), severity, status, "fp-liveness-"+id)
		return id
	}
	danglingChecked := func(tid, assetID shared.ID) {
		t.Helper()
		mustExec(t, db, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome, last_attempt_at, last_success_at)
			VALUES ($1, $2, 'dns.dangling', 'covered', 'ok', now(), now())`, tid.String(), assetID.String())
	}
	status := func(id string) (st string, reason sql.NullString, regression bool, sla time.Time) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT status, closure_reason, COALESCE(is_regression, false), sla_deadline FROM findings WHERE id = $1`, id).
			Scan(&st, &reason, &regression, &sla); err != nil {
			t.Fatal(err)
		}
		return
	}
	state := func(tid, id shared.ID) string {
		t.Helper()
		var s string
		if err := db.QueryRowContext(ctx, `SELECT state FROM asset_liveness WHERE tenant_id = $1 AND asset_id = $2`, tid.String(), id.String()).Scan(&s); err != nil {
			if err == sql.ErrNoRows {
				return ""
			}
			t.Fatal(err)
		}
		return s
	}
	nx := func(tid shared.ID, ids []shared.ID, observers []string) {
		t.Helper()
		base := time.Now().Add(-5 * 24 * time.Hour)
		for i, d := range []int{0, 1, 4} {
			obs := make([]liveness.AssetObservation, 0, len(ids))
			for _, id := range ids {
				obs = append(obs, liveness.AssetObservation{AssetID: id, Observation: liveness.Observation{
					Kind: liveness.KindNXDomain, Observer: observers[i%len(observers)], Capability: "resolve.dns", Outcome: "no_answer"}})
			}
			if _, err := repo.Observe(ctx, tid, obs, liveness.DefaultThresholds(), base.Add(time.Duration(d)*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
	}

	name := asset(tenant, "gone.example.com", "subdomain", "")
	svc := asset(tenant, "https://gone.example.com", "service", "http")
	dangling := asset(tenant, "dangle.example.com", "subdomain", "")
	pinned := asset(tenant, "pinned.example.com", "subdomain", "")
	lonely := asset(tenant, "lonely.example.com", "subdomain", "")
	theirs := asset(other, "gone.example.com", "subdomain", "")
	mustExec(t, db, `UPDATE assets SET manual_status_override = true WHERE id = $1`, pinned.String())
	mustExec(t, db, `INSERT INTO exposure_events (tenant_id, asset_id, event_type, severity, state, title, fingerprint, source)
		VALUES ($1, $2, 'dangling_cname', 'medium', 'active', 'dangling', 'fp-dangle', 'dns')`, tenant.String(), dangling.String())
	for _, id := range []shared.ID{name, dangling, pinned, lonely} {
		danglingChecked(tenant, id)
	}
	danglingChecked(other, theirs)

	fSvc := finding(tenant, svc, "confirmed", "critical")
	fSvc2 := finding(tenant, svc, "in_progress", "medium")
	fAccepted := finding(tenant, svc, "accepted", "high")
	fName := finding(tenant, name, "new", "low")
	fDangling := finding(tenant, dangling, "confirmed", "high")
	fPinned := finding(tenant, pinned, "confirmed", "high")
	fLonely := finding(tenant, lonely, "confirmed", "high")
	fTheirs := finding(other, theirs, "confirmed", "high")

	nx(tenant, []shared.ID{name, dangling, pinned}, []string{"sensor:a", "zone:b"})
	nx(tenant, []shared.ID{lonely}, []string{"sensor:a"})
	nx(other, []shared.ID{theirs}, []string{"sensor:a", "zone:b"})
	if st := state(tenant, name); st != "unresolvable" {
		t.Fatalf("after the settle path: %s, want unresolvable (gone needs the guards)", st)
	}

	// Closing off: gone is a label, nothing closes.
	off := livenessapp.NewService(repo, livenessSettings{close: false}, nil, logger.NewNop())
	if _, err := off.ReconcileTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if st := state(tenant, name); st != "gone" {
		t.Fatalf("name: %s, want gone", st)
	}
	if st := state(tenant, svc); st != "gone" {
		t.Fatalf("service: %s, want gone (its host name is gone)", st)
	}
	if st, _, _, _ := status(fSvc); st != "confirmed" {
		t.Fatalf("closing off closed a finding: %s", st)
	}
	for id, want := range map[shared.ID]string{dangling: "unresolvable", pinned: "unresolvable", lonely: "unresolvable"} {
		if st := state(tenant, id); st != want {
			t.Fatalf("asset %s: %s, want %s", id, st, want)
		}
	}

	// Dry run counts what would close.
	dry, err := off.Preview(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if dry.WouldCloseFindings != 3 || dry.WouldCloseCritical != 1 || dry.States["gone"] != 2 {
		t.Fatalf("dry run: %+v, want 3 to close (1 critical), 2 gone", dry)
	}

	on := livenessapp.NewService(repo, livenessSettings{close: true}, nil, logger.NewNop())
	res, err := on.ReconcileTenant(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closed) != 3 || res.ClosedCritical != 1 {
		t.Fatalf("closed %d (%d critical), want 3 (1 critical)", len(res.Closed), res.ClosedCritical)
	}
	for _, id := range []string{fSvc, fSvc2, fName} {
		st, reason, _, _ := status(id)
		if st != "resolved" || reason.String != "obsolete_asset" {
			t.Fatalf("finding %s: %s/%s, want resolved/obsolete_asset", id, st, reason.String)
		}
	}
	for id, want := range map[string]string{fAccepted: "accepted", fDangling: "confirmed", fPinned: "confirmed", fLonely: "confirmed"} {
		if st, _, _, _ := status(id); st != want {
			t.Fatalf("finding %s: %s, want %s", id, st, want)
		}
	}
	if st, _, _, _ := status(fTheirs); st != "confirmed" {
		t.Fatalf("another tenant's finding moved: %s", st)
	}
	if st := state(other, theirs); st != "unresolvable" {
		t.Fatalf("another tenant's asset decided by this tenant's pass: %s", st)
	}
	var audits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.status_changed'
		AND metadata->>'source' = 'asset_liveness' AND metadata->>'closure_reason' = 'obsolete_asset'`, tenant.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 3 {
		t.Fatalf("audit rows %d, want 3", audits)
	}
	var history int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM asset_state_history WHERE tenant_id = $1 AND field = 'liveness' AND new_value = 'gone'`,
		tenant.String()).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if history != 2 {
		t.Fatalf("gone history rows %d, want 2", history)
	}

	// A person reopens and closes one finding again: no longer the pass's.
	mustExec(t, db, `UPDATE findings SET status = 'confirmed' WHERE id = $1`, fName)
	mustExec(t, db, `UPDATE findings SET status = 'resolved', closure_reason = 'fixed', resolution = 'fixed', resolved_at = now() WHERE id = $1`, fName)

	// The name resolves again: the service follows, its findings reopen.
	if _, err := repo.Observe(ctx, tenant, []liveness.AssetObservation{{AssetID: name, Observation: liveness.Observation{
		Kind: liveness.KindResolved, Observer: "sensor:a", Capability: "resolve.dns", Outcome: "ok"}}},
		liveness.DefaultThresholds(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if st := state(tenant, name); st != "alive" {
		t.Fatalf("name after resolving: %s, want alive", st)
	}
	res, err = on.ReconcileTenant(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if st := state(tenant, svc); st == "gone" {
		t.Fatal("service still gone after its host came back")
	}
	if len(res.Reopened) != 2 {
		t.Fatalf("reopened %d, want 2", len(res.Reopened))
	}
	for id, want := range map[string]string{fSvc: "confirmed", fSvc2: "in_progress"} {
		st, _, regression, sla := status(id)
		if st != want || regression {
			t.Fatalf("finding %s: %s (regression %v), want %s, not a regression", id, st, regression, want)
		}
		if !sla.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("finding %s: SLA deadline %v changed", id, sla)
		}
	}
	if st, reason, _, _ := status(fName); st != "resolved" || reason.String != "fixed" {
		t.Fatalf("a person's close was reopened: %s/%s", st, reason.String)
	}

	// The inventory filter selects by liveness, unknown for no row.
	assets := NewAssetRepository(&DB{DB: db})
	tid := tenant.String()
	for st, want := range map[string]int{"unresolvable": 3, "alive": 1, "gone": 0} {
		f := assetdom.Filter{LivenessStates: []string{st}}
		f.TenantID = &tid
		res, err := assets.List(ctx, f, assetdom.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Data) != want {
			t.Errorf("liveness filter %s: %d assets, want %d", st, len(res.Data), want)
		}
	}

	// The API view names the tenant's last check only.
	views, err := repo.ForAssets(ctx, tenant, []shared.ID{name, theirs})
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := views[theirs]; leaked || views[name].State != "alive" {
		t.Fatalf("views: %+v", views)
	}
}

// The daily bound holds the promotions over it: a resolver that suddenly
// answers NXDOMAIN for everything cannot close the inventory at once.
func TestAssetLivenessDailyBound(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetLivenessRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	mustExec(t, db, `UPDATE tenants SET settings = '{}'::jsonb WHERE id = $1`, tenant.String())
	ids := make([]shared.ID, 0, 4)
	// d has no finding: it does not count against the bound.
	quiet := shared.NewID()
	mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'd.example.com', 'subdomain', 'active')`,
		quiet.String(), tenant.String())
	mustExec(t, db, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome, last_attempt_at, last_success_at)
		VALUES ($1, $2, 'dns.dangling', 'covered', 'ok', now(), now())`, tenant.String(), quiet.String())
	ids = append(ids, quiet)
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'subdomain', 'active')`,
			id.String(), tenant.String(), n)
		mustExec(t, db, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome, last_attempt_at, last_success_at)
			VALUES ($1, $2, 'dns.dangling', 'covered', 'ok', now(), now())`, tenant.String(), id.String())
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint)
			VALUES ($1, $2, $3, 'dast', 'tool', 'msg', 'high', 'confirmed', $4)`, shared.NewID().String(), tenant.String(), id.String(), "fp-bound-"+n)
		ids = append(ids, id)
	}
	base := time.Now().Add(-5 * 24 * time.Hour)
	for i, d := range []int{0, 1, 4} {
		obs := make([]liveness.AssetObservation, 0, len(ids))
		for _, id := range ids {
			obs = append(obs, liveness.AssetObservation{AssetID: id, Observation: liveness.Observation{
				Kind: liveness.KindNXDomain, Observer: []string{"sensor:a", "zone:b"}[i%2]}})
		}
		if _, err := repo.Observe(ctx, tenant, obs, liveness.DefaultThresholds(), base.Add(time.Duration(d)*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	svc := livenessapp.NewService(repo, boundSettings{max: 2}, nil, logger.NewNop())
	res, err := svc.ReconcileTenant(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if res.Transitions[liveness.StateGone] != 3 || res.GoneHeld != 1 {
		t.Fatalf("gone %d, held %d, want 3 (2 with findings, 1 without) and 1", res.Transitions[liveness.StateGone], res.GoneHeld)
	}
	if res, _ = svc.ReconcileTenant(ctx, tenant); res.GoneHeld != 1 {
		t.Fatalf("second pass the same day: held %d, want 1", res.GoneHeld)
	}
}

type boundSettings struct{ max int }

func (s boundSettings) GetAssetLifecycleSettings(context.Context, string) (*tenantdom.AssetLifecycleSettings, error) {
	return &tenantdom.AssetLifecycleSettings{Liveness: &tenantdom.AssetLivenessSettings{MaxGonePerDay: s.max}}, nil
}
