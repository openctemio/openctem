package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedNamedAsset(ctx context.Context, t *testing.T, r *EASMDNSRepository, tenant shared.ID, name, typ, status string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, $5)`,
		id.String(), tenant.String(), name, typ, status); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

// The DNS checks against the real schema (migration 000325): which names are
// due, rotation, tenant isolation, and resolve/reopen that only ever touch
// this source's own active or self-resolved exposures. Requires DATABASE_URL.
func TestEASMDNSRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	r := NewEASMDNSRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	sub := seedNamedAsset(ctx, t, r, tenant, "shop.acme.example.com", "subdomain", "active")
	root := seedNamedAsset(ctx, t, r, tenant, "acme.example.com", "domain", "active")
	rejected := seedNamedAsset(ctx, t, r, tenant, "notours.example.com", "subdomain", "active")
	seedNamedAsset(ctx, t, r, tenant, "old.acme.example.com", "subdomain", "inactive")
	seedNamedAsset(ctx, t, r, tenant, "10.0.0.1", "ip_address", "active")
	seedNamedAsset(ctx, t, r, other, "theirs.example.com", "domain", "active")
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'rejected', 0)`,
		rejected.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	due, err := r.DueTargets(ctx, tenant, easmdns.KindDangling, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("dangling targets = %+v, want the active domain and subdomain only", due)
	}
	email, _ := r.DueTargets(ctx, tenant, easmdns.KindEmail, now, 10)
	if len(email) != 1 || email[0].AssetID != root {
		t.Fatalf("email targets = %+v, want the domain only", email)
	}

	// Rotation: a checked name is not due again until checkedBefore passes it.
	if err := r.SaveState(ctx, tenant, sub, easmdns.KindDangling, easmdns.OutcomeOK, "", now); err != nil {
		t.Fatal(err)
	}
	due, _ = r.DueTargets(ctx, tenant, easmdns.KindDangling, now.Add(-time.Hour), 10)
	if len(due) != 1 || due[0].AssetID != root {
		t.Fatalf("after a check: %+v", due)
	}
	due, _ = r.DueTargets(ctx, tenant, easmdns.KindDangling, now.Add(time.Hour), 1)
	if len(due) != 1 || due[0].AssetID != root {
		t.Fatalf("never-checked must come first: %+v", due)
	}
	// SaveState on another tenant's asset writes nothing.
	theirs, _ := r.DueTargets(ctx, other, easmdns.KindDangling, now, 10)
	if err := r.SaveState(ctx, tenant, theirs[0].AssetID, easmdns.KindDangling, "ok", "", now); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM easm_dns_check_state WHERE asset_id = $1`, theirs[0].AssetID.String()).Scan(&n)
	if n != 0 {
		t.Fatal("state written for another tenant's asset")
	}

	// Exposures: ours (active), another source's (active), ours accepted.
	exp := NewExposureRepository(db)
	mk := func(title, source string) *exposure.ExposureEvent {
		ev, err := exposure.NewExposureEvent(tenant, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, title, source, map[string]any{"domain": title})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	ours, foreign, accepted := mk("Dangling CNAME: a", easmdns.Source), mk("Dangling CNAME: b", "other_tool"), mk("Dangling CNAME: c", easmdns.Source)
	if err := exp.BulkUpsert(ctx, []*exposure.ExposureEvent{ours, foreign, accepted}); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE exposure_events SET state = 'accepted' WHERE tenant_id = $1 AND fingerprint = $2`, tenant.String(), accepted.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	fps := []string{ours.Fingerprint(), foreign.Fingerprint(), accepted.Fingerprint()}
	if n, err := r.ResolveAuto(ctx, other, easmdns.Source, fps, easmdns.AutoResolveNote); err != nil || n != 0 {
		t.Fatalf("another tenant resolved %d (%v)", n, err)
	}
	if n, err := r.ResolveAuto(ctx, tenant, easmdns.Source, fps, easmdns.AutoResolveNote); err != nil || n != 1 {
		t.Fatalf("resolve: %d %v, want only our active one", n, err)
	}
	state := func(fp string) string {
		var s string
		_ = sqlDB.QueryRowContext(ctx, `SELECT state FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`, tenant.String(), fp).Scan(&s)
		return s
	}
	if state(ours.Fingerprint()) != "resolved" || state(foreign.Fingerprint()) != "active" || state(accepted.Fingerprint()) != "accepted" {
		t.Fatal("resolve touched the wrong exposures")
	}
	var hist int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM exposure_state_history h JOIN exposure_events e ON e.id = h.exposure_event_id
		WHERE e.fingerprint = $1 AND h.new_state = 'resolved'`, ours.Fingerprint()).Scan(&hist)
	if hist != 1 {
		t.Fatalf("resolution history rows = %d", hist)
	}
	// A person's resolution (other note) is never reopened; ours is.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE exposure_events SET state = 'resolved', resolution_notes = 'fixed by hand' WHERE fingerprint = $1`, foreign.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ReopenAuto(ctx, tenant, easmdns.Source, fps, easmdns.AutoResolveNote); err != nil || n != 1 || state(ours.Fingerprint()) != "active" {
		t.Fatalf("reopen: %d %v state=%s", n, err, state(ours.Fingerprint()))
	}
	if state(foreign.Fingerprint()) != "resolved" {
		t.Fatal("a resolution by a person was reopened")
	}

	// Lock: one holder per tenant and kind.
	rel, ok, err := r.TryLockTenant(ctx, tenant, easmdns.KindDangling)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, ok, _ := NewEASMDNSRepository(db).TryLockTenant(ctx, tenant, easmdns.KindDangling); ok {
		t.Fatal("second holder took the lock")
	}
	if rel2, ok, _ := r.TryLockTenant(ctx, tenant, easmdns.KindEmail); !ok {
		t.Fatal("email lock blocked by the dangling lock")
	} else {
		rel2()
	}
	rel()
}

// Every exposure type the domain knows is accepted by the database CHECK
// constraint, so a new type cannot ship without its migration.
func TestExposureEventTypes_MatchTheCheckConstraint(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	exp := NewExposureRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	for _, typ := range exposure.AllEventTypes() {
		ev, err := exposure.NewExposureEvent(tenant, typ, exposure.SeverityLow, "type check "+string(typ), "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := exp.BulkUpsert(ctx, []*exposure.ExposureEvent{ev}); err != nil {
			t.Errorf("event type %q rejected by the database: %v", typ, err)
		}
	}
}

// 22c B3: the email check takes root-domain seeds and verified domains with
// no domain asset by name, never another tenant's, never a rejected
// (tombstoned) name, and drops the name once a domain asset covers it.
func TestEASMDNSRepository_EmailNameTargets(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewEASMDNSRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed := func(tn shared.ID, v string, on bool) {
		exec(`INSERT INTO easm_seeds (id, tenant_id, kind, value, discovery_enabled) VALUES ($1, $2, 'root_domain', $3, $4)`,
			shared.NewID().String(), tn.String(), v, on)
	}
	seed(tenant, "seeded.example", true)
	seed(tenant, "paused.example", false)
	seed(tenant, "covered.example", true)
	seed(tenant, "rejected.example", true)
	seed(other, "theirs.example", true)
	exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status) VALUES ($1, $2, 'verified.example', 'x', 'verified')`,
		shared.NewID().String(), tenant.String())
	exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status) VALUES ($1, $2, 'pending.example', 'x', 'pending')`,
		shared.NewID().String(), tenant.String())
	exec(`INSERT INTO easm_tombstones (tenant_id, name) VALUES ($1, 'rejected.example')`, tenant.String())
	covered := seedNamedAsset(ctx, t, r, tenant, "covered.example", "domain", "active")

	now := time.Now().UTC()
	names := func() map[string]shared.ID {
		t.Helper()
		due, err := r.DueTargets(ctx, tenant, easmdns.KindEmail, now, 50)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]shared.ID{}
		for _, d := range due {
			out[d.Name] = d.AssetID
		}
		return out
	}
	got := names()
	want := map[string]bool{"seeded.example": true, "verified.example": true, "covered.example": true}
	if len(got) != len(want) {
		t.Fatalf("email targets = %v", got)
	}
	for n := range want {
		if _, ok := got[n]; !ok {
			t.Fatalf("missing %s in %v", n, got)
		}
	}
	if got["covered.example"] != covered || !got["seeded.example"].IsZero() {
		t.Fatalf("asset/name targets mixed up: %v", got)
	}

	// A checked name is not due again until the window passes.
	if err := r.SaveNameState(ctx, tenant, "seeded.example", easmdns.KindEmail, easmdns.OutcomeOK, "", now); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveState(ctx, tenant, shared.ID{}, easmdns.KindEmail, easmdns.OutcomeOK, "", now); err == nil {
		t.Fatal("SaveState without an asset must refuse")
	}
	due, _ := r.DueTargets(ctx, tenant, easmdns.KindEmail, now.Add(-time.Hour), 50)
	for _, d := range due {
		if d.Name == "seeded.example" {
			t.Fatal("checked name is due again")
		}
	}
	// The dangling check never takes name targets; another tenant sees only its own.
	if dang, _ := r.DueTargets(ctx, tenant, easmdns.KindDangling, now, 50); len(dang) != 1 {
		t.Fatalf("dangling targets = %+v", dang)
	}
	theirs, _ := r.DueTargets(ctx, other, easmdns.KindEmail, now, 50)
	if len(theirs) != 1 || theirs[0].Name != "theirs.example" {
		t.Fatalf("tenant B email targets = %+v", theirs)
	}
}
