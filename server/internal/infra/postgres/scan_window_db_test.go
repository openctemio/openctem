package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan window storage against a real schema (RFC-067; migration 001760):
// policies and overrides are tenant-scoped, selector ids must be the
// tenant's own, the assets behind targets are matched in one query, and the
// claim's and the closing-window controller's writes apply only to the
// command as it was read. Requires DATABASE_URL.

func swPolicy(t *testing.T, tenant shared.ID, name string, sel swdom.Selector) *swdom.Policy {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p, err := swdom.NewPolicy(tenant, swdom.Spec{Name: name, Kind: swdom.KindAllow, MinTier: 1, Timezone: "Europe/Berlin",
		Enabled: true, Selector: sel, Slots: []swdom.Slot{{Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "17:00"}},
		OneOffs:      []swdom.OneOff{{StartsAt: now.Add(time.Hour), EndsAt: now.Add(2 * time.Hour)}},
		GraceMinutes: 15, RateLimitRPS: 5, MaxConcurrent: 2}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanWindowPolicyRepository_CRUDAndIsolation(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanWindowPolicyRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	p := swPolicy(t, tenant, "business hours", swdom.Selector{Tags: []string{"prod"}, Criticalities: []string{"critical"}})
	if err := repo.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, tenant, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != p.Name || got.Kind != swdom.KindAllow || got.Timezone != "Europe/Berlin" || len(got.Slots) != 1 ||
		got.Slots[0].Start != "09:00" || len(got.OneOffs) != 1 || !got.OneOffs[0].StartsAt.Equal(p.OneOffs[0].StartsAt) ||
		got.Selector.Tags[0] != "prod" || got.RateLimitRPS != 5 || got.MaxConcurrent != 2 || got.GraceMinutes != 15 {
		t.Fatalf("round trip = %+v", got)
	}
	// Another tenant never reads, changes or deletes it.
	if _, err := repo.GetByID(ctx, other, p.ID); !errors.Is(err, swdom.ErrNotFound) {
		t.Fatalf("get across tenants: %v", err)
	}
	foreign := *got
	foreign.TenantID = other
	if err := repo.Update(ctx, &foreign); !errors.Is(err, swdom.ErrNotFound) {
		t.Fatalf("update across tenants: %v", err)
	}
	if err := repo.Delete(ctx, other, p.ID); !errors.Is(err, swdom.ErrNotFound) {
		t.Fatalf("delete across tenants: %v", err)
	}
	if ps, _ := repo.List(ctx, other, swdom.Filter{}); len(ps) != 0 {
		t.Fatalf("another tenant lists %d policies", len(ps))
	}
	got.Enabled = false
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if ps, _ := repo.List(ctx, tenant, swdom.Filter{EnabledOnly: true}); len(ps) != 0 {
		t.Fatal("a disabled policy listed as enabled")
	}
	if n, _ := repo.Count(ctx, tenant); n != 1 {
		t.Fatalf("count = %d", n)
	}
	// The database refuses what the domain refuses, too.
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_window_policies (id, tenant_id, name, kind, timezone, rate_limit_rps, slots)
		VALUES ($1, $2, 'x', 'blackout', 'UTC', 5, '[{"days":[1],"start":"01:00","end":"02:00"}]')`, shared.NewID().String(), tenant.String()); err == nil {
		t.Fatal("a blackout with a rate cap was stored")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_window_policies (id, tenant_id, name, kind, timezone)
		VALUES ($1, $2, 'x', 'allow', 'UTC')`, shared.NewID().String(), tenant.String()); err == nil {
		t.Fatal("a policy without any window was stored")
	}
	if err := repo.Delete(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestScanWindowPolicyRepository_CheckReferences(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanWindowPolicyRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	group := func(tid shared.ID) string {
		var id string
		if err := db.QueryRowContext(ctx, `INSERT INTO asset_groups (tenant_id, name) VALUES ($1, 'g') RETURNING id`, tid.String()).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	zone := func(tid shared.ID) string {
		var id string
		if err := db.QueryRowContext(ctx, `INSERT INTO scan_zones (tenant_id, name, ranges) VALUES ($1, $2, '{10.77.0.0/16}') RETURNING id`, tid.String(), "z-"+shared.NewID().String()[:8]).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	own, foreign := group(tenant), group(other)
	if err := repo.CheckReferences(ctx, tenant, swdom.Selector{AssetGroupIDs: []string{own}, ScanZoneIDs: []string{zone(tenant)}}); err != nil {
		t.Fatalf("own references refused: %v", err)
	}
	for name, sel := range map[string]swdom.Selector{
		"another tenant's group": {AssetGroupIDs: []string{own, foreign}},
		"another tenant's zone":  {ScanZoneIDs: []string{zone(other)}},
		"unknown unit":           {BusinessUnitIDs: []string{shared.NewID().String()}},
		"unknown scope entry":    {ScopeTargetIDs: []string{shared.NewID().String()}},
		"unknown program":        {ProgramIDs: []string{shared.NewID().String()}},
	} {
		if err := repo.CheckReferences(ctx, tenant, sel); !errors.Is(err, swdom.ErrUnknownReference) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestScanWindowOverrideRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	policies := NewScanWindowPolicyRepository(&DB{DB: db})
	repo := NewScanWindowOverrideRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	p := swPolicy(t, tenant, "business hours", swdom.Selector{})
	if err := policies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	// A policy of another tenant fails the composite key.
	cross, _ := swdom.NewOverride(other, &p.ID, "incident 4711 rescan now", time.Hour, nil, now)
	if err := repo.Create(ctx, cross); !errors.Is(err, swdom.ErrNotFound) {
		t.Fatalf("override of another tenant's policy: %v", err)
	}
	o, _ := swdom.NewOverride(tenant, &p.ID, "incident 4711 rescan now", time.Hour, nil, now)
	if err := repo.Create(ctx, o); err != nil {
		t.Fatal(err)
	}
	active, err := repo.ListActive(ctx, tenant, now.Add(time.Minute))
	if err != nil || len(active) != 1 || active[0].PolicyName != "business hours" {
		t.Fatalf("active = %+v %v", active, err)
	}
	if a, _ := repo.ListActive(ctx, tenant, now.Add(2*time.Hour)); len(a) != 0 {
		t.Fatal("an expired override is active")
	}
	if a, _ := repo.ListActive(ctx, other, now.Add(time.Minute)); len(a) != 0 {
		t.Fatal("another tenant sees the override")
	}
	if err := repo.Revoke(ctx, other, o.ID, shared.NewID(), now); !errors.Is(err, swdom.ErrOverrideNotFound) {
		t.Fatalf("revoke across tenants: %v", err)
	}
	user := seedSWUser(ctx, t, db)
	if err := repo.Revoke(ctx, tenant, o.ID, user, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a, _ := repo.ListActive(ctx, tenant, now.Add(2*time.Minute)); len(a) != 0 {
		t.Fatal("a revoked override is active")
	}
	if err := repo.Revoke(ctx, tenant, o.ID, user, now.Add(time.Minute)); !errors.Is(err, swdom.ErrOverrideNotFound) {
		t.Fatalf("revoked twice: %v", err)
	}
	// More than 24 hours is refused by the database too.
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_window_overrides (id, tenant_id, reason, starts_at, ends_at)
		VALUES ($1, $2, 'a long enough reason', NOW(), NOW() + interval '25 hours')`, shared.NewID().String(), tenant.String()); err == nil {
		t.Fatal("a 25-hour override was stored")
	}
	// Deleting the policy deletes its overrides.
	if err := policies.Delete(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByID(ctx, tenant, o.ID); !errors.Is(err, swdom.ErrOverrideNotFound) {
		t.Fatalf("override of a deleted policy: %v", err)
	}
}

func seedSWUser(ctx context.Context, t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'sw')`,
		id.String(), "sw-"+id.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func TestScanWindowAssets_MatchTargets(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanWindowAssetRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := func(tid shared.ID, name, typ, crit string, tags string) string {
		var id string
		if err := db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type, criticality, tags)
			VALUES ($1, $2, $3, $4, $5::text[]) RETURNING id`, tid.String(), name, typ, crit, tags).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	api := asset(tenant, "api.example.com", "domain", "critical", "{prod,business-hours}")
	ip1 := asset(tenant, "10.9.0.1", "ip_address", "high", "{}")
	_ = asset(tenant, "10.9.1.1", "ip_address", "high", "{}")
	gone := asset(tenant, "gone.example.com", "domain", "low", "{}")
	_ = asset(other, "other.example.com", "domain", "low", "{prod}")
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	var group, unit string
	if err := db.QueryRowContext(ctx, `INSERT INTO asset_groups (tenant_id, name) VALUES ($1, 'g') RETURNING id`, tenant.String()).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, group, api); err != nil {
		t.Fatal(err)
	}
	unit = shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'u')`, unit, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
		shared.NewID().String(), tenant.String(), unit, ip1); err != nil {
		t.Fatal(err)
	}

	got, err := repo.MatchTargetAssets(ctx, tenant, []string{"https://API.example.com/login", "10.9.0.0/24", "gone.example.com", "other.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	a := got["https://API.example.com/login"]
	if len(a) != 1 || a[0].ID != api || a[0].Criticality != "critical" || len(a[0].Tags) != 2 || len(a[0].GroupIDs) != 1 || a[0].GroupIDs[0] != group {
		t.Fatalf("URL target = %+v", a)
	}
	if c := got["10.9.0.0/24"]; len(c) != 1 || c[0].ID != ip1 || len(c[0].BusinessUnitIDs) != 1 || c[0].BusinessUnitIDs[0] != unit {
		t.Fatalf("CIDR target = %+v, want only the IP inside the range with its unit", c)
	}
	if len(got["gone.example.com"]) != 0 || len(got["other.example.com"]) != 0 {
		t.Fatalf("a deleted or another tenant's asset matched: %+v", got)
	}

	total, list, err := repo.MatchingAssets(ctx, tenant, swdom.Selector{Tags: []string{"PROD"}}, 50)
	if err != nil || total != 1 || len(list) != 1 || list[0].ID != api {
		t.Fatalf("matching by tag = %d %+v %v", total, list, err)
	}
	if total, _, _ := repo.MatchingAssets(ctx, tenant, swdom.Selector{BusinessUnitIDs: []string{unit}, Criticalities: []string{"high"}}, 50); total != 1 {
		t.Fatalf("matching by unit and criticality = %d", total)
	}
	aid, _ := shared.IDFromString(api)
	foreignAsset := seedTestAsset(ctx, t, db, other)
	names, err := repo.AssetNames(ctx, tenant, []shared.ID{aid, foreignAsset})
	if err != nil || len(names) != 1 || names[aid] != "api.example.com" {
		t.Fatalf("names = %v %v", names, err)
	}
}

func TestCommandWindowHold_Storage(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	runs := NewScanRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	stepRun := seedChunkStepRun(ctx, t, db, tenant)
	var runID string
	if err := db.QueryRowContext(ctx, `SELECT scan_run_id FROM scan_run_steps WHERE id = $1`, stepRun.String()).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET started_at = NOW(), deadline_at = NOW() + interval '1 hour' WHERE id = $1`, runID); err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"scan_run_id":"` + runID + `","targets":["a.example.com","b.example.com"]}`)
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetStepRunID(stepRun)
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	cmd, _ = repo.GetByTenantAndID(ctx, tenant, cmd.ID)
	expiresBefore := *cmd.ExpiresAt

	opens := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	hold := json.RawMessage(`{"reason":"window","checked_at":"2026-10-05T10:00:00Z"}`)
	def := command.WindowDeferral{Until: until, Hold: hold, ExtendExpiry: true, RunOpensAt: &opens}

	// Never across tenants.
	foreign := *cmd
	foreign.TenantID = other
	if ok, err := repo.DeferPending(ctx, &foreign, def); err != nil || ok {
		t.Fatalf("deferred across tenants: %v %v", ok, err)
	}
	if ok, err := repo.DeferPending(ctx, cmd, def); err != nil || !ok {
		t.Fatalf("defer: %v %v", ok, err)
	}
	got, _ := repo.GetByTenantAndID(ctx, tenant, cmd.ID)
	if got.ScheduledAt == nil || !got.ScheduledAt.Equal(until) || !got.ExpiresAt.After(expiresBefore.Add(50*time.Minute)) {
		t.Fatalf("deferred command: scheduled %v expires %v (was %v)", got.ScheduledAt, got.ExpiresAt, expiresBefore)
	}
	var deadline time.Time
	if err := db.QueryRowContext(ctx, `SELECT deadline_at FROM scan_runs WHERE id = $1`, runID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if !deadline.After(opens) {
		t.Fatalf("run deadline %v did not move past the opening %v", deadline, opens)
	}
	// A deferred job is neither offered nor claimable by id before then.
	sensor := seedJobSensor(ctx, t, db, tenant)
	pending, err := repo.GetPendingForSensor(ctx, tenant, &sensor, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range pending {
		if c.ID == cmd.ID {
			t.Fatal("a deferred job was offered")
		}
	}
	if ok, err := repo.ClaimForSensor(ctx, tenant, cmd.ID, sensor.String()); err != nil || ok {
		t.Fatalf("a deferred job was claimed by id: %v %v", ok, err)
	}
	// The unclaimed-run reaper leaves a run that waits for its window.
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET started_at = NOW() - interval '5 hours' WHERE id = $1`, runID); err != nil {
		t.Fatal(err)
	}
	if reaped, err := runs.AbortUnclaimedRunsReporting(ctx, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range reaped {
			if r.RunID.String() == runID {
				t.Fatal("a run waiting for its scan window was reaped as unclaimed")
			}
		}
	}
	// The run timeline reads the hold of the queued task.
	tasks, _, err := repo.ListRunTasks(ctx, tenant, shared.MustIDFromString(runID), 10)
	if err != nil || len(tasks) != 1 || tasks[0].WindowHold == nil || tasks[0].WindowHold.Reason != "window" {
		t.Fatalf("tasks = %+v %v", tasks, err)
	}
	// A policy change releases it: due now, offered again.
	if n, err := repo.ReleaseWindowHolds(ctx, other); err != nil || n != 0 {
		t.Fatalf("another tenant released %d: %v", n, err)
	}
	if n, err := repo.ReleaseWindowHolds(ctx, tenant); err != nil || n != 1 {
		t.Fatalf("released %d: %v", n, err)
	}

	// Split: the job keeps a, a sibling of the same step waits with b.
	got, _ = repo.GetByTenantAndID(ctx, tenant, cmd.ID)
	keep := json.RawMessage(`{"scan_run_id":"` + runID + `","targets":["a.example.com"]}`)
	wait := json.RawMessage(`{"scan_run_id":"` + runID + `","targets":["b.example.com"]}`)
	if _, ok, err := repo.SplitPending(ctx, &foreign, keep, wait, def); err != nil || ok {
		t.Fatalf("split across tenants: %v %v", ok, err)
	}
	sib, ok, err := repo.SplitPending(ctx, got, keep, wait, def)
	if err != nil || !ok {
		t.Fatalf("split: %v %v", ok, err)
	}
	if _, ok, _ := repo.SplitPending(ctx, got, keep, wait, def); ok {
		t.Fatal("a stale read split twice")
	}
	s, err := repo.GetByTenantAndID(ctx, tenant, sib)
	var sp struct {
		Targets []string `json:"targets"`
	}
	if err == nil {
		_ = json.Unmarshal(s.Payload, &sp)
	}
	if err != nil || s.StepRunID == nil || *s.StepRunID != stepRun || s.ScheduledAt == nil || len(sp.Targets) != 1 || sp.Targets[0] != "b.example.com" {
		t.Fatalf("sibling = %+v %v", s, err)
	}
	if st, err := repo.StepBatchState(ctx, tenant, stepRun); err != nil || st.Total != 2 || st.Active != 2 {
		t.Fatalf("the step must count both jobs: %+v %v", st, err)
	}

	// Concurrency bookkeeping.
	pid := shared.NewID().String()
	got, _ = repo.GetByTenantAndID(ctx, tenant, cmd.ID)
	if ok, err := repo.RecordWindowPolicies(ctx, got, []string{pid}); err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	if ok, err := repo.ClaimForSensor(ctx, tenant, cmd.ID, sensor.String()); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if n, err := repo.CountRunningUnderPolicies(ctx, tenant, []string{pid}); err != nil || n[pid] != 1 {
		t.Fatalf("running under policy = %v %v", n, err)
	}
	if n, _ := repo.CountRunningUnderPolicies(ctx, other, []string{pid}); n[pid] != 0 {
		t.Fatal("another tenant counts the job")
	}

	// The closing-window controller: mark, then requeue under the epoch read.
	running, err := repo.RunningProbing(ctx, tenant, 10)
	if err != nil || len(running) != 1 || running[0].Command.ID != cmd.ID {
		t.Fatalf("running = %+v %v", running, err)
	}
	if other, _ := repo.RunningProbing(ctx, other, 10); len(other) != 0 {
		t.Fatal("another tenant lists the running job")
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := repo.MarkWindowClosed(ctx, tenant, []shared.ID{cmd.ID}, at); err != nil {
		t.Fatal(err)
	}
	running, _ = repo.RunningProbing(ctx, tenant, 10)
	if running[0].WindowClosedAt == nil || !running[0].WindowClosedAt.Equal(at) {
		t.Fatalf("mark = %v", running[0].WindowClosedAt)
	}
	stale := *running[0]
	stale.LeaseEpoch--
	if ok, err := repo.RequeueForWindow(ctx, &stale, def); err != nil || ok {
		t.Fatalf("a stale epoch requeued: %v %v", ok, err)
	}
	if ok, err := repo.RequeueForWindow(ctx, running[0], def); err != nil || !ok {
		t.Fatalf("requeue: %v %v", ok, err)
	}
	got, _ = repo.GetByTenantAndID(ctx, tenant, cmd.ID)
	if got.Status != command.CommandStatusPending || got.SensorID != nil || got.ScheduledAt == nil || got.DispatchAttempts != 0 {
		t.Fatalf("requeued = %+v", got)
	}
	// The old holder is told to stop.
	cancel, err := repo.CommandsToCancel(ctx, tenant, sensor, []string{cmd.ID.String()})
	if err != nil || len(cancel) != 1 {
		t.Fatalf("cancel list = %v %v", cancel, err)
	}
}

func TestScanWindowPolicyRepository_TenantsWithWindows(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanWindowPolicyRepository(&DB{DB: db})
	tenant, quiet := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	if err := repo.Create(ctx, swPolicy(t, tenant, "p", swdom.Selector{})); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.TenantsWithWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[shared.ID]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found[tenant] || found[quiet] {
		t.Fatalf("tenants with windows: has policy tenant %v, has quiet tenant %v", found[tenant], found[quiet])
	}
}
