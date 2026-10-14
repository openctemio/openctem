package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/lib/pq"
	"github.com/openctemio/ctis/politeness"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Partial admission at claim time and host-affine chunks against a real
// schema (research/130 follow-up, live 2026-10-14). Requires DATABASE_URL.

// stepScan creates a pending nuclei command of the step run with targets,
// keyed like the step dispatcher keys a chunk (politeness.Keys, network
// none, also in the payload).
func stepScan(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, stepRun shared.ID, targets ...string) shared.ID {
	t.Helper()
	keys := politeness.Keys(targets, "")
	raw, _ := json.Marshal(map[string]any{
		"scanner": "nuclei", "preferred_tool": "nuclei", "step_key": "templates",
		"scan_run_step_id": stepRun.String(), "targets": targets, "host_keys": keys,
	})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetStepRunID(stepRun)
	cmd.HostKeys = keys
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

// runningScan creates a scan command holding targets' keys and claims it
// for sensor (another run's task, running).
func runningScan(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, sensor shared.ID, targets ...string) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": targets,
		"scan_run_id": shared.NewID().String(), "step_key": "other"})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.HostKeys = politeness.Keys(targets, "")
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.ClaimForSensor(ctx, tenant, cmd.ID, sensor.String()); err != nil || !ok {
		t.Fatalf("claim holder: %v %v", ok, err)
	}
	return cmd.ID
}

type stepRow struct {
	id      shared.ID
	status  string
	targets []string
	keys    []string
	splits  int
}

func stepRows(ctx context.Context, t *testing.T, db *sql.DB, tenant, stepRun shared.ID) []stepRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT id, status, payload, host_keys, host_splits FROM commands
		WHERE tenant_id = $1 AND scan_run_step_id = $2 ORDER BY created_at, id`, tenant.String(), stepRun.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []stepRow
	for rows.Next() {
		var r stepRow
		var id string
		var payload []byte
		if err := rows.Scan(&id, &r.status, &payload, pq.Array(&r.keys), &r.splits); err != nil {
			t.Fatal(err)
		}
		r.id = shared.MustIDFromString(id)
		var p struct {
			Targets  []string `json:"targets"`
			HostKeys []string `json:"host_keys"`
		}
		_ = json.Unmarshal(payload, &p)
		r.targets = p.Targets
		if !slices.Equal(p.HostKeys, r.keys) {
			t.Fatalf("command %s: payload host_keys %v, stored %v", id, p.HostKeys, r.keys)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// liveShape is the queued chunk of 2026-10-14: 23 targets over 21 host keys
// (20 addresses of one /24 and its bucket marker; three targets name an
// address with a port). A task of another run holds one of its addresses
// and that bucket's marker: the chunk overlaps it on 2 keys, of which only
// the address conflicts.
func liveShape() (targets, held []string) {
	for i := 1; i <= 20; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	targets = append(targets, "203.0.113.3:8443", "203.0.113.5:443", "203.0.113.7:8080")
	return targets, []string{"203.0.113.3"}
}

// The live case replayed: the sensor has one free slot, the only pending
// task waits for 2 of its 23 targets (one host). The claim splits it: the
// 21 targets on free hosts start at once on the free slot, the 2 others
// wait in a new task of the same step, which starts when the holder ends.
func TestHostSplit_LiveShapeStartsTheFreeTargets(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant := seedTestTenant(ctx, t, sqlDB)
	sensor := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)

	targets, held := liveShape()
	holder := runningScan(ctx, t, cmds, tenant, sensor, held...)
	runningScan(ctx, t, cmds, tenant, sensor, "198.51.100.1")
	runningScan(ctx, t, cmds, tenant, sensor, "198.51.100.2")
	waiting := stepScan(ctx, t, cmds, tenant, stepRun, targets...)
	if n := len(politeness.Keys(targets, "")); n != 21 {
		t.Fatalf("fixture keys %d, want 21", n)
	}

	// Before: the task is not offered (its hosts are busy).
	if offered, _ := cmds.GetPendingForSensor(ctx, tenant, &sensor, nil, 10); len(offered) != 0 {
		t.Fatalf("offered %d before the split", len(offered))
	}

	got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: sensor.String(), MaxJobs: 4, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != waiting {
		t.Fatalf("claimed %d commands, want the split task", len(got))
	}
	rows := stepRows(ctx, t, sqlDB, tenant, stepRun)
	if len(rows) != 2 {
		t.Fatalf("step commands %d, want 2", len(rows))
	}
	start, wait := rows[0], rows[1]
	if start.id != waiting || start.status != "acknowledged" || len(start.targets) != 21 || start.splits != 1 {
		t.Fatalf("started part %+v", start)
	}
	if slices.Contains(start.targets, "203.0.113.3") || slices.Contains(start.keys, "203.0.113.3") {
		t.Fatalf("the started part holds the busy host: %v", start.keys)
	}
	if wait.status != "pending" || !slices.Equal(wait.targets, []string{"203.0.113.3", "203.0.113.3:8443"}) ||
		!slices.Equal(wait.keys, []string{"203.0.113.3", "in:203.0.113.0/24"}) || wait.splits != 1 {
		t.Fatalf("waiting part %+v", wait)
	}
	// Accounting: the two parts carry every target once, under one step.
	all := append(slices.Clone(start.targets), wait.targets...)
	slices.Sort(all)
	want := slices.Clone(targets)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Fatalf("targets of the parts %v", all)
	}
	b, err := cmds.StepBatchState(ctx, tenant, stepRun)
	if err != nil {
		t.Fatal(err)
	}
	if b.Total != 2 || b.Active != 2 {
		t.Fatalf("step batch %+v: the step must wait for both parts", b)
	}

	// The waiting part starts once the holder ends (and a slot is free).
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = ANY($1)`,
		pq.Array([]string{holder.String(), start.id.String()})); err != nil {
		t.Fatal(err)
	}
	got, err = svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: sensor.String(), MaxJobs: 4, Limit: 10})
	if err != nil || len(got) != 1 || got[0].ID != wait.id {
		t.Fatalf("waiting part not claimed: %v %d", err, len(got))
	}
}

// Concurrent claims split a task once: one wins the row, the other sees it
// changed and writes nothing; a repeated pass splits nothing more.
func TestHostSplit_ConcurrentAndIdempotent(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	targets, held := liveShape()
	runningScan(ctx, t, cmds, tenant, a, held...)
	waiting := stepScan(ctx, t, cmds, tenant, stepRun, targets...)

	cands, err := cmds.HostSplitCandidates(ctx, tenant, &a, nil, 10)
	if err != nil || len(cands) != 1 || cands[0].ID != waiting {
		t.Fatalf("candidates %v %d", err, len(cands))
	}
	c := cands[0]
	keys, _, err := cmds.HostHolders(ctx, tenant, c.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := command.PartitionHeld(command.PayloadTargets(c.Payload), "", keys, held)
	if !ok || !p.Splittable() {
		t.Fatalf("partition %+v %v", p, ok)
	}
	keep, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": p.Free, "host_keys": p.FreeKeys})
	wait, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": p.Blocked, "host_keys": p.BlockedKeys})
	plan := command.HostSplit{Keep: keep, KeepKeys: p.FreeKeys, Wait: wait, WaitKeys: p.BlockedKeys}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, won, err := cmds.SplitHostBusy(ctx, c, plan)
			if err != nil {
				t.Error(err)
			}
			if won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d splits won, want 1", wins)
	}
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun); len(rows) != 2 {
		t.Fatalf("step commands %d, want 2", len(rows))
	}
	// Again through the service: the started part is free now, the waiting
	// part is all blocked: nothing to split.
	svc := commandapp.NewService(cmds, logger.NewNop())
	for i := 0; i < 3; i++ {
		if _, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: a.String(), MaxJobs: 8, Limit: 10}); err != nil {
			t.Fatal(err)
		}
	}
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun); len(rows) != 2 {
		t.Fatalf("step commands %d after repeated claims, want 2", len(rows))
	}
}

// Two sensors claiming at once split the task once and never take the same
// target twice.
func TestHostSplit_ConcurrentClaimsTwoSensors(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	targets, held := liveShape()
	runningScan(ctx, t, cmds, tenant, a, held...)
	stepScan(ctx, t, cmds, tenant, stepRun, targets...)

	var wg sync.WaitGroup
	claimed := make([][]*command.Command, 2)
	for i, s := range []shared.ID{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: s.String(), MaxJobs: 4, Limit: 10})
			if err != nil {
				t.Error(err)
			}
			claimed[i] = got
		}()
	}
	wg.Wait()
	if n := len(claimed[0]) + len(claimed[1]); n != 1 {
		t.Fatalf("%d commands claimed, want the one started part", n)
	}
	rows := stepRows(ctx, t, sqlDB, tenant, stepRun)
	if len(rows) != 2 {
		t.Fatalf("step commands %d, want 2", len(rows))
	}
}

// Bounds: a task most of whose targets wait is not split; one split
// MaxHostSplits times is not split again; another tenant's tasks never
// cause or see a split.
func TestHostSplit_Bounds(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	claim := func(tn, s shared.ID) {
		t.Helper()
		if _, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tn.String(), SensorID: s.String(), MaxJobs: 8, Limit: 10}); err != nil {
			t.Fatal(err)
		}
	}

	// Most targets busy: waits whole.
	runningScan(ctx, t, cmds, tenant, a, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	stepScan(ctx, t, cmds, tenant, stepRun, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")
	claim(tenant, a)
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun); len(rows) != 1 || rows[0].status != "pending" {
		t.Fatalf("a mostly blocked task was split or started: %+v", rows)
	}

	// At the bound: not split.
	stepRun2 := seedChunkStepRun(ctx, t, sqlDB, tenant)
	targets, held := liveShape()
	runningScan(ctx, t, cmds, tenant, a, held...)
	id := stepScan(ctx, t, cmds, tenant, stepRun2, targets...)
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET host_splits = $2 WHERE id = $1`, id.String(), command.MaxHostSplits); err != nil {
		t.Fatal(err)
	}
	claim(tenant, a)
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun2); len(rows) != 1 || rows[0].status != "pending" {
		t.Fatalf("a task at the split bound was split: %+v", rows)
	}

	// Another tenant: its holder on the same address does not hold the
	// tenant's task back, and its sensor's claims never split the tenant's
	// tasks.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET host_splits = 0 WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE tenant_id = $1 AND status <> 'pending'`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	runningScan(ctx, t, cmds, other, o, held...)
	claim(other, o)
	if c, err := cmds.HostSplitCandidates(ctx, other, &o, nil, 10); err != nil || len(c) != 0 {
		t.Fatalf("another tenant's candidates: %v %d", err, len(c))
	}
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun2); len(rows) != 1 || rows[0].splits != 0 {
		t.Fatalf("another tenant's claim split the task: %+v", rows)
	}
}

// Host-affine chunks: the chunks of one step, cut from whole hosts, never
// wait on each other; cut by position, the live shape's sibling waits.
func TestStepChunks_ClaimableTogether(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	sensor := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})

	var targets []string
	for i := 1; i <= 60; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	targets = append(targets, "203.0.113.3:8443", "203.0.113.30:443", "203.0.113.55:8080")

	claimAll := func(chunks [][]string) int {
		t.Helper()
		stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
		for _, c := range chunks {
			stepScan(ctx, t, cmds, tenant, stepRun, c...)
		}
		n := 0
		for {
			if _, ok := claimOne(ctx, t, cmds, tenant, sensor); !ok {
				break
			}
			n++
		}
		_, _ = sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE tenant_id = $1`, tenant.String())
		return n
	}
	var positional [][]string
	for i := 0; i < len(targets); i += 25 {
		positional = append(positional, targets[i:min(i+25, len(targets))])
	}
	if n := claimAll(positional); n == len(positional) {
		t.Fatal("positional chunks should hold one host twice")
	}
	// Whole hosts, three chunks.
	groups := politeness.Group(targets, "")
	affine := make([][]string, 3)
	for i, g := range groups {
		affine[i%3] = append(affine[i%3], g...)
	}
	if n := claimAll(affine); n != 3 {
		t.Fatalf("claimed %d of 3 host-affine chunks at once", n)
	}
}
