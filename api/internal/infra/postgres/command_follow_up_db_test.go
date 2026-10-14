package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Follow-up commands for unfinished targets (research/125). Requires
// DATABASE_URL (CI applies every migration first).

func httpxTargets(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("https://h%02d.example", i)
	}
	return out
}

// claimRunning has sensor claim and start the pending command id and
// returns it as read back.
func claimRunning(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant, sensor shared.ID, id shared.ID) *command.Command {
	t.Helper()
	if ok, err := cmds.ClaimForSensor(ctx, tenant, id, sensor.String()); err != nil || !ok {
		t.Fatalf("claim %s: %v %v", id, ok, err)
	}
	if _, err := cmds.db.ExecContext(ctx, `UPDATE commands SET status = 'running', started_at = NOW() WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	cmd, err := cmds.GetByTenantAndID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func newHTTPXCommand(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant shared.ID, targets []string) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": targets,
		"budget": map[string]int{"target_seconds": 30, "task_seconds": 600, "stall_seconds": 300}})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

// completeAs completes cmd as sensor with outcomes the way the command
// service does: the follow-up of its unfinished targets, if any, in the
// same transaction. Returns the follow-up's id (zero: none).
func completeAs(ctx context.Context, t *testing.T, cmds *CommandRepository, cmd *command.Command, sensor shared.ID, outs []outcome.Target) shared.ID {
	t.Helper()
	fence := command.Fence{SensorID: sensor.String(), Status: cmd.Status, Epoch: cmd.LeaseEpoch}
	res, _ := json.Marshal(map[string]any{"status": "completed", "target_outcomes": outs})
	cmd.Complete(res)
	var fu *command.Command
	if remaining, settled, ok := command.UnfinishedTargets(cmd); ok && len(remaining) > 0 {
		var err error
		if fu, err = command.NewFollowUp(cmd, remaining, settled); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := cmds.CompleteWithFollowUp(ctx, cmd, fence, fu)
	if err != nil || !applied {
		t.Fatalf("complete: %v %v", applied, err)
	}
	if fu == nil {
		return shared.ID{}
	}
	return fu.ID
}

type followUpRow struct {
	status   string
	targets  []string
	attempts int
	retryOf  sql.NullString
	sensor   sql.NullString
}

func readFollowUp(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) followUpRow {
	t.Helper()
	var r followUpRow
	var payload []byte
	if err := db.QueryRowContext(ctx, `SELECT status, payload, dispatch_attempts, retry_of::text, sensor_id::text FROM commands WHERE id = $1`, id.String()).
		Scan(&r.status, &payload, &r.attempts, &r.retryOf, &r.sensor); err != nil {
		t.Fatal(err)
	}
	r.targets = command.PayloadTargets(payload)
	return r
}

// The 2026-10-14 incident, replayed on the database: 72 httpx targets.
// Before, each stall re-queued the whole command (one more dispatch
// attempt, every target again) and the third made it COMMAND_EXHAUSTED.
// Now each run settles what it finished and only the unfinished targets go
// out again; one host that never answers exhausts only its own command.
func TestFollowUp_IncidentReplay(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	all := httpxTargets(72)
	bad := all[40]

	done := func(ts []string) []outcome.Target {
		out := make([]outcome.Target, 0, len(ts))
		for _, h := range ts {
			out = append(out, outcome.Target{Target: h, State: outcome.Done})
		}
		return out
	}

	// Run 1 stops after 30 targets (a stop by its time budget): 42 go out
	// again, with no attempt charged (the run made progress).
	first := newHTTPXCommand(ctx, t, cmds, tenant, all)
	fu := completeAs(ctx, t, cmds, claimRunning(ctx, t, cmds, tenant, a, first), a, done(all[:30]))
	row := readFollowUp(ctx, t, sqlDB, fu)
	if row.status != "pending" || !slices.Equal(row.targets, all[30:]) || row.attempts != 0 ||
		row.retryOf.String != first.String() || row.sensor.Valid {
		t.Fatalf("follow-up 1: %+v", row)
	}

	// Run 2 settles every target but the bad host.
	var rest []string
	for _, h := range all[30:] {
		if h != bad {
			rest = append(rest, h)
		}
	}
	fu = completeAs(ctx, t, cmds, claimRunning(ctx, t, cmds, tenant, a, fu), a,
		append(done(rest), outcome.Target{Target: bad, State: outcome.Unfinished}))
	if row = readFollowUp(ctx, t, sqlDB, fu); !slices.Equal(row.targets, []string{bad}) || row.attempts != 0 {
		t.Fatalf("follow-up 2: %+v", row)
	}

	// The bad host alone: each run settles nothing, so each counts.
	for want := 1; want <= 3; want++ {
		fu = completeAs(ctx, t, cmds, claimRunning(ctx, t, cmds, tenant, a, fu), a, []outcome.Target{{Target: bad, State: outcome.Unfinished}})
		if row = readFollowUp(ctx, t, sqlDB, fu); row.attempts != want {
			t.Fatalf("bad-host chunk attempts %d, want %d", row.attempts, want)
		}
	}
	failed, err := cmds.FailExhaustedCommandsReturning(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	var exhausted []string
	for _, c := range failed {
		if c.TenantID == tenant {
			exhausted = append(exhausted, c.ID.String())
		}
	}
	if !slices.Equal(exhausted, []string{fu.String()}) {
		t.Fatalf("exhausted %v, want only the bad host's chunk %s", exhausted, fu)
	}

	// 71 targets settled across the chain; none was run twice.
	var settled int
	rows, err := sqlDB.QueryContext(ctx, `SELECT result FROM commands WHERE tenant_id = $1 AND status = 'completed'`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var res struct {
			Outcomes []outcome.Target `json:"target_outcomes"`
		}
		_ = json.Unmarshal(raw, &res)
		for _, o := range res.Outcomes {
			if o.Settled() {
				if seen[o.Target] {
					t.Fatalf("%s settled twice", o.Target)
				}
				seen[o.Target] = true
				settled++
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if settled != 71 || seen[bad] {
		t.Fatalf("settled %d targets (bad host settled: %v)", settled, seen[bad])
	}
}

// The completion and its follow-up are one write: a completion the fence
// refuses (the lease moved on) inserts no follow-up, and a follow-up of
// another tenant's command is never inserted.
func TestCompleteWithFollowUp_FenceAndTenant(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	targets := httpxTargets(3)

	countFollowUps := func(parent shared.ID) int {
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands WHERE retry_of = $1`, parent.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	id := newHTTPXCommand(ctx, t, cmds, tenant, targets)
	cmd := claimRunning(ctx, t, cmds, tenant, a, id)
	stale := command.Fence{SensorID: a.String(), Status: cmd.Status, Epoch: cmd.LeaseEpoch + 1}
	res, _ := json.Marshal(map[string]any{"target_outcomes": []outcome.Target{{Target: targets[0], State: outcome.Done}}})
	cmd.Complete(res)
	fu, err := command.NewFollowUp(cmd, targets[1:], 1)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := cmds.CompleteWithFollowUp(ctx, cmd, stale, fu); err != nil || applied {
		t.Fatalf("a stale completion applied: %v %v", applied, err)
	}
	if n := countFollowUps(id); n != 0 {
		t.Fatalf("%d follow-ups of a refused completion", n)
	}

	fu.TenantID = other
	fence := command.Fence{SensorID: a.String(), Status: command.CommandStatusRunning, Epoch: cmd.LeaseEpoch}
	if applied, err := cmds.CompleteWithFollowUp(ctx, cmd, fence, fu); err == nil || applied {
		t.Fatalf("a cross-tenant follow-up was accepted: %v %v", applied, err)
	}
	if n := countFollowUps(id); n != 0 {
		t.Fatalf("%d cross-tenant follow-ups", n)
	}
	var status string
	_ = sqlDB.QueryRowContext(ctx, `SELECT status FROM commands WHERE id = $1`, id.String()).Scan(&status)
	if status != "running" {
		t.Fatalf("command %s after refused completions", status)
	}
}

// A step run by one command waits for that command's follow-up: the step
// settles with the last command carrying its id, so the unfinished targets'
// results count towards the step.
func TestFollowUp_StepWaitsForIt(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	targets := httpxTargets(4)
	raw, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": targets,
		"scan_run_id": shared.NewID().String(), "step_key": "probe", "scan_run_step_id": stepRun.String()})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetStepRunID(stepRun)
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	if b, err := cmds.StepBatchState(ctx, tenant, stepRun); err != nil || b.Total != 1 {
		t.Fatalf("one command: %+v %v", b, err)
	}
	fu := completeAs(ctx, t, cmds, claimRunning(ctx, t, cmds, tenant, a, cmd.ID), a,
		[]outcome.Target{{Target: targets[0], State: outcome.Done}, {Target: targets[1], State: outcome.Done}})
	b, err := cmds.StepBatchState(ctx, tenant, stepRun)
	if err != nil || b.Total != 2 || b.Active != 1 {
		t.Fatalf("after the partial completion: %+v %v (the step must wait)", b, err)
	}
	completeAs(ctx, t, cmds, claimRunning(ctx, t, cmds, tenant, a, fu), a,
		[]outcome.Target{{Target: targets[2], State: outcome.Done}, {Target: targets[3], State: outcome.Failed, Class: outcome.Timeout}})
	if b, err = cmds.StepBatchState(ctx, tenant, stepRun); err != nil || b.Total != 2 || b.Active != 0 || b.Failed != 0 {
		t.Fatalf("after the follow-up: %+v %v", b, err)
	}
}
