package postgres

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Short and long work on one sensor (command_claim_lanes.go), against the
// real SQL. The fixture sensor measured nuclei at half a target per minute
// (a one-target job: 2 min, ten targets: 20 min) and dnsx at 200 targets
// per minute.

// reportSpeeds gives the fixture sensor a fresh load report with the tools'
// speeds (targets per minute); age makes it that old.
func (f *fairFixture) reportSpeeds(age time.Duration) {
	f.t.Helper()
	capacity := map[string]any{
		"slots_total": 1, "slots_free": 1, "active_jobs": 0,
		"per_tool": map[string]any{
			"nuclei": map[string]any{"throughput_targets_per_min": 0.5},
			"dnsx":   map[string]any{"throughput_targets_per_min": 200},
		},
	}
	raw, _ := json.Marshal(capacity)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE sensors SET reported_capacity = $1::jsonb,
		load_reported_at = NOW() - make_interval(secs => $2) WHERE id = $3`,
		string(raw), age.Seconds(), f.sensor.String()); err != nil {
		f.t.Fatal(err)
	}
}

// addTool creates a pending command of run for tool with n targets, created
// age ago.
func (f *fairFixture) addTool(run, tool string, n int, age time.Duration) shared.ID {
	f.t.Helper()
	// Distinct hosts per command: a held command's hosts are busy for the
	// others (hostFreePredicate).
	f.n++
	targets := make([]string, n)
	for i := range targets {
		targets[i] = fmt.Sprintf("h%d-%d.example.test", f.n, i)
	}
	payload := map[string]any{"scanner": tool, "targets": targets}
	if run != "" {
		payload["scan_run_id"] = run
	}
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(f.tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	f.n++
	cmd.CreatedAt = time.Now().Add(-age).Add(time.Duration(f.n) * time.Millisecond)
	if err := f.cmds.Create(f.ctx, cmd); err != nil {
		f.t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

// hold makes the fixture sensor hold id since claimedAgo; endedAgo > 0
// marks it completed that long ago instead.
func (f *fairFixture) hold(id shared.ID, claimedAgo, endedAgo time.Duration) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, `UPDATE commands SET sensor_id = $1,
		status = CASE WHEN $3::float8 > 0 THEN 'completed' ELSE 'running' END,
		acknowledged_at = NOW() - make_interval(secs => $2::float8),
		completed_at = CASE WHEN $3::float8 > 0 THEN NOW() - make_interval(secs => $3::float8) END
		WHERE id = $4`, f.sensor.String(), claimedAgo.Seconds(), endedAgo.Seconds(), id.String()); err != nil {
		f.t.Fatal(err)
	}
}

// The prod case (2026-11-04): a batch of long jobs of several runs, queued
// an hour before a discovery run, holds the sensor's slot. The discovery
// run's short job must be the next one claimed, not the last.
func TestFairPoll_ShortWorkNotStarvedBehindLongBatch(t *testing.T) {
	f := newFairFixture(t)
	f.reportSpeeds(0)
	var long []shared.ID
	for range 6 {
		run := shared.NewID().String()
		for range 4 {
			long = append(long, f.addTool(run, "nuclei", 10, 70*time.Minute))
		}
	}
	f.hold(long[0], 20*time.Minute, 0)
	discovery := shared.NewID().String()
	short := f.addTool(discovery, "dnsx", 50, 0)

	got := f.poll(1)
	if len(got) != 1 || got[0] != short {
		t.Fatalf("next claim = %v, want the discovery run's short job %v first", got, short)
	}
}

// Without a fresh load report nothing is known to be short: the order is
// the previous one (class, round-robin, age), so the old batch goes first.
func TestFairPoll_NoFreshSpeedsKeepsPreviousOrder(t *testing.T) {
	f := newFairFixture(t)
	f.reportSpeeds(10 * time.Minute) // stale
	old := f.addTool(shared.NewID().String(), "nuclei", 10, 70*time.Minute)
	f.addTool(shared.NewID().String(), "dnsx", 50, 0)
	if got := f.poll(1); len(got) != 1 || got[0] != old {
		t.Fatalf("next claim = %v, want the oldest job %v (no lanes without fresh speeds)", got, old)
	}
}

// Long work keeps its half of the sensor's time: once short jobs held the
// sensor longer than long jobs in the last hour, a long job goes before a
// fresher short one.
func TestFairPoll_LongWorkKeepsHalfTheSensor(t *testing.T) {
	f := newFairFixture(t)
	f.reportSpeeds(0)
	run := shared.NewID().String()
	for range 3 {
		done := f.addTool(run, "dnsx", 50, 50*time.Minute)
		f.hold(done, 40*time.Minute, 30*time.Minute) // 10 min each of short work
	}
	longJob := f.addTool(shared.NewID().String(), "nuclei", 10, 5*time.Minute)
	f.addTool(run, "dnsx", 50, 0)
	if got := f.poll(1); len(got) != 1 || got[0] != longJob {
		t.Fatalf("next claim = %v, want the long job %v (short work used more than half)", got, longJob)
	}
}

// Round-robin across runs counts what a run already has running: a run
// queued later with nothing running goes before an older run that holds a
// job, and so does the next command of a run with nothing running.
func TestFairPoll_RoundRobinCountsHeldJobs(t *testing.T) {
	f := newFairFixture(t)
	runA, runB := shared.NewID().String(), shared.NewID().String()
	a1 := f.addTool(runA, "nuclei", 1, 2*time.Minute)
	a2 := f.addTool(runA, "nuclei", 1, 2*time.Minute)
	b1 := f.addTool(runB, "nuclei", 1, 0)
	f.hold(a1, time.Minute, 0)
	if got := f.poll(2); len(got) != 2 || got[0] != b1 || got[1] != a2 {
		t.Fatalf("order = %v, want [%v %v] (run A already has a job running)", got, b1, a2)
	}
}

// Tenant isolation: another organization's jobs of a run with the same id,
// and another organization's sensor, never change this organization's
// order, and the poll never offers them (only a1 and b1 come back).
func TestFairPoll_LanesAndRunsAreTenantScoped(t *testing.T) {
	f := newFairFixture(t)
	f.reportSpeeds(0)
	other := seedTestTenant(f.ctx, t, f.db)
	otherSensor := seedZoneSensor(f.ctx, t, f.db, &other, "other", zoneSensorOpts{tools: []string{"nuclei", "dnsx"}})
	runA, runB := shared.NewID().String(), shared.NewID().String()

	// The other tenant holds jobs of a run with runA's id on its own sensor,
	// and that sensor was busy with short work all hour.
	for range 3 {
		raw, _ := json.Marshal(map[string]any{"scanner": "dnsx", "targets": []string{"x.example.test"}, "scan_run_id": runA})
		cmd, err := command.NewCommand(other, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.cmds.Create(f.ctx, cmd); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(f.ctx, `UPDATE commands SET status = 'running', sensor_id = $1,
			acknowledged_at = NOW() - INTERVAL '50 minutes' WHERE id = $2`, otherSensor.String(), cmd.ID.String()); err != nil {
			t.Fatal(err)
		}
	}
	a1 := f.addTool(runA, "nuclei", 1, 2*time.Minute)
	b1 := f.addTool(runB, "nuclei", 1, time.Minute)

	got := f.poll(10)
	if len(got) != 2 || got[0] != a1 || got[1] != b1 {
		t.Fatalf("order = %v, want [%v %v]: another tenant's jobs must not count", got, a1, b1)
	}
}
