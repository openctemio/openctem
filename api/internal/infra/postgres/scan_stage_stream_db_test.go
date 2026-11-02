package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A streamed stage on a real database: the first plan opens the stream,
// a later wave adds only keys the stage has not decided (and returns only
// those), the counts are recomputed from the targets, a closed stream takes
// no wave, and another tenant reads and writes nothing.
func TestStageStream_WavesDedupeCloseAndTenantScope(t *testing.T) {
	db := openHopDB(t)
	ctx := context.Background()
	repo := NewScanHopRepository(&DB{DB: db})
	h := newHopTenant(t, db, 0)
	other := newHopTenant(t, db, 0)

	plan := &scanrun.StagePlan{TenantID: h.tenant, RunID: h.run, StageKey: "ports", Stage: "scan.ports", Tool: "naabu",
		Tier: 1, Chained: true, Streamed: true, Inputs: 2, Planned: 2, Skipped: map[string]int{"invalid": 1}}
	ok, err := repo.SaveStagePlan(ctx, plan, []scanrun.RunTarget{
		{TargetKey: "acme.test", Origin: scanrun.TargetOriginSeed, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonSeed},
		{TargetKey: "www.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonGateAllowed, Hop: 1},
	})
	if err != nil || !ok {
		t.Fatalf("save first wave: %v %v", ok, err)
	}
	p, found, err := repo.StageStream(ctx, h.tenant, h.run, "ports")
	if err != nil || !found || !p.Streamed || !p.StreamOpen || p.Waves != 1 || p.FirstDispatchAt == nil {
		t.Fatalf("stream after the first wave = %+v found=%v err=%v", p, found, err)
	}

	// A later wave: one key decided already (kept as planned, not
	// returned), one new planned, one new refused.
	added, err := repo.SaveStageWave(ctx, &scanrun.StagePlan{TenantID: h.tenant, RunID: h.run, StageKey: "ports",
		Inputs: 5, Skipped: map[string]int{"duplicate": 1}}, []scanrun.RunTarget{
		{TargetKey: "www.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetSkipped, Reason: scanrun.ReasonExcluded, Hop: 1},
		{TargetKey: "api.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonGateAllowed, Hop: 2},
		{TargetKey: "evil.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetSkipped, Reason: scanrun.ReasonExcluded, Hop: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "api.acme.test" {
		t.Fatalf("added = %v, want only the new planned key", added)
	}
	p, _, _ = repo.StageStream(ctx, h.tenant, h.run, "ports")
	if p.Planned != 3 || p.MaxHop != 2 || p.Inputs != 5 || p.Waves != 2 ||
		p.Skipped["excluded"] != 1 || p.Skipped["duplicate"] != 1 || p.Skipped["invalid"] != 0 {
		t.Fatalf("plan after the wave = %+v", p)
	}
	targets, err := repo.StageTargets(ctx, h.tenant, h.run, "ports")
	if err != nil || len(targets) != 4 {
		t.Fatalf("stage targets = %d %v", len(targets), err)
	}
	for _, tg := range targets {
		if tg.TargetKey == "www.acme.test" && tg.Decision != scanrun.TargetPlanned {
			t.Fatal("a later wave changed an earlier decision")
		}
	}

	// Another tenant: nothing read, nothing written, nothing closed.
	if _, found, _ := repo.StageStream(ctx, other.tenant, h.run, "ports"); found {
		t.Fatal("another tenant read the stream")
	}
	if ts, _ := repo.StageTargets(ctx, other.tenant, h.run, "ports"); len(ts) != 0 {
		t.Fatal("another tenant read the stage's targets")
	}
	if a, err := repo.SaveStageWave(ctx, &scanrun.StagePlan{TenantID: other.tenant, RunID: h.run, StageKey: "ports"},
		[]scanrun.RunTarget{{TargetKey: "x.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonGateAllowed}}); err != nil || len(a) != 0 {
		t.Fatalf("another tenant's wave = %v %v", a, err)
	}
	if closed, _ := repo.CloseStageStream(ctx, other.tenant, h.run, "ports"); closed {
		t.Fatal("another tenant closed the stream")
	}

	// Close once; a closed stream takes no wave.
	if closed, err := repo.CloseStageStream(ctx, h.tenant, h.run, "ports"); err != nil || !closed {
		t.Fatalf("close = %v %v", closed, err)
	}
	if closed, _ := repo.CloseStageStream(ctx, h.tenant, h.run, "ports"); closed {
		t.Fatal("closed twice")
	}
	if a, _ := repo.SaveStageWave(ctx, &scanrun.StagePlan{TenantID: h.tenant, RunID: h.run, StageKey: "ports"},
		[]scanrun.RunTarget{{TargetKey: "late.acme.test", Origin: scanrun.TargetOriginDerived, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonGateAllowed}}); len(a) != 0 {
		t.Fatalf("a closed stream took a wave: %v", a)
	}
	if p, _, _ := repo.StageStream(ctx, h.tenant, h.run, "ports"); p.StreamOpen || p.ClosedAt == nil {
		t.Fatalf("closed stream = %+v", p)
	}
	// A barrier plan is never an open stream (the database refuses one).
	if _, err := db.ExecContext(ctx, `UPDATE scan_run_stage_plans SET streamed = false, stream_open = true
		WHERE tenant_id = $1 AND run_id = $2`, h.tenant.String(), h.run.String()); err == nil {
		t.Fatal("an open stream on a barrier plan was stored")
	}
}

// Waves of one stage never run at once: the second lock waits for the
// first's release.
func TestStageStream_LockSerializesWaves(t *testing.T) {
	db := openHopDB(t)
	ctx := context.Background()
	repo := NewScanHopRepository(&DB{DB: db})
	h := newHopTenant(t, db, 0)

	release, err := repo.LockStageStream(ctx, h.tenant, h.run, "ports")
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if r2, err := repo.LockStageStream(short, h.tenant, h.run, "ports"); err == nil {
		r2()
		t.Fatal("a second wave locked the stage while the first held it")
	}
	// Another stage of the run is not held.
	r3, err := repo.LockStageStream(ctx, h.tenant, h.run, "http")
	if err != nil {
		t.Fatal(err)
	}
	r3()
	release()
	r4, err := repo.LockStageStream(ctx, h.tenant, h.run, "ports")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	r4()
	if _, err := repo.LockStageStream(ctx, shared.ID{}, h.run, "ports"); err == nil {
		t.Fatal("a lock without a tenant was taken")
	}
}

// The stall repair finds a run whose streamed step missed its closing wave
// (stream open, none of its commands active, its predecessor finished), and
// leaves one whose streamed step still has a command running.
func TestStageStream_StallRepairFindsAMissedClose(t *testing.T) {
	db := openHopDB(t)
	ctx := context.Background()
	hops := NewScanHopRepository(&DB{DB: db})
	runs := NewScanRunRepository(&DB{DB: db})
	h := newHopTenant(t, db, 0)
	old := time.Now().Add(-time.Hour)
	ports := shared.NewID()
	hopExec(t, db, `UPDATE scan_runs SET started_at = $2 WHERE id = $1`, h.run, old)
	hopExec(t, db, `UPDATE scan_run_steps SET completed_at = $2 WHERE id = $1`, h.stepRun, old)
	hopExec(t, db, `INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status, queued_at, created_at)
		VALUES ($1, $2, 'ports', 2, 'queued', $3, $3)`, ports, h.run, old)
	if ok, err := hops.SaveStagePlan(ctx, &scanrun.StagePlan{TenantID: h.tenant, RunID: h.run, StageKey: "ports", Chained: true, Streamed: true, Planned: 1, Skipped: map[string]int{}},
		nil); err != nil || !ok {
		t.Fatalf("save plan: %v %v", ok, err)
	}
	active := shared.NewID()
	hopExec(t, db, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, scan_run_step_id)
		VALUES ($1, $2, $3, 'scan', 'running', '{}', $4)`, active, h.tenant, h.sensor, ports)

	stalled := func() bool {
		t.Helper()
		got, err := runs.StalledRuns(ctx, time.Now().Add(-2*time.Minute), 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			if r.RunID == h.run {
				return true
			}
		}
		return false
	}
	if stalled() {
		t.Fatal("a run whose streamed step has a running command was found stalled")
	}
	hopExec(t, db, `UPDATE commands SET status = 'completed' WHERE id = $1`, active)
	if !stalled() {
		t.Fatal("a run whose streamed step missed its closing wave was not found")
	}
	// An open stream is not an orphan plan: never released under a wave.
	hopExec(t, db, `UPDATE scan_run_steps SET status = 'pending' WHERE id = $1`, ports)
	hopExec(t, db, `DELETE FROM commands WHERE id = $1`, active)
	hopExec(t, db, `UPDATE scan_run_stage_plans SET planned_at = $3 WHERE tenant_id = $1 AND run_id = $2`, h.tenant, h.run, old)
	if _, err := runs.ReleaseOrphanStagePlans(ctx, time.Now().Add(-2*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := hops.StageStream(ctx, h.tenant, h.run, "ports"); !found {
		t.Fatal("an open stream was released as an orphan plan")
	}
}
