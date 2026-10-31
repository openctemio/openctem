package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// streamGate is the target gate of these tests: it refuses the names in
// refuse (an exclusion) and allows everything else. The real gate's rules
// on every wave are covered by the scanrun package's tests.
type streamGate struct{ refuse map[string]bool }

func (g streamGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	out := &scanapp.DispatchTargets{}
	for _, t := range in.Targets {
		if g.refuse[t] {
			out.Excluded = append(out.Excluded, t)
			continue
		}
		out.Allowed = append(out.Allowed, t)
	}
	return out, nil
}

// streamRun is one tenant's run of dns (dnsx, three running tasks) ->
// ports (naabu), on the real repositories.
type streamRun struct {
	db                          *sql.DB
	tenant, run, dnsSR, portsSR shared.ID
	tasks                       []shared.ID
	svc                         *scanrun.Service
	hops                        *postgres.ScanHopRepository
}

func newStreamRun(t *testing.T, db *sql.DB, refuse map[string]bool) *streamRun {
	t.Helper()
	ctx := context.Background()
	r := &streamRun{db: db, tenant: createTestTenant(t, db, "stage-stream"), run: shared.NewID(), dnsSR: shared.NewID(), portsSR: shared.NewID()}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scan_runs WHERE tenant_id = $1`, r.tenant.String())
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id = $1`, r.tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id = $1`, r.tenant.String())
		_, _ = db.Exec(`DELETE FROM sensors WHERE tenant_id = $1`, r.tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, r.tenant.String())
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	wf, dnsStep, portsStep, sensor := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	exec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status) VALUES ($1, $2, 'stream-sensor', $3, 'p', 'active')`,
		sensor.String(), r.tenant.String(), "h-"+sensor.String())
	exec(`INSERT INTO scan_workflows (id, tenant_id, name, description, settings) VALUES ($1, $2, $3, '', '{"max_parallel_steps":3}')`, wf.String(), r.tenant.String(), "stream "+wf.String())
	exec(`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order, tool, capabilities) VALUES ($1, $2, 'dns', 'dns', 1, 'dnsx', ARRAY['dns'])`,
		dnsStep.String(), wf.String())
	exec(`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order, tool, capabilities, depends_on) VALUES ($1, $2, 'ports', 'ports', 2, 'naabu', ARRAY['port'], ARRAY['dns'])`,
		portsStep.String(), wf.String())
	exec(`INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, trigger_type, status, total_steps, context, started_at)
		VALUES ($1, $2, $3, 'manual', 'running', 2, '{"targets":["acme.test"]}', now())`, r.run.String(), wf.String(), r.tenant.String())
	exec(`INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status, started_at) VALUES ($1, $2, $3, 'dns', 1, 'running', now())`,
		r.dnsSR.String(), r.run.String(), dnsStep.String())
	exec(`INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status) VALUES ($1, $2, $3, 'ports', 2, 'pending')`,
		r.portsSR.String(), r.run.String(), portsStep.String())
	for range 3 {
		id := shared.NewID()
		exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, scan_run_step_id) VALUES ($1, $2, $3, 'scan', 'running', '{}', $4)`,
			id.String(), r.tenant.String(), sensor.String(), r.dnsSR.String())
		r.tasks = append(r.tasks, id)
	}
	pg := &postgres.DB{DB: db}
	r.hops = postgres.NewScanHopRepository(pg)
	r.svc = scanrun.NewService(postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg), nil, postgres.NewCommandRepository(pg),
		acceptingStepValidator{}, logger.New(logger.Config{Level: "error"}),
		scanrun.WithHopStore(r.hops), scanrun.WithTargetGate(streamGate{refuse: refuse}),
		scanrun.WithToolRepo(postgres.NewToolRepository(pg)), scanrun.WithStageStreaming(true))
	return r
}

// finish ends dnsx task i (completed with the given output names, or
// failed) and reports it the way the command handler does.
func (r *streamRun) finish(t *testing.T, i int, ok bool, names ...string) {
	t.Helper()
	ctx := context.Background()
	ids := make([]shared.ID, 0, len(names))
	for _, n := range names {
		var id string
		err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, r.tenant.String(), n).Scan(&id)
		if err != nil {
			nid := shared.NewID()
			if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'subdomain')`,
				nid.String(), r.tenant.String(), n); err != nil {
				t.Fatal(err)
			}
			id = nid.String()
		}
		aid, _ := shared.IDFromString(id)
		ids = append(ids, aid)
	}
	if _, err := r.hops.RecordStepOutputs(ctx, r.tenant, r.dnsSR, ids); err != nil {
		t.Fatal(err)
	}
	status := "completed"
	if !ok {
		status = "failed"
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE commands SET status = $2, completed_at = now() WHERE id = $1`, r.tasks[i].String(), status); err != nil {
		t.Fatal(err)
	}
	var err error
	if ok {
		err = r.svc.OnStepCompleted(ctx, r.tenant, r.run.String(), "dns", 0, nil)
	} else {
		err = r.svc.OnStepFailed(ctx, r.tenant, r.run.String(), "dns", "tool crashed", "COMMAND_FAILED")
	}
	if err != nil {
		t.Fatal(err)
	}
}

// portsCommands returns each ports command's id and targets, in creation order.
func (r *streamRun) portsCommands(t *testing.T) (ids []string, targets [][]string) {
	t.Helper()
	rows, err := r.db.Query(`SELECT id, payload FROM commands WHERE tenant_id = $1 AND scan_run_step_id = $2 ORDER BY created_at, id`,
		r.tenant.String(), r.portsSR.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		var p struct {
			Targets []string `json:"targets"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		sort.Strings(p.Targets)
		ids, targets = append(ids, id), append(targets, p.Targets)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids, targets
}

func (r *streamRun) stepStatus(t *testing.T, id shared.ID) string {
	t.Helper()
	var st string
	if err := r.db.QueryRow(`SELECT status FROM scan_run_steps WHERE id = $1`, id.String()).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// On a real database: a slow dnsx task does not hold back the ports scan
// of the names the finished tasks found; a failed task loses nothing of the
// others; no target is dispatched twice across waves; a refused name never
// is; every planned target is in exactly one command (coverage is decided
// per command on its own targets, so a target counts only through the
// command that ran it); a ports command that fails leaves the step partial,
// never completed.
func TestStageStreaming_RealDatabase(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	r := newStreamRun(t, db, map[string]bool{"evil.acme.test": true})

	// Task 0 finishes, tasks 1 and 2 still run.
	r.finish(t, 0, true, "www.acme.test", "mail.acme.test")
	_, waves := r.portsCommands(t)
	if len(waves) != 1 || !has(waves[0], "www.acme.test") || !has(waves[0], "mail.acme.test") || !has(waves[0], "acme.test") {
		t.Fatalf("ports after the first dnsx task = %v, want one command with the seed and task 0's names", waves)
	}
	if st := r.stepStatus(t, r.portsSR); st != "queued" {
		t.Fatalf("ports step = %s, want queued while dnsx runs", st)
	}
	if st := r.stepStatus(t, r.dnsSR); st != "running" {
		t.Fatalf("dns step = %s, want running", st)
	}

	// The first ports command finishes while dnsx runs: the step waits.
	ids, _ := r.portsCommands(t)
	if _, err := db.Exec(`UPDATE commands SET status = 'completed', completed_at = now() WHERE id = $1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.OnStepCompleted(ctx, r.tenant, r.run.String(), "ports", 0, nil); err != nil {
		t.Fatal(err)
	}
	if st := r.stepStatus(t, r.portsSR); st != "queued" {
		t.Fatalf("ports step = %s after its first wave, want queued (stream open)", st)
	}

	// Task 1 fails; task 2 finishes with a duplicate, a new and a refused name.
	r.finish(t, 1, false)
	r.finish(t, 2, true, "www.acme.test", "api.acme.test", "evil.acme.test")
	if st := r.stepStatus(t, r.dnsSR); st != "partial" {
		t.Fatalf("dns step = %s, want partial (one task failed)", st)
	}
	ids, waves = r.portsCommands(t)
	if len(waves) != 2 || len(waves[1]) != 1 || waves[1][0] != "api.acme.test" {
		t.Fatalf("ports commands = %v, want a second wave with only api.acme.test", waves)
	}
	seen := map[string]bool{}
	for _, w := range waves {
		for _, x := range w {
			if seen[x] {
				t.Fatalf("%s dispatched twice", x)
			}
			seen[x] = true
		}
	}
	if seen["evil.acme.test"] {
		t.Fatal("a refused name was dispatched")
	}
	planned := plannedPorts(t, r)
	if len(planned) != len(seen) {
		t.Fatalf("planned %v, dispatched %v: every planned target must be in exactly one command", planned, seen)
	}
	for _, k := range planned {
		if !seen[k] {
			t.Fatalf("planned target %s was never dispatched", k)
		}
	}
	var open bool
	var streamWaves int
	if err := db.QueryRow(`SELECT stream_open, waves FROM scan_run_stage_plans WHERE tenant_id = $1 AND run_id = $2 AND stage_key = 'ports'`,
		r.tenant.String(), r.run.String()).Scan(&open, &streamWaves); err != nil {
		t.Fatal(err)
	}
	if open || streamWaves != 2 {
		t.Fatalf("ports stream open=%v waves=%d, want closed after 2 waves", open, streamWaves)
	}

	// The last ports command fails: the step ends partial (what it covered
	// is kept), never completed.
	if _, err := db.Exec(`UPDATE commands SET status = 'failed', completed_at = now(), error_message = 'tool crashed' WHERE id = $1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.OnStepFailed(ctx, r.tenant, r.run.String(), "ports", "tool crashed", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if st := r.stepStatus(t, r.portsSR); st != "partial" {
		t.Fatalf("ports step = %s, want partial", st)
	}
	var runStatus string
	if err := db.QueryRow(`SELECT status FROM scan_runs WHERE id = $1`, r.run.String()).Scan(&runStatus); err != nil {
		t.Fatal(err)
	}
	if runStatus != "partial" {
		t.Fatalf("run = %s, want partial", runStatus)
	}

	// Another tenant's step results move nothing of this run.
	other := createTestTenant(t, db, "stage-stream-other")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	if err := r.svc.OnStepCompleted(ctx, other, r.run.String(), "dns", 0, nil); err == nil {
		t.Fatal("another tenant's result was accepted for this run")
	}
}

// Waves of one stage triggered at once (several servers ingesting reports
// of the same run) dispatch each new target exactly once.
func TestStageStreaming_ConcurrentWavesDispatchOnce(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	r := newStreamRun(t, db, nil)
	r.finish(t, 0, true, "www.acme.test")

	// Task 1's report: outputs recorded and the command completed; then
	// the "ingested" hook fires on several servers at once.
	ids := make([]shared.ID, 0, 20)
	for i := range 20 {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'subdomain')`,
			id.String(), r.tenant.String(), "h"+string(rune('a'+i))+".acme.test"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := r.hops.RecordStepOutputs(ctx, r.tenant, r.dnsSR, ids); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE commands SET status = 'completed', completed_at = now() WHERE id = $1`, r.tasks[1].String()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.svc.OnCommandIngested(ctx, r.tenant, r.tasks[1])
		}()
	}
	wg.Wait()
	_, waves := r.portsCommands(t)
	seen := map[string]int{}
	for _, w := range waves {
		for _, x := range w {
			seen[x]++
		}
	}
	for x, n := range seen {
		if n != 1 {
			t.Fatalf("%s dispatched %d times across %d commands", x, n, len(waves))
		}
	}
	if len(seen) != 22 { // the seed, www and the 20 new names
		t.Fatalf("dispatched %d targets, want 22: %v", len(seen), seen)
	}
}

func plannedPorts(t *testing.T, r *streamRun) []string {
	t.Helper()
	rows, err := r.db.Query(`SELECT target_key FROM scan_run_targets WHERE tenant_id = $1 AND run_id = $2 AND stage_key = 'ports' AND decision = 'planned'`,
		r.tenant.String(), r.run.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
