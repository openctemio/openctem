package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run's tasks are the commands it dispatched (RFC-046 §4.1). The runs page
// reads them by run; another tenant's commands never show up, and another
// tenant's sensor is never named. Against the real SQL.

type runTasksFixture struct {
	ctx    context.Context
	db     *sql.DB
	runs   *ScanRunRepository
	cmds   *CommandRepository
	tenant shared.ID
	scan   shared.ID
}

func newRunTasksFixture(t *testing.T) *runTasksFixture {
	t.Helper()
	ctx := context.Background()
	db := openScanDB(t)
	tenant, scan := seedCounterScan(ctx, t, db)
	return &runTasksFixture{ctx: ctx, db: db, tenant: tenant, scan: scan,
		runs: NewScanRunRepository(&DB{DB: db}), cmds: NewCommandRepository(&DB{DB: db})}
}

func (f *runTasksFixture) sensor(t *testing.T, tenant shared.ID, name string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`, id.String(), tenant.String(), name+"-"+id.String()[:8], "h-"+id.String()); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	return id
}

func (f *runTasksFixture) command(t *testing.T, tenant, run shared.ID, sensor *shared.ID, status string, payload map[string]any) shared.ID {
	t.Helper()
	id := shared.NewID()
	payload["scan_run_id"] = run.String()
	raw, _ := json.Marshal(payload)
	var sensorArg any
	if sensor != nil {
		sensorArg = sensor.String()
	}
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, acknowledged_at, started_at, completed_at, error_message)
		VALUES ($1, $2, $3, 'scan', $4::text, $5,
		        CASE WHEN $4::text NOT IN ('pending') THEN NOW() END,
		        CASE WHEN $4::text NOT IN ('pending', 'acknowledged') THEN NOW() END,
		        CASE WHEN $4::text IN ('completed', 'failed', 'expired', 'canceled') THEN NOW() END,
		        CASE WHEN $4::text = 'failed' THEN 'scanner exited 2' END)`,
		id.String(), tenant.String(), sensorArg, status, raw); err != nil {
		t.Fatalf("seed command: %v", err)
	}
	return id
}

// A task whose sensor skipped targets carries them, bounded and cleaned,
// from its result metadata; a result without them, or with a malformed
// list, reads as none.
func TestListRunTasks_SkippedTargets(t *testing.T) {
	f := newRunTasksFixture(t)
	s1 := f.sensor(t, f.tenant, "edge")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	setResult := func(id shared.ID, result string) {
		t.Helper()
		if _, err := f.db.ExecContext(f.ctx, `UPDATE commands SET result = $2::jsonb WHERE tenant_id = $1 AND id = $3`,
			f.tenant.String(), result, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	partial := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"example.com"}})
	setResult(partial, `{"status":"completed","findings_count":1,"metadata":{"partial":true,"refused_targets_total":2,
		"refused_targets":[{"target":"api.example.com","reason":"unresolvable","rule":"targets"},{"target":"*.example.com","reason":"wildcard_pattern"}]}}`)
	plain := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"b.example.com"}})
	setResult(plain, `{"status":"completed","findings_count":0}`)
	bogus := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"c.example.com"}})
	setResult(bogus, `{"metadata":{"refused_targets":"nope","refused_targets_total":"9"}}`)

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[shared.ID]scanrun.Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	p := byID[partial]
	if p.SkippedTotal != 2 || len(p.Skipped) != 2 || p.Skipped[0].Target != "api.example.com" ||
		p.Skipped[0].Reason != scanrun.SkipReasonUnresolvable || p.Skipped[1].Reason != scanrun.SkipReasonWildcard {
		t.Fatalf("partial task skipped = %+v (total %d)", p.Skipped, p.SkippedTotal)
	}
	if byID[plain].SkippedTotal != 0 || byID[plain].Skipped != nil {
		t.Fatalf("plain task skipped = %+v", byID[plain])
	}
	if byID[bogus].SkippedTotal != 0 || byID[bogus].Skipped != nil {
		t.Fatalf("malformed metadata read as %+v", byID[bogus])
	}
	// The page read carries them too.
	page, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, nil, 10)
	if err != nil || len(page) != 3 || page[0].SkippedTotal != 2 {
		t.Fatalf("page %+v, err %v", page, err)
	}
}

func TestListRunTasks_SummaryItemsAndTenantScope(t *testing.T) {
	f := newRunTasksFixture(t)
	s1 := f.sensor(t, f.tenant, "edge")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)

	f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"a", "b"}})
	failed := f.command(t, f.tenant, run.ID, &s1, "failed", map[string]any{"scanner": "nuclei", "target": "c"})
	f.command(t, f.tenant, run.ID, &s1, "running", map[string]any{"preferred_tool": "naabu", "targets": []string{"d"}})
	f.command(t, f.tenant, run.ID, nil, "pending", map[string]any{"scanner": "nuclei", "targets": []string{"e", "f", "g"}})
	f.command(t, f.tenant, run.ID, &s1, "expired", map[string]any{"scanner": "nuclei"})
	f.command(t, f.tenant, run.ID, &s1, "canceled", map[string]any{"scanner": "nuclei"})

	// Another run of the tenant, and another tenant's command that names this
	// run in its payload (a forged or confused payload): neither counts.
	other := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	f.command(t, f.tenant, other.ID, &s1, "running", map[string]any{"scanner": "nuclei"})
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	strangerSensor := f.sensor(t, stranger, "stranger")
	f.command(t, stranger, run.ID, &strangerSensor, "completed", map[string]any{"scanner": "nuclei"})

	tasks, sum, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatalf("ListRunTasks: %v", err)
	}
	want := scanrun.TaskSummary{Total: 6, Queued: 1, Running: 1, Completed: 1, Failed: 2, Canceled: 1, Sensors: 1}
	if sum != want {
		t.Fatalf("summary = %+v, want %+v", sum, want)
	}
	if len(tasks) != 6 {
		t.Fatalf("got %d tasks, want 6", len(tasks))
	}
	byID := map[shared.ID]scanrun.Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	ft := byID[failed]
	if ft.Status != scanrun.TaskStatusFailed || ft.Tool != "nuclei" || ft.Targets != 1 ||
		ft.ErrorMessage != "scanner exited 2" || ft.SensorID == nil || *ft.SensorID != s1 || ft.SensorName == "" {
		t.Fatalf("failed task = %+v", ft)
	}
	if tasks[0].Targets != 2 || tasks[0].Status != scanrun.TaskStatusCompleted {
		t.Fatalf("first task = %+v, want the completed 2-target task in dispatch order", tasks[0])
	}

	// The limit bounds the items, not the summary.
	tasks, sum, err = f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 2)
	if err != nil || len(tasks) != 2 || sum.Total != 6 {
		t.Fatalf("limited: %d tasks, total %d, err %v; want 2 of 6", len(tasks), sum.Total, err)
	}

	// The other tenant reads nothing for this run, and only its own command
	// when it asks for the run id its forged payload names.
	tasks, sum, err = f.cmds.ListRunTasks(f.ctx, stranger, run.ID, 0)
	if err != nil || sum.Total != 1 || len(tasks) != 1 {
		t.Fatalf("stranger: %d tasks, total %d, err %v; want only its own command", len(tasks), sum.Total, err)
	}

	sums, err := f.cmds.TaskSummaries(f.ctx, f.tenant, []shared.ID{run.ID, other.ID, shared.NewID()})
	if err != nil {
		t.Fatalf("TaskSummaries: %v", err)
	}
	if sums[run.ID] != want || sums[other.ID].Total != 1 || sums[other.ID].Running != 1 || len(sums) != 2 {
		t.Fatalf("summaries = %+v", sums)
	}
	if sums, err := f.cmds.TaskSummaries(f.ctx, shared.NewID(), []shared.ID{run.ID}); err != nil || len(sums) != 0 {
		t.Fatalf("unknown tenant summaries = %+v, %v; want none", sums, err)
	}
}

// A sensor of another tenant holding the command (it cannot happen through
// the claim, which filters by tenant, but the row could exist) is not named.
func TestListRunTasks_ForeignSensorIsNotNamed(t *testing.T) {
	f := newRunTasksFixture(t)
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	foreign := f.sensor(t, stranger, "foreign")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	f.command(t, f.tenant, run.ID, &foreign, "running", map[string]any{"scanner": "nuclei"})

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks = %v, %v", tasks, err)
	}
	if tasks[0].SensorID != nil || tasks[0].SensorName != "" {
		t.Fatalf("task names another tenant's sensor: %+v", tasks[0])
	}
}
