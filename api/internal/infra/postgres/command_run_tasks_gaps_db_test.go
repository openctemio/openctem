package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A task that completed with hosts its sensor could not fully cover carries
// them (RFC-074); malformed metadata reads as none, and another tenant never
// sees them.
func TestListRunTasks_CoverageGaps(t *testing.T) {
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
	gapped := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"a.example.com"}})
	setResult(gapped, `{"status":"completed","metadata":{"coverage_gaps_total":3,
		"coverage_gaps":[{"host":"a.example.com","reason":"breaker_open","detail":"given up after 3 breaker trips"},
		{"host":"b.example.com","reason":"made-up"},{"host":"c.example.com","reason":"blocked"}]}}`)
	bogus := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"d.example.com"}})
	setResult(bogus, `{"metadata":{"coverage_gaps":"nope","coverage_gaps_total":"9"}}`)
	edge := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"e.example.com"}})
	setResult(edge, `{"metadata":{"coverage_gaps_total":2,"coverage_gaps":[
		{"host":"e.example.com","reason":"blocked","edge":"challenged","vendor":"DataDome"},
		{"host":"f.example.com","reason":"rate_floor","edge":"blocked","vendor":"datadome"}]}}`)
	stranger, _ := seedCounterScan(f.ctx, t, f.db)

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[shared.ID]scanrun.Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	g := byID[gapped]
	if e := byID[edge].CoverageGaps; len(e) != 2 || e[0].Edge != scanrun.EdgeChallenged || e[0].Vendor != "datadome" || e[1].Edge != "" || e[1].Vendor != "" {
		t.Fatalf("edge gaps = %+v", e)
	}
	if g.CoverageGapsTotal != 3 || len(g.CoverageGaps) != 2 || g.CoverageGaps[0].Host != "a.example.com" ||
		g.CoverageGaps[0].Reason != scanrun.GapReasonBreakerOpen || g.CoverageGaps[1].Reason != scanrun.GapReasonBlocked {
		t.Fatalf("gaps = %+v (total %d)", g.CoverageGaps, g.CoverageGapsTotal)
	}
	if byID[bogus].CoverageGapsTotal != 0 || byID[bogus].CoverageGaps != nil {
		t.Fatalf("malformed metadata read as %+v", byID[bogus])
	}
	page, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, nil, 10)
	if err != nil || len(page) != 3 || page[0].CoverageGapsTotal != 3 {
		t.Fatalf("page %+v, err %v", page, err)
	}
	// SECURITY: another tenant reads no task (and no gap) of this run.
	if tasks, sum, err := f.cmds.ListRunTasks(f.ctx, stranger, run.ID, 0); err != nil || len(tasks) != 0 || sum.Total != 0 {
		t.Fatalf("stranger read %d tasks (total %d), err %v", len(tasks), sum.Total, err)
	}
}

// A completed task whose sensor's network confinement kept the tool from
// reaching some targets (ctis outcome failed/egress_refused) counts them:
// the run page says "could not reach", never "produced nothing". Other
// outcomes, a malformed list and a task still running count none; a
// sensor cannot count more targets than the task carries; another tenant
// sees nothing.
func TestListRunTasks_EgressRefusedTargets(t *testing.T) {
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
	blocked := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "naabu", "targets": []string{"a.example.com", "b.example.com", "c.example.com"}})
	setResult(blocked, `{"status":"completed","target_outcomes":[
		{"target":"a.example.com","state":"failed","class":"egress_refused"},
		{"target":"b.example.com","state":"failed","class":"egress_refused"},
		{"target":"c.example.com","state":"done"}]}`)
	other := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "naabu", "targets": []string{"d.example.com"}})
	setResult(other, `{"target_outcomes":[{"target":"d.example.com","state":"failed","class":"unreachable"},{"target":"x","state":"skipped","class":"egress_refused"}]}`)
	bogus := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "naabu", "targets": []string{"e.example.com"}})
	setResult(bogus, `{"target_outcomes":"nope"}`)
	inflated := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "naabu", "targets": []string{"f.example.com"}})
	setResult(inflated, `{"target_outcomes":[{"target":"f.example.com","state":"failed","class":"egress_refused"},
		{"target":"g.example.com","state":"failed","class":"egress_refused"},{"target":"h.example.com","state":"failed","class":"egress_refused"}]}`)
	running := f.command(t, f.tenant, run.ID, &s1, "running", map[string]any{"scanner": "naabu", "targets": []string{"i.example.com"}})
	setResult(running, `{"target_outcomes":[{"target":"i.example.com","state":"failed","class":"egress_refused"}]}`)
	stranger, _ := seedCounterScan(f.ctx, t, f.db)

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]int{}
	for _, task := range tasks {
		got[task.ID] = task.EgressRefusedTargets
	}
	want := map[shared.ID]int{blocked: 2, other: 0, bogus: 0, inflated: 1, running: 0}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("task %s: %d egress-refused targets, want %d", id, got[id], w)
		}
	}
	page, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, nil, 10)
	if err != nil || len(page) != 5 || page[0].EgressRefusedTargets != 2 {
		t.Fatalf("page %+v, err %v", page, err)
	}
	// SECURITY: another tenant reads no task of this run.
	if tasks, sum, err := f.cmds.ListRunTasks(f.ctx, stranger, run.ID, 0); err != nil || len(tasks) != 0 || sum.Total != 0 {
		t.Fatalf("stranger read %d tasks (total %d), err %v", len(tasks), sum.Total, err)
	}
}

// A task whose sensor's target guard refused some targets (refused_targets
// with rule target_guard) counts them, so the step says "N targets refused
// by the sensor's target guard". Local-policy refusals, a malformed list
// and a list without the rule count none; when every listed entry is the
// guard's, the unlisted rest (refused_targets_total) count too; a sensor
// cannot count more targets than the task carries; another tenant sees
// nothing.
func TestListRunTasks_GuardRefusedTargets(t *testing.T) {
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
	targets := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "t" + string(rune('a'+i)) + ".example.com"
		}
		return out
	}
	mixed := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "httpx", "targets": targets(4)})
	setResult(mixed, `{"status":"completed","metadata":{"refused_targets_total":3,"refused_targets":[
		{"target":"127.0.0.1:80","reason":"denied_by_policy","rule":"target_guard"},
		{"target":"gone.example.net","reason":"unresolvable","rule":"target_guard"},
		{"target":"10.0.0.1","reason":"denied_by_policy","rule":"targets.deny"}]}}`)
	policy := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "httpx", "targets": targets(2)})
	setResult(policy, `{"metadata":{"refused_targets_total":1,"refused_targets":[{"target":"10.0.0.1","reason":"denied_by_policy","rule":"targets.deny"}]}}`)
	bogus := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "httpx", "targets": targets(1)})
	setResult(bogus, `{"metadata":{"refused_targets":"nope","refused_targets_total":"9"}}`)
	unlisted := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "httpx", "targets": targets(8)})
	setResult(unlisted, `{"metadata":{"refused_targets_total":6,"refused_targets":[
		{"target":"127.0.0.1","reason":"denied_by_policy","rule":"target_guard"},{"target":"169.254.169.254","reason":"denied_by_policy","rule":"target_guard"}]}}`)
	inflated := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "httpx", "targets": targets(1)})
	setResult(inflated, `{"metadata":{"refused_targets_total":500,"refused_targets":[{"target":"x","reason":"invalid_target","rule":"target_guard"}]}}`)
	stranger, _ := seedCounterScan(f.ctx, t, f.db)

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]int{}
	for _, task := range tasks {
		got[task.ID] = task.GuardRefusedTargets
	}
	want := map[shared.ID]int{mixed: 2, policy: 0, bogus: 0, unlisted: 6, inflated: 1}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("task %s: %d guard-refused targets, want %d", id, got[id], w)
		}
	}
	page, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, nil, 10)
	if err != nil || len(page) != 5 || page[0].GuardRefusedTargets != 2 {
		t.Fatalf("page %+v, err %v", page, err)
	}
	// SECURITY: another tenant reads no task of this run.
	if tasks, sum, err := f.cmds.ListRunTasks(f.ctx, stranger, run.ID, 0); err != nil || len(tasks) != 0 || sum.Total != 0 {
		t.Fatalf("stranger read %d tasks (total %d), err %v", len(tasks), sum.Total, err)
	}
}
