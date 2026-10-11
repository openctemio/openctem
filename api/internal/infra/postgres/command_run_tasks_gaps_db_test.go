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
	if g.CoverageGapsTotal != 3 || len(g.CoverageGaps) != 2 || g.CoverageGaps[0].Host != "a.example.com" ||
		g.CoverageGaps[0].Reason != scanrun.GapReasonBreakerOpen || g.CoverageGaps[1].Reason != scanrun.GapReasonBlocked {
		t.Fatalf("gaps = %+v (total %d)", g.CoverageGaps, g.CoverageGapsTotal)
	}
	if byID[bogus].CoverageGapsTotal != 0 || byID[bogus].CoverageGaps != nil {
		t.Fatalf("malformed metadata read as %+v", byID[bogus])
	}
	page, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, nil, 10)
	if err != nil || len(page) != 2 || page[0].CoverageGapsTotal != 3 {
		t.Fatalf("page %+v, err %v", page, err)
	}
	// SECURITY: another tenant reads no task (and no gap) of this run.
	if tasks, sum, err := f.cmds.ListRunTasks(f.ctx, stranger, run.ID, 0); err != nil || len(tasks) != 0 || sum.Total != 0 {
		t.Fatalf("stranger read %d tasks (total %d), err %v", len(tasks), sum.Total, err)
	}
}
