package postgres

// Paging a run's tasks by cursor (GET /scan-runs/{id}/tasks): every task
// exactly once, in dispatch order, never another tenant's, and the run of
// another tenant is not found. Against the real SQL.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRunTasksPage_CursorWalksEveryTaskOnce_DB(t *testing.T) {
	f := newRunTasksFixture(t)
	s1 := f.sensor(t, f.tenant, "edge")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	for i := 0; i < 7; i++ {
		f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei", "targets": []string{"x"}})
	}
	// Another tenant's command naming this run in its payload must never show.
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	f.command(t, stranger, run.ID, nil, "pending", map[string]any{"scanner": "nuclei"})

	all, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil || len(all) != 7 {
		t.Fatalf("full list: %d tasks, %v", len(all), err)
	}
	want := make([]shared.ID, len(all))
	for i, task := range all {
		want[i] = task.ID
	}

	// Repository: pages of 3 after a cursor reproduce the full order.
	var got []shared.ID
	var after *scanrundom.TaskCursor
	for page := 0; page < 5; page++ {
		items, err := f.cmds.ListRunTasksAfter(f.ctx, f.tenant, run.ID, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			got = append(got, it.ID)
		}
		c := scanrundom.TaskCursorAfter(items[len(items)-1])
		// Round-trip through the wire form, as the client does.
		decoded, err := scanrundom.DecodeTaskCursor(c.Encode())
		if err != nil {
			t.Fatal(err)
		}
		after = &decoded
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paged = %v\nwant    %v", got, want)
	}

	// Service: per_page pages with next_cursor until the last page.
	pg := &DB{DB: f.db}
	svc := scanrun.NewService(nil, nil, NewScanRunRepository(pg), nil, nil, NewCommandRepository(pg), nil, logger.NewNop())
	got = got[:0]
	cursor := ""
	for i := 0; i < 5; i++ {
		page, err := svc.ListRunTasksPage(f.ctx, f.tenant.String(), run.ID.String(), cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Items {
			got = append(got, it.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service paged = %v\nwant           %v", got, want)
	}

	// The other tenant asking for this run: not found, never its tasks.
	if _, err := svc.ListRunTasksPage(f.ctx, stranger.String(), run.ID.String(), "", 50); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: err = %v, want not found", err)
	}
	// Bad input is a validation error, not a 500 or a full read.
	for _, tc := range []struct {
		cursor string
		limit  int
	}{{"not-a-cursor", 10}, {"", 201}, {"", -1}} {
		if _, err := svc.ListRunTasksPage(f.ctx, f.tenant.String(), run.ID.String(), tc.cursor, tc.limit); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("cursor=%q limit=%d: err = %v, want validation", tc.cursor, tc.limit, err)
		}
	}
}
