package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// research/62 SG-7: a workflow's timeout_seconds was stored and shown but
// never applied. A run without a scan timeout now ends at the workflow's
// timeout; a scan's own timeout still wins; a malformed setting is ignored.
func TestRunDeadline_UsesTheWorkflowTimeout(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	runs := NewScanRunRepository(&DB{DB: db})

	newWorkflow := func(settings string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO scan_workflows (id, tenant_id, name, settings) VALUES ($1, $2, $3, $4::jsonb)`,
			id.String(), tenant.String(), "deadline "+id.String(), settings); err != nil {
			t.Fatal(err)
		}
		return id
	}
	deadline := func(workflow shared.ID, scanID *shared.ID) time.Duration {
		t.Helper()
		run, err := scanrun.NewRun(workflow, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		run.ScanID = scanID
		run.Start()
		if err := runs.Create(ctx, run); err != nil {
			t.Fatal(err)
		}
		var started, dl time.Time
		if err := db.QueryRowContext(ctx, `SELECT started_at, deadline_at FROM scan_runs WHERE id = $1`, run.ID.String()).Scan(&started, &dl); err != nil {
			t.Fatal(err)
		}
		return dl.Sub(started).Round(time.Second)
	}

	if got := deadline(newWorkflow(`{"timeout_seconds": 600}`), nil); got != 600*time.Second {
		t.Errorf("workflow timeout 600s: deadline after %s", got)
	}
	if got := deadline(newWorkflow(`{"timeout_seconds": "bogus"}`), nil); got != AbsoluteRunTimeoutSeconds*time.Second {
		t.Errorf("malformed timeout: deadline after %s, want the 24h ceiling", got)
	}
	if got := deadline(newWorkflow(`{"timeout_seconds": 999999}`), nil); got != AbsoluteRunTimeoutSeconds*time.Second {
		t.Errorf("timeout above the ceiling: deadline after %s, want the 24h ceiling", got)
	}

	// A scan's own timeout wins over the workflow's.
	wf := newWorkflow(`{"timeout_seconds": 600}`)
	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id, timeout_seconds) VALUES ($1, $2, $3, 'workflow', $4, 1200)`,
		scanID.String(), tenant.String(), "deadline scan "+scanID.String(), wf.String()); err != nil {
		t.Fatal(err)
	}
	if got := deadline(wf, &scanID); got != 1200*time.Second {
		t.Errorf("scan timeout 1200s over workflow 600s: deadline after %s", got)
	}
}
