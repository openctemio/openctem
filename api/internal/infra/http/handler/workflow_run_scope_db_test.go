package handler

import (
	"net/http"
	"strings"
	"testing"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run that lists several discovered assets, or reports a finished scan, is
// readable by a reader limited to their data scope without naming assets
// outside it, on detail, list and step inputs.
func TestWorkflowRunsReaderScope_ListedAssets_DB(t *testing.T) {
	f := newWFDB(t)
	nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"asset_discovered"}},
		{"node_key":"n","node_type":"notification","name":"n","config":{"notification_type":"email","notification_config":{"title":"x","body":"y"}}}]`
	edges := `[{"source_node_key":"t","target_node_key":"n"}]`
	wf := f.create(nodes, edges)
	outName := "wfd-" + f.assetOut + ".example.com"
	inName := "wfd-" + f.assetIn + ".example.com"
	a := func(id string) map[string]any {
		return map[string]any{"id": id, "name": "wfd-" + id + ".example.com", "type": "domain", "criticality": "high", "internet_facing": true}
	}
	trigger := func(assets ...map[string]any) map[string]any {
		list := make([]any, len(assets))
		for i, x := range assets {
			list[i] = x
		}
		return map[string]any{"event_type": "asset_discovered", "asset": assets[0],
			"assets": list, "asset_count": len(assets), "internet_facing_count": len(assets)}
	}
	trig := func(td map[string]any) *automationdom.Run {
		run, err := f.svc.TriggerWorkflow(f.ctx, automationsvc.TriggerWorkflowInput{
			TenantID: shared.MustIDFromString(f.tenantA), WorkflowID: shared.MustIDFromString(wf),
			TriggerType: automationdom.TriggerTypeAssetDiscovered, TriggerData: td,
		})
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	mixed := trig(trigger(a(f.assetIn), a(f.assetOut)))
	own := trig(trigger(a(f.assetIn)))

	get := func(user string, id shared.ID) (int, string) {
		return f.call(f.h.GetRun, f.as(user, http.MethodGet, "", map[string]string{"id": id.String()}))
	}

	t.Run("restricted reader sees only listed assets in scope", func(t *testing.T) {
		s, b := get(f.operator, mixed.ID)
		if s != http.StatusOK {
			t.Fatalf("GET run = %d %s", s, b)
		}
		if strings.Contains(b, outName) || strings.Contains(b, f.assetOut) {
			t.Errorf("run detail names an asset outside the reader's scope: %s", b)
		}
		if !strings.Contains(b, inName) || !strings.Contains(b, `"asset_count":1`) {
			t.Errorf("run detail lost the visible asset or its count: %s", b)
		}
		s, b = f.call(f.h.ListRuns, f.as(f.operator, http.MethodGet, "", nil))
		if s != http.StatusOK || strings.Contains(b, outName) || strings.Contains(b, f.assetOut) {
			t.Errorf("run list = %d and names an asset outside the reader's scope", s)
		}
		if !strings.Contains(b, own.ID.String()) {
			t.Errorf("run list lost the reader's own run")
		}
	})

	t.Run("step inputs and deliveries carry nothing of the redacted run", func(t *testing.T) {
		f.exec(`INSERT INTO automation_run_steps (id, automation_run_id, node_id, node_key, node_type, status, input, output)
			SELECT gen_random_uuid(), $1, gen_random_uuid(), 'marker', 'notification', 'completed', $2::jsonb, $2::jsonb
			WHERE NOT EXISTS (SELECT 1 FROM automation_run_steps WHERE automation_run_id = $1 AND node_key = 'marker')`,
			mixed.ID.String(), `{"title":"`+outName+`"}`)
		f.exec(`UPDATE automation_run_steps SET input = $2::jsonb, output = $2::jsonb WHERE automation_run_id = $1`,
			mixed.ID.String(), `{"title":"`+outName+`"}`)
		_, b := get(f.operator, mixed.ID)
		if strings.Contains(b, outName) {
			t.Errorf("step payload names an asset outside the reader's scope: %s", b)
		}
	})

	t.Run("a reader who sees every listed asset gets the run unchanged", func(t *testing.T) {
		_, b := get(f.admin, mixed.ID)
		if !strings.Contains(b, outName) || !strings.Contains(b, inName) || !strings.Contains(b, `"asset_count":2`) {
			t.Errorf("unrestricted reader should see the whole run: %s", b)
		}
	})

	t.Run("a reader who cannot see the first asset gets 404", func(t *testing.T) {
		only := trig(trigger(a(f.assetOut), a(f.assetIn)))
		if s, _ := get(f.operator, only.ID); s != http.StatusNotFound {
			t.Errorf("run whose subject is out of scope = %d, want 404", s)
		}
	})
}

func TestWorkflowRunsReaderScope_ScanCompleted_DB(t *testing.T) {
	f := newWFDB(t)
	nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"scan_completed"}},
		{"node_key":"n","node_type":"notification","name":"n","config":{"notification_type":"email","notification_config":{"title":"x","body":"y"}}}]`
	wf := f.create(nodes, `[{"source_node_key":"t","target_node_key":"n"}]`)
	run, err := f.svc.TriggerWorkflow(f.ctx, automationsvc.TriggerWorkflowInput{
		TenantID: shared.MustIDFromString(f.tenantA), WorkflowID: shared.MustIDFromString(wf),
		TriggerType: automationdom.TriggerTypeScanCompleted,
		TriggerData: map[string]any{"event_type": "scan_completed", "scan": map[string]any{
			"run_id": shared.NewID().String(), "status": "completed", "total_findings": 7,
			"scan_workflow_id": "wf-internal-marker", "trigger_type": "schedule"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pathParams := map[string]string{"id": run.ID.String()}
	s, b := f.call(f.h.GetRun, f.as(f.operator, http.MethodGet, "", pathParams))
	if s != http.StatusOK {
		t.Fatalf("GET run = %d %s", s, b)
	}
	if strings.Contains(b, "wf-internal-marker") || !strings.Contains(b, `"total_findings":7`) {
		t.Errorf("restricted reader should get run id, status and finding count only: %s", b)
	}
	_, b = f.call(f.h.GetRun, f.as(f.admin, http.MethodGet, "", pathParams))
	if !strings.Contains(b, "wf-internal-marker") {
		t.Errorf("unrestricted reader should get the whole scan data: %s", b)
	}
}
