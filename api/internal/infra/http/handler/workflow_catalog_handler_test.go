package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The catalog lists exactly the types the engine runs, never a removed
// one, and says per type whether the caller holds its permission.
func TestWorkflowCatalog_ListsRunnableTypesWithPermission(t *testing.T) {
	h := &WorkflowHandler{logger: logger.NewNop()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/catalog", nil)
	req = req.WithContext(authzCtx(false, string(permission.WorkflowsRead), string(permission.FindingsWrite)))
	rec := httptest.NewRecorder()
	h.GetCatalog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp WorkflowCatalogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Triggers) != len(automation.TriggerTypes()) || len(resp.Actions) != len(automation.ActionTypes()) ||
		len(resp.Notifications) != len(automation.NotificationTypes()) {
		t.Fatalf("catalog sizes %d/%d/%d differ from the domain lists", len(resp.Triggers), len(resp.Actions), len(resp.Notifications))
	}
	removed := map[string]bool{
		"schedule": true, "finding_age": true, "finding_updated": true, "webhook": true,
		"assign_team": true, "update_priority": true, "run_script": true, "http_request": true,
		"trigger_pipeline": true, "pagerduty": true,
	}
	for _, list := range [][]WorkflowCatalogEntry{resp.Triggers, resp.Actions} {
		for _, e := range list {
			if removed[e.Type] {
				t.Errorf("removed type %s is offered", e.Type)
			}
		}
	}
	for _, e := range resp.Notifications {
		if e.Type == "pagerduty" {
			t.Errorf("removed notification %s is offered", e.Type)
		}
	}
	byType := map[string]WorkflowCatalogEntry{}
	for _, e := range resp.Actions {
		byType[e.Type] = e
	}
	if e := byType["update_status"]; !e.Allowed || e.Permission != string(permission.FindingsWrite) {
		t.Errorf("update_status = %+v, want allowed with findings:write", e)
	}
	if e := byType["trigger_scan"]; e.Allowed || e.Permission != string(permission.ScansWrite) {
		t.Errorf("trigger_scan = %+v, want not allowed (needs scans:write)", e)
	}
	for _, e := range resp.Triggers {
		if !e.Allowed || e.Permission != "" {
			t.Errorf("trigger %s = %+v, want allowed without a permission", e.Type, e)
		}
	}
}
