package routes

// The exposure flow panel routes (docs/architecture/dashboards.md): status
// codes, the permission gate of the organization routes, owner-only personal
// access, tenant isolation, one-time add and the audit rows.

import (
	"net/http"
	"testing"
)

func TestDashboardFlowPanel_Routes_DB(t *testing.T) {
	h := newDashHarness(t)
	me := caller{h.tenant, h.viewer, false, nil}
	colleague := caller{h.tenant, h.plain, false, nil}
	otherTenant := caller{h.other, h.otherManager, true, []string{dashManage}}
	manager := caller{h.tenant, h.manager, false, []string{dashManage}}
	viewer := caller{h.tenant, h.viewerR, false, []string{dashView}}

	body := map[string]any{"name": "Mine", "columns": 2, "layout": []map[string]any{{"widget_type": "kpi", "x": 0, "y": 0, "w": 3, "h": 2}}}
	code, d := h.do(me, http.MethodPost, "/api/v1/me/dashboards", body)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, d)
	}
	id := d["id"].(string)
	if d["flow_panel_at"] == nil {
		t.Fatal("a new dashboard must come back already offered (flow_panel_at set)")
	}
	// An existing dashboard has flow_panel_at NULL.
	h.exec(`UPDATE user_dashboards SET flow_panel_at = NULL WHERE id = $1`, id)
	path := "/api/v1/me/dashboards/" + id + "/flow-panels"

	for name, c := range map[string]caller{"colleague": colleague, "admin of the tenant": {h.tenant, h.owner, true, nil}, "other tenant": otherTenant} {
		if code, _ := h.do(c, http.MethodPost, path, nil); code != http.StatusNotFound {
			t.Errorf("%s adds = %d, want 404", name, code)
		}
		if code, _ := h.do(c, http.MethodDelete, path+"/w_flow", nil); code != http.StatusNotFound {
			t.Errorf("%s undoes = %d, want 404", name, code)
		}
	}

	code, res := h.do(me, http.MethodPost, path, nil)
	if code != http.StatusOK || res["added"] != true || res["widget_id"] != "w_flow" {
		t.Fatalf("add = %d %v", code, res)
	}
	if dash, _ := res["dashboard"].(map[string]any); dash["flow_panel_at"] == nil || len(dash["layout"].([]any)) != 2 {
		t.Fatalf("dashboard after add = %v", res["dashboard"])
	}
	if code, res := h.do(me, http.MethodPost, path, nil); code != http.StatusOK || res["added"] != false {
		t.Fatalf("second add = %d %v", code, res)
	}
	if h.auditCount("dashboard.flow_panel_added", id) != 1 {
		t.Fatal("add not audited exactly once")
	}
	if code, _ := h.do(me, http.MethodDelete, path+"/w_missing", nil); code != http.StatusBadRequest {
		t.Fatalf("undo of an unknown widget = %d, want 400", code)
	}
	if code, out := h.do(me, http.MethodDelete, path+"/w_flow", nil); code != http.StatusOK || len(out["layout"].([]any)) != 1 || out["flow_panel_at"] == nil {
		t.Fatalf("undo = %d %v", code, out)
	}
	if h.auditCount("dashboard.flow_panel_undone", id) != 1 {
		t.Fatal("undo not audited")
	}
	if _, res := h.do(me, http.MethodPost, path, nil); res["added"] != false {
		t.Fatalf("add after undo = %v", res)
	}

	// Organization: dashboards:org:manage on both routes.
	code, org := h.do(manager, http.MethodPost, "/api/v1/organization/dashboards", body)
	if code != http.StatusCreated {
		t.Fatalf("org create = %d %v", code, org)
	}
	oid := org["id"].(string)
	h.exec(`UPDATE user_dashboards SET flow_panel_at = NULL WHERE id = $1`, oid)
	opath := "/api/v1/organization/dashboards/" + oid + "/flow-panels"
	for name, c := range map[string]caller{"viewer": viewer, "plain member": colleague} {
		if code, _ := h.do(c, http.MethodPost, opath, nil); code != http.StatusForbidden {
			t.Errorf("%s adds = %d, want 403", name, code)
		}
		if code, _ := h.do(c, http.MethodDelete, opath+"/w_flow", nil); code != http.StatusForbidden {
			t.Errorf("%s undoes = %d, want 403", name, code)
		}
	}
	if code, _ := h.do(otherTenant, http.MethodPost, opath, nil); code != http.StatusNotFound {
		t.Errorf("manager of another tenant adds = %d, want 404", code)
	}
	if code, _ := h.do(manager, http.MethodPost, path, nil); code != http.StatusNotFound {
		t.Errorf("personal route on someone's dashboard = %d, want 404", code)
	}
	if code, res := h.do(manager, http.MethodPost, opath, nil); code != http.StatusOK || res["added"] != true {
		t.Fatalf("org add = %d %v", code, res)
	}
	if h.auditCount("dashboard.flow_panel_added", oid) != 1 {
		t.Fatal("org add not audited")
	}
	if code, _ := h.do(manager, http.MethodDelete, opath+"/w_flow", nil); code != http.StatusOK {
		t.Fatalf("org undo = %d", code)
	}
	if h.auditCount("dashboard.flow_panel_undone", oid) != 1 {
		t.Fatal("org undo not audited")
	}
	// The org route never reaches a personal dashboard.
	if code, _ := h.do(manager, http.MethodPost, "/api/v1/organization/dashboards/"+id+"/flow-panels", nil); code != http.StatusNotFound {
		t.Errorf("org route on a personal dashboard = %d, want 404", code)
	}
}
