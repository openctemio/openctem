package routes

import (
	"net/http"
	"testing"
)

// Typed widgets are validated on every write path (personal create and
// update, organization create): a config the server did not validate is never
// stored, and what is stored is the normalized spec.
func TestDashboards_TypedWidgetSpec_DB(t *testing.T) {
	h := newDashHarness(t)
	member := caller{h.tenant, h.plain, false, nil}
	manager := caller{h.tenant, h.manager, false, []string{dashManage}}

	good := map[string]any{"widget_type": "metric", "x": 0, "y": 0, "w": 3, "h": 2, "config": map[string]any{
		"v": 2, "id": "w_kpi1", "data": map[string]any{"kind": "metric", "metric": "exposure.priority_open"}, "viz": map[string]any{},
	}}
	smuggle := map[string]any{"widget_type": "metric", "x": 0, "y": 0, "w": 3, "h": 2, "config": map[string]any{
		"v": 2, "id": "w_kpi2", "data": map[string]any{"kind": "metric", "metric": "findings.open", "filter": map[string]any{"tenant_id": []string{h.other.String()}}}, "viz": map[string]any{},
	}}
	wrongViz := map[string]any{"widget_type": "metric", "x": 0, "y": 0, "w": 3, "h": 2, "config": map[string]any{
		"v": 2, "id": "w_kpi3", "data": map[string]any{"kind": "metric", "metric": "sla.within"}, "viz": map[string]any{"type": "heatmap"},
	}}

	code, created := h.do(member, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "Typed", "layout": []any{good}})
	if code != http.StatusCreated {
		t.Fatalf("create typed = %d %v", code, created)
	}
	layout := created["layout"].([]any)
	cfg := layout[0].(map[string]any)["config"].(map[string]any)
	if cfg["drill"] != "auto" || cfg["viz"].(map[string]any)["type"] != "stat" {
		t.Errorf("stored config is not normalized: %v", cfg)
	}
	id := created["id"].(string)

	for name, w := range map[string]any{"unknown filter field": smuggle, "visualization unfit for the shape": wrongViz} {
		if code, _ := h.do(member, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "Bad " + name, "layout": []any{w}}); code != http.StatusBadRequest {
			t.Errorf("personal create with %s = %d, want 400", name, code)
		}
		if code, _ := h.do(member, http.MethodPut, "/api/v1/me/dashboards/"+id, map[string]any{"name": "Typed", "layout": []any{w}}); code != http.StatusBadRequest {
			t.Errorf("personal update with %s = %d, want 400", name, code)
		}
		if code, _ := h.do(manager, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "Org " + name, "layout": []any{w}}); code != http.StatusBadRequest {
			t.Errorf("organization create with %s = %d, want 400", name, code)
		}
	}

	// The catalog is readable by any member and lists the metrics with shapes.
	code, cat := h.do(member, http.MethodGet, "/api/v1/me/dashboards/widget-catalog", nil)
	if code != http.StatusOK {
		t.Fatalf("catalog = %d", code)
	}
	metrics, _ := cat["metrics"].([]any)
	if len(metrics) == 0 || cat["spec_version"].(float64) != 2 {
		t.Fatalf("catalog = %v", cat)
	}
	for _, m := range metrics {
		mm := m.(map[string]any)
		if _, ok := mm["shapes"].(map[string]any)["0"]; !ok {
			t.Errorf("metric %v has no shape for zero group-bys", mm["id"])
		}
	}
}
