package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
)

// Personal dashboard figures are computed for the caller's data scope, but a
// role still needs dashboard:read for the routes that compute them and the
// entity permission of each metric (findings:read, assets:read).
func TestPersonalDashboardFigures_NeedPermissions_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	preview := func(perms []string, metric string) (int, string) {
		return e.call(h.memberA, false, perms, http.MethodPost, "/api/v1/me/dashboards/widget-preview", metricWidget("w_pm", metric, nil))
	}

	t.Run("preview without dashboard:read is 403", func(t *testing.T) {
		code, body := preview([]string{"team:read", "scans:read"}, "fix.next")
		if code != http.StatusForbidden {
			t.Errorf("preview = %d %s, want 403", code, body)
		}
	})

	t.Run("data and refresh without dashboard:read are 403", func(t *testing.T) {
		perms := []string{"team:read", "scans:read"}
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/me/dashboards/" + h.tenant.String() + "/data"},
			{http.MethodPost, "/api/v1/me/dashboards/" + h.tenant.String() + "/refresh"},
		} {
			if code, body := e.call(h.memberA, false, perms, c.method, c.path, nil); code != http.StatusForbidden {
				t.Errorf("%s %s = %d %s, want 403", c.method, c.path, code, body)
			}
		}
	})

	t.Run("layout routes need no dashboard:read", func(t *testing.T) {
		code, body := e.call(h.memberA, false, []string{"team:read"}, http.MethodGet, "/api/v1/me/dashboards/widget-catalog", nil)
		if code != http.StatusOK {
			t.Errorf("widget-catalog = %d %s, want 200", code, body)
		}
	})

	t.Run("a metric needs its entity permission", func(t *testing.T) {
		code, body := preview([]string{"dashboard:read", "assets:read"}, "fix.next")
		if code != http.StatusOK {
			t.Fatalf("preview = %d %s", code, body)
		}
		var w widgets.WidgetValue
		if err := json.Unmarshal([]byte(body), &w); err != nil {
			t.Fatal(err)
		}
		if w.State != widgets.StateUnsupported || w.Reason != widgets.ReasonForbidden || w.Items != nil || strings.Contains(body, "asset_name") {
			t.Errorf("fix.next without findings:read = %s, want an unsupported widget with no rows", body)
		}
		code, body = preview([]string{"dashboard:read", "findings:read"}, "fix.next")
		if code != http.StatusOK || strings.Contains(body, `"forbidden"`) {
			t.Errorf("fix.next with findings:read = %d %s, want figures", code, body)
		}
	})

	t.Run("a stored layout read is masked the same way", func(t *testing.T) {
		code, body := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards",
			map[string]any{"name": "perm-mask", "layout": []any{metricWidget("w_next", "fix.next", nil), metricWidget("w_open", "findings.open", nil)}})
		if code != http.StatusCreated {
			t.Fatalf("create = %d %s", code, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(body), &created)
		got := e.data(t, h.memberA, false, []string{"dashboard:read", "assets:read"}, "/api/v1/me/dashboards/"+created.ID+"/data")
		if len(got.Widgets) != 2 {
			t.Fatalf("widgets = %d, want 2", len(got.Widgets))
		}
		for _, w := range got.Widgets {
			if w.Reason != widgets.ReasonForbidden || w.Scalar != nil || w.Items != nil {
				t.Errorf("widget %s leaked figures without findings:read: %+v", w.ID, w)
			}
		}
	})

	t.Run("refresh now is masked the same way", func(t *testing.T) {
		code, body := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards",
			map[string]any{"name": "perm-refresh", "layout": []any{metricWidget("w_next", "fix.next", nil)}})
		if code != http.StatusCreated {
			t.Fatalf("create = %d %s", code, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(body), &created)
		code, body = e.call(h.memberA, false, []string{"dashboard:read", "assets:read"}, http.MethodPost, "/api/v1/me/dashboards/"+created.ID+"/refresh", nil)
		if code != http.StatusOK {
			t.Fatalf("refresh = %d %s", code, body)
		}
		var got dataResp
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Widgets) != 1 {
			t.Fatalf("widgets = %d, want 1", len(got.Widgets))
		}
		w := got.Widgets[0]
		if w.State != widgets.StateUnsupported || w.Reason != widgets.ReasonForbidden || w.Scalar != nil || w.Items != nil || strings.Contains(body, "asset_name") {
			t.Errorf("refresh leaked figures without findings:read: %s", body)
		}
	})
}
