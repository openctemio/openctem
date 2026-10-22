package dashboard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The web console's dashboard templates (web/src/features/dashboards/templates.json)
// are typed widget configs copied into stored dashboards. Every widget must
// pass the same validation a save does, so a template is never refused.
func TestWebDashboardTemplatesAreValidSpecs(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "web", "src", "features", "dashboards", "templates.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read templates: %v", err)
	}
	var templates []struct {
		Key     string `json:"key"`
		Columns int    `json:"columns"`
		Widgets []struct {
			WidgetType string         `json:"widget_type"`
			W          int            `json:"w"`
			H          int            `json:"h"`
			Config     map[string]any `json:"config"`
		} `json:"widgets"`
	}
	if err := json.Unmarshal(raw, &templates); err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	if len(templates) == 0 {
		t.Fatal("no templates")
	}
	keys := map[string]bool{}
	for _, tpl := range templates {
		if keys[tpl.Key] {
			t.Errorf("template %q twice", tpl.Key)
		}
		keys[tpl.Key] = true
		if tpl.Columns < 1 || tpl.Columns > 4 {
			t.Errorf("%s: columns %d", tpl.Key, tpl.Columns)
		}
		ids := map[string]bool{}
		widgets := make([]dashboard.Widget, 0, len(tpl.Widgets))
		for i, w := range tpl.Widgets {
			spec, err := dashboard.ParseWidgetSpec(w.WidgetType, w.Config)
			if err != nil {
				t.Errorf("%s widget %d: %v", tpl.Key, i, err)
				continue
			}
			if ids[spec.ID] {
				t.Errorf("%s: widget id %s twice", tpl.Key, spec.ID)
			}
			ids[spec.ID] = true
			if w.W < 1 || w.W > 12 || w.H < 1 || w.H > 6 {
				t.Errorf("%s widget %d: size %dx%d", tpl.Key, i, w.W, w.H)
			}
			widgets = append(widgets, dashboard.Widget{WidgetType: w.WidgetType, X: 0, Y: i, W: w.W, H: w.H, Config: w.Config})
		}
		if _, err := dashboard.NewDashboard(shared.NewID(), shared.NewID(), tpl.Key, "", tpl.Columns, widgets); err != nil {
			t.Errorf("%s: as a dashboard: %v", tpl.Key, err)
		}
	}
}

// Every catalog metric has a translated name and definition in the web
// console (en and vi), so a metric added here never shows as a raw id.
func TestCatalogMetricsAreNamedInTheWebConsole(t *testing.T) {
	for _, locale := range []string{"en", "vi"} {
		path := filepath.Join("..", "..", "..", "..", "web", "src", "lib", "i18n", "dictionaries", locale, "dashboards.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("parse %s: %v", locale, err)
		}
		for _, m := range dashboard.Catalog() {
			base := "dashboards.metric." + strings.ReplaceAll(m.ID, ".", "_")
			for _, k := range []string{base + ".name", base + ".definition"} {
				if strings.TrimSpace(dict[k]) == "" {
					t.Errorf("%s: %s has no %s", locale, m.ID, k)
				}
			}
		}
	}
}
