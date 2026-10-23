package dashboard

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func cfg(t *testing.T, js string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatalf("bad fixture %s: %v", js, err)
	}
	return m
}

func TestParseWidgetSpec_Valid(t *testing.T) {
	s, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, `{"v":2,"id":"w_7f3a","data":{"kind":"metric","metric":"findings.open","group_by":["severity"],"filter":{"source":["sast"],"kev":true}},"viz":{"type":"column"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Drill != "auto" || s.Data.Time.Range != TimeRangeInherit || s.Data.Time.Compare != CompareNone {
		t.Errorf("defaults not filled: %+v", s)
	}
	// Re-parsing the stored config gives the same spec (normalization is idempotent).
	stored, err := s.ToConfig()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseWidgetSpec(WidgetKindMetric, stored)
	if err != nil {
		t.Fatalf("stored config does not parse: %v", err)
	}
	if !reflect.DeepEqual(s, again) {
		t.Errorf("normalization not idempotent:\n%+v\n%+v", s, again)
	}
}

func TestParseWidgetSpec_DefaultVizByShape(t *testing.T) {
	for _, tc := range []struct {
		js   string
		want VizType
	}{
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`, VizStat},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity"]},"viz":{}}`, VizBar},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity","age_band"]},"viz":{}}`, VizHeatmap},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.age_bands"},"viz":{}}`, VizHeatmap},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"sla.within"},"viz":{}}`, VizProgress},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"flow.new_vs_fixed"},"viz":{}}`, VizDiverging},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"exposure.open_by_priority"},"viz":{}}`, VizArea},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.next"},"viz":{}}`, VizList},
		{`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.time_to_fix","group_by":["priority_class"]},"viz":{}}`, VizBar},
	} {
		s, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, tc.js))
		if err != nil {
			t.Fatalf("%s: %v", tc.js, err)
		}
		if s.Viz.Type != tc.want {
			t.Errorf("%s: viz = %s, want %s", tc.js, s.Viz.Type, tc.want)
		}
	}
}

func TestParseWidgetSpec_Refused(t *testing.T) {
	for name, js := range map[string]string{
		"unknown top-level field":   `{"v":2,"id":"w_a","sql":"select 1","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`,
		"unknown filter field":      `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","filter":{"tenant_id":["x"]}},"viz":{}}`,
		"unknown data field":        `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","query":"x"},"viz":{}}`,
		"wrong version":             `{"v":1,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`,
		"bad id":                    `{"v":2,"id":"../x","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`,
		"unknown metric":            `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"users.all"},"viz":{}}`,
		"kind mismatch":             `{"v":2,"id":"w_a","data":{"kind":"note","text":"x"},"viz":{}}`,
		"group-by not allowed":      `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"sla.within","group_by":["severity"]},"viz":{}}`,
		"group-by unknown":          `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["assignee"]},"viz":{}}`,
		"too many group-bys":        `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity","source","kev"]},"viz":{}}`,
		"duplicate group-by":        `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity","severity"]},"viz":{}}`,
		"viz unfit for scalar":      `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{"type":"heatmap"}}`,
		"area for a flow":           `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"flow.new_vs_fixed"},"viz":{"type":"area"}}`,
		"unknown viz":               `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{"type":"iframe"}}`,
		"severity value":            `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","filter":{"severity":["catastrophic"]}},"viz":{}}`,
		"filter dim not on metric":  `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.time_to_fix","filter":{"source":["sast"]}},"viz":{}}`,
		"kev on F2 metric":          `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"flow.new_vs_fixed","filter":{"kev":true}},"viz":{}}`,
		"asset group not an id":     `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","filter":{"asset_group_id":["1 OR 1=1"]}},"viz":{}}`,
		"time range":                `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.time_to_fix","time":{"range":"10y"}},"viz":{}}`,
		"time on a list":            `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.next","time":{"compare":"previous_period"}},"viz":{}}`,
		"limit on a scalar":         `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","limit":5},"viz":{}}`,
		"list limit too large":      `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.next","limit":11},"viz":{}}`,
		"severity filter on a list": `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"sla.at_risk","filter":{"severity":["low"]}},"viz":{}}`,
		"target on a category":      `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity"]},"viz":{},"target":{"op":"<=","value":0}}`,
		"target op":                 `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{},"target":{"op":"==","value":0}}`,
		"drill url":                 `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{},"drill":"https://example.com"}`,
		"orientation":               `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity"]},"viz":{"options":{"orientation":"diagonal"}}}`,
		"text on a metric":          `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","text":"<script>"},"viz":{}}`,
		"long title":                `{"v":2,"id":"w_a","title":"` + strings.Repeat("x", 121) + `","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`,
		"wrong type":                `{"v":"2","id":"w_a","data":{"kind":"metric","metric":"findings.open"},"viz":{}}`,
		"too many filter values":    `{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","filter":{"severity":[` + strings.TrimSuffix(strings.Repeat(`"high",`, 21), ",") + `]}},"viz":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, js))
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("error %v is not a validation error", err)
			}
			if strings.Contains(err.Error(), "select 1") || strings.Contains(err.Error(), "<script>") {
				t.Errorf("error echoes the input: %v", err)
			}
		})
	}
}

func TestParseWidgetSpec_Note(t *testing.T) {
	s, err := ParseWidgetSpec(WidgetKindNote, cfg(t, `{"v":2,"id":"w_n","data":{"kind":"note","text":"  Read **this** first  "},"viz":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Data.Text != "Read **this** first" || s.Viz.Type != VizNote || s.Drill != "none" {
		t.Errorf("note not normalized: %+v", s)
	}
	for name, js := range map[string]string{
		"empty":        `{"v":2,"id":"w_n","data":{"kind":"note","text":" "},"viz":{}}`,
		"with metric":  `{"v":2,"id":"w_n","data":{"kind":"note","text":"x","metric":"findings.open"},"viz":{}}`,
		"with filter":  `{"v":2,"id":"w_n","data":{"kind":"note","text":"x","filter":{"kev":true}},"viz":{}}`,
		"chart viz":    `{"v":2,"id":"w_n","data":{"kind":"note","text":"x"},"viz":{"type":"bar"}}`,
		"too long":     `{"v":2,"id":"w_n","data":{"kind":"note","text":"` + strings.Repeat("y", 2001) + `"},"viz":{}}`,
		"with a range": `{"v":2,"id":"w_n","data":{"kind":"note","text":"x","time":{"range":"7d"}},"viz":{}}`,
	} {
		if _, err := ParseWidgetSpec(WidgetKindNote, cfg(t, js)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDashboard_TypedWidgetsNormalizedAndUnique(t *testing.T) {
	w := func(id string) Widget {
		return Widget{WidgetType: WidgetKindMetric, W: 3, H: 2, Config: cfg(t, `{"v":2,"id":"`+id+`","data":{"kind":"metric","metric":"sla.within"},"viz":{}}`)}
	}
	d, err := NewDashboard(shared.NewID(), shared.NewID(), "Board", "", 2, []Widget{w("w_a"), {WidgetType: "open_findings", W: 1, H: 1}})
	if err != nil {
		t.Fatal(err)
	}
	got := d.Widgets()[0].Config
	if got["drill"] != "auto" || got["viz"].(map[string]any)["type"] != string(VizProgress) {
		t.Errorf("stored config is not the normalized spec: %v", got)
	}
	if _, err := NewDashboard(shared.NewID(), shared.NewID(), "Board", "", 2, []Widget{w("w_a"), w("w_a")}); err == nil {
		t.Error("duplicate widget ids accepted")
	}
	bad := Widget{WidgetType: WidgetKindMetric, W: 1, H: 1, Config: cfg(t, `{"v":2,"id":"w_b","data":{"kind":"metric","metric":"nope"},"viz":{}}`)}
	if err := d.Update("Board", "", 2, []Widget{bad}); err == nil {
		t.Error("update accepted an invalid typed widget")
	}
}

func TestCatalog_EveryMetricConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Catalog() {
		if seen[m.ID] {
			t.Errorf("duplicate metric %s", m.ID)
		}
		seen[m.ID] = true
		for _, d := range m.GroupBys {
			if !containsDim(m.Filters, d) {
				t.Errorf("%s groups by %s but cannot filter on it", m.ID, d)
			}
		}
		for _, d := range m.DefaultGroupBy {
			if !containsDim(m.GroupBys, d) {
				t.Errorf("%s default group-by %s is not allowed", m.ID, d)
			}
		}
		if len(m.Vizzes(m.EffectiveGroupBy(nil))) == 0 {
			t.Errorf("%s has no visualization", m.ID)
		}
		// The metric with no options is a valid widget.
		js := `{"v":2,"id":"w_x","data":{"kind":"metric","metric":"` + m.ID + `"},"viz":{}}`
		if _, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, js)); err != nil {
			t.Errorf("%s bare widget: %v", m.ID, err)
		}
		if err := m.DefaultFilter.validate(m); err != nil {
			t.Errorf("%s default filter: %v", m.ID, err)
		}
	}
}

func TestLegacySpec(t *testing.T) {
	for id := range legacySpecs {
		s, ok := LegacySpec(id, "w_legacy0")
		if !ok {
			t.Errorf("%s does not map", id)
			continue
		}
		if s.ID != "w_legacy0" || s.V != WidgetSpecVersion {
			t.Errorf("%s: %+v", id, s)
		}
	}
	if _, ok := LegacySpec("assigned_to_me", "w_x"); ok {
		t.Error("a tile the facts cannot answer must not map")
	}
}

func FuzzParseWidgetSpec(f *testing.F) {
	f.Add(`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"findings.open","group_by":["severity"]},"viz":{"type":"bar"}}`)
	f.Add(`{"v":2,"id":"w_n","data":{"kind":"note","text":"x"},"viz":{}}`)
	f.Add(`{"v":2,"id":"w_a","data":{"kind":"metric","metric":"fix.next","limit":10},"viz":{},"target":{"op":"<=","value":1}}`)
	f.Fuzz(func(t *testing.T, js string) {
		var m map[string]any
		if json.Unmarshal([]byte(js), &m) != nil {
			return
		}
		for _, kind := range []string{WidgetKindMetric, WidgetKindNote} {
			s, err := ParseWidgetSpec(kind, m)
			if err != nil {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("non-validation error: %v", err)
				}
				continue
			}
			stored, err := s.ToConfig()
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseWidgetSpec(kind, stored)
			if err != nil {
				t.Fatalf("accepted spec does not re-parse: %v", err)
			}
			if !reflect.DeepEqual(s, again) {
				t.Fatalf("not idempotent: %+v vs %+v", s, again)
			}
		}
	})
}

func TestParseWidgetSpec_CTEMMetrics(t *testing.T) {
	valid := []string{
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop"},"viz":{"type":"loop"}}`,
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop"},"viz":{"type":"table"}}`,
		`{"v":2,"id":"w_p","data":{"kind":"metric","metric":"attack_paths.to_crown_jewels","limit":5},"viz":{"type":"paths"}}`,
		`{"v":2,"id":"w_c","data":{"kind":"metric","metric":"crown_jewels.exposed"},"viz":{"type":"stat"},"target":{"op":"<=","value":0}}`,
		`{"v":2,"id":"w_c","data":{"kind":"metric","metric":"crown_jewels.exposed","filter":{"priority_class":["P0"]}},"viz":{"type":"stat"}}`,
	}
	for _, js := range valid {
		if _, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, js)); err != nil {
			t.Errorf("%s: %v", js, err)
		}
	}
	// Defaults: the loop draws as a loop, attack paths list 10 at most.
	s, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, `{"v":2,"id":"w_p","data":{"kind":"metric","metric":"attack_paths.to_crown_jewels"},"viz":{}}`))
	if err != nil || s.Viz.Type != VizPaths || s.Data.Limit != defaultItemsLimit {
		t.Errorf("paths defaults: %+v %v", s, err)
	}
	invalid := []string{
		// a loop is not a bar, a stat or a list
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop"},"viz":{"type":"bar"}}`,
		// current figures: no time window, no comparison
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop","time":{"range":"30d"}},"viz":{"type":"loop"}}`,
		`{"v":2,"id":"w_c","data":{"kind":"metric","metric":"crown_jewels.exposed","time":{"compare":"previous_period"}},"viz":{"type":"stat"}}`,
		// no filters other than the declared ones
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop","filter":{"severity":["high"]}},"viz":{"type":"loop"}}`,
		`{"v":2,"id":"w_c","data":{"kind":"metric","metric":"crown_jewels.exposed","filter":{"kev":true}},"viz":{"type":"stat"}}`,
		// no group-by, a bounded list, no target on a loop
		`{"v":2,"id":"w_c","data":{"kind":"metric","metric":"crown_jewels.exposed","group_by":["severity"]},"viz":{"type":"bar"}}`,
		`{"v":2,"id":"w_p","data":{"kind":"metric","metric":"attack_paths.to_crown_jewels","limit":11},"viz":{"type":"paths"}}`,
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop","limit":3},"viz":{"type":"loop"}}`,
		`{"v":2,"id":"w_l","data":{"kind":"metric","metric":"ctem.loop"},"viz":{"type":"loop"},"target":{"op":">=","value":1}}`,
		// the new visualizations do not fit other shapes
		`{"v":2,"id":"w_x","data":{"kind":"metric","metric":"findings.open"},"viz":{"type":"loop"}}`,
		`{"v":2,"id":"w_x","data":{"kind":"metric","metric":"fix.next"},"viz":{"type":"paths"}}`,
	}
	for _, js := range invalid {
		if _, err := ParseWidgetSpec(WidgetKindMetric, cfg(t, js)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", js, err)
		}
	}
}
