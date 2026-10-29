package dashboard

import (
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FlowMetricID is the metric of the exposure flow panel.
const FlowMetricID = "exposure.flow"

// flowWidgetBaseID is the config id of an added flow panel (suffixed when
// taken).
const flowWidgetBaseID = "w_flow"

// IsFlowWidget reports whether w is a typed widget computing the exposure flow
// metric.
func IsFlowWidget(w Widget) bool {
	if w.WidgetType != WidgetKindMetric {
		return false
	}
	spec, err := ParseWidgetSpec(w.WidgetType, w.Config)
	return err == nil && spec.Data.Metric == FlowMetricID
}

// HasFlowWidget reports whether the layout holds an exposure flow widget.
func (d *Dashboard) HasFlowWidget() bool {
	for _, w := range d.widgets {
		if IsFlowWidget(w) {
			return true
		}
	}
	return false
}

// WidgetConfigID returns the config id of a widget ("" when it has none).
func WidgetConfigID(w Widget) string {
	id, _ := w.Config["id"].(string)
	return id
}

// PrependFlowPanel puts a full-width exposure flow widget at the top of the
// layout and returns its config id. The other widgets move down by the panel's
// height. The layout is validated like any other save.
func (d *Dashboard) PrependFlowPanel() (string, error) {
	taken := make(map[string]bool, len(d.widgets))
	for _, w := range d.widgets {
		taken[WidgetConfigID(w)] = true
	}
	id := flowWidgetBaseID
	for n := 2; taken[id]; n++ {
		id = flowWidgetBaseID + strconv.Itoa(n)
	}
	const panelH = 4
	flow := Widget{
		WidgetType: WidgetKindMetric, X: 0, Y: 0, W: 12, H: panelH,
		Config: map[string]any{
			"v":     2,
			"id":    id,
			"title": "",
			"data": map[string]any{
				"kind": WidgetKindMetric, "metric": FlowMetricID,
				"filter": map[string]any{}, "time": map[string]any{"range": "30d"},
			},
			"viz": map[string]any{"type": "flow", "options": map[string]any{}},
		},
	}
	next := make([]Widget, 0, len(d.widgets)+1)
	next = append(next, flow)
	for _, w := range d.widgets {
		w.Y += panelH
		next = append(next, w)
	}
	if err := d.Update(d.name, d.description, d.columns, next); err != nil {
		return "", err
	}
	return id, nil
}

// RemoveFlowWidget removes the exposure flow widget with this config id. Any
// other widget id (or an id that is not a flow widget) is a validation error:
// Undo never deletes a tile it did not add. flow_panel_at is left alone.
func (d *Dashboard) RemoveFlowWidget(widgetID string) error {
	for i, w := range d.widgets {
		if WidgetConfigID(w) != widgetID || widgetID == "" {
			continue
		}
		if !IsFlowWidget(w) {
			return fmt.Errorf("%w: the widget is not an exposure flow panel", shared.ErrValidation)
		}
		next := make([]Widget, 0, len(d.widgets)-1)
		next = append(next, d.widgets[:i]...)
		next = append(next, d.widgets[i+1:]...)
		return d.Update(d.name, d.description, d.columns, next)
	}
	return fmt.Errorf("%w: no such exposure flow panel on this dashboard", shared.ErrValidation)
}

// MarkFlowPanelOffered records that the panel was offered at t.
func (d *Dashboard) MarkFlowPanelOffered(t time.Time) { d.flowPanelAt = &t }
