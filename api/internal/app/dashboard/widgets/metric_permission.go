package widgets

import (
	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// metricPermission is the permission to read what a metric counts. A personal
// dashboard computes figures for the caller's data scope, so the figure needs
// the same entity permission as reading those rows directly.
func metricPermission(m dashboard.Metric) permission.Permission {
	switch {
	case m.Kind == dashboard.MetricKindAssetCount, m.Kind == dashboard.MetricKindPaths, m.ID == "coverage.discovery":
		return permission.AssetsRead
	default:
		return permission.FindingsRead
	}
}

// maskForbidden replaces every widget of a personal read whose metric the
// caller may not read with an unsupported widget (reason "forbidden") that
// carries no figure. It runs on the way out, so it also covers figures read
// from a stored snapshot.
func maskForbidden(d *DashboardData, c dashboardapp.Caller) {
	for i := range d.Widgets {
		w := d.Widgets[i]
		if w.Metric == "" {
			continue
		}
		m, ok := dashboard.LookupMetric(w.Metric)
		if !ok || (c.Has != nil && c.Has(metricPermission(m).String())) {
			continue
		}
		d.Widgets[i] = WidgetValue{
			ID: w.ID, Index: w.Index, WidgetType: w.WidgetType, Metric: w.Metric,
			State: StateUnsupported, Reason: ReasonForbidden,
		}
	}
}
