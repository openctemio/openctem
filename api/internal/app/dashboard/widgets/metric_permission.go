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
	case assetBreakdowns[m.ID]:
		return permission.AssetsRead
	case m.ID == "remediation.campaign_progress":
		return permission.RemediationRead
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
			if ok {
				maskAssetParts(&d.Widgets[i], c)
			}
			continue
		}
		d.Widgets[i] = WidgetValue{
			ID: w.ID, Index: w.Index, WidgetType: w.WidgetType, Metric: w.Metric,
			State: StateUnsupported, Reason: ReasonForbidden,
		}
	}
}

// maskAssetParts removes the parts of a findings widget that are read from
// the coverage ledger (asset figures) when the caller may not read assets:
// the KPI strip's coverage tile, the blind spot lever, and a brief sentence
// that words it.
func maskAssetParts(w *WidgetValue, c dashboardapp.Caller) {
	if c.Has == nil || c.Has(permission.AssetsRead.String()) {
		return
	}
	if k := w.KPIs; k != nil {
		for i := range k.Tiles {
			if k.Tiles[i].Metric == "coverage.discovery" {
				k.Tiles[i] = KPITile{Key: k.Tiles[i].Key, Metric: k.Tiles[i].Metric, State: StateUnsupported, Reason: ReasonForbidden,
					Unit: k.Tiles[i].Unit, Polarity: k.Tiles[i].Polarity}
			}
		}
	}
	if l := w.Levers; l != nil {
		kept := l.Levers[:0]
		for _, x := range l.Levers {
			if x.Kind != LeverBlindSpot {
				kept = append(kept, x)
			}
		}
		l.Levers = kept
	}
	if b := w.Brief; b != nil {
		kept := b.Items[:0]
		for _, it := range b.Items {
			if it.Lever == nil || it.Lever.Kind != LeverBlindSpot {
				kept = append(kept, it)
			}
		}
		b.Items = kept
	}
}

// assetBreakdowns are the breakdowns that count assets.
var assetBreakdowns = map[string]bool{"surface.new_assets": true, "certificates.expiry": true}
