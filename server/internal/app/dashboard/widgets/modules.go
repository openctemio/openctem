package widgets

// Module awareness of widget reads (docs/architecture/dashboards.md, "Module
// awareness"): a metric may read a tenant module (Metric.Module). While that
// module is off for the organization the gallery does not offer the metric
// and a widget of it carries no figure, never a "0" that would read as
// "nothing to see".

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ModuleChecker reports whether a module's data may be read for an
// organization (the module gate: on, or in its read-only grace).
type ModuleChecker interface {
	IsReadable(ctx context.Context, tenantID, moduleID string) bool
}

// SetModules wires the module check (nil: every module is readable).
func (s *Service) SetModules(m ModuleChecker) {
	s.modules = m
}

// moduleOff reports whether the metric reads a module that is off for the
// organization.
func (s *Service) moduleOff(ctx context.Context, tenantID shared.ID, m dashboard.Metric) bool {
	if m.Module == "" || s.modules == nil {
		return false
	}
	return !s.modules.IsReadable(ctx, tenantID.String(), m.Module)
}

// MetricOffered reports whether the gallery offers the metric to the
// organization: false while the module it reads is off.
func (s *Service) MetricOffered(ctx context.Context, tenantID shared.ID, metricID string) bool {
	m, ok := dashboard.LookupMetric(metricID)
	return ok && !s.moduleOff(ctx, tenantID, m)
}

// maskModulesOff replaces every widget whose metric reads a module that is
// off for the organization with an unsupported widget (reason module_off)
// that carries no figure. It runs on the way out, so it also covers figures
// read from a snapshot stored while the module was on.
func (s *Service) maskModulesOff(ctx context.Context, d *DashboardData, tenantID shared.ID) {
	for i := range d.Widgets {
		w := d.Widgets[i]
		if w.Metric == "" {
			continue
		}
		m, ok := dashboard.LookupMetric(w.Metric)
		if !ok || !s.moduleOff(ctx, tenantID, m) {
			continue
		}
		d.Widgets[i] = WidgetValue{
			ID: w.ID, Index: w.Index, WidgetType: w.WidgetType, Metric: w.Metric,
			State: StateUnsupported, Reason: ReasonModuleOff,
		}
	}
}

// moduleBackOn reports whether a stored snapshot holds a module_off widget
// whose module has been turned on again since: the snapshot has no figure
// for it, so the read computes again rather than keep the widget hidden
// until the next refresh.
func (s *Service) moduleBackOn(ctx context.Context, d *DashboardData, tenantID shared.ID) bool {
	for i := range d.Widgets {
		if d.Widgets[i].Reason != ReasonModuleOff {
			continue
		}
		if m, ok := dashboard.LookupMetric(d.Widgets[i].Metric); ok && !s.moduleOff(ctx, tenantID, m) {
			return true
		}
	}
	return false
}
