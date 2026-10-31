package widgets

// Nothing to count yet (docs/architecture/dashboards.md, "Empty and
// unmeasured widgets"): a findings figure in a scope that has never held a
// finding is not measured, never a "0", an empty chart or a met target. The
// web draws every such widget in the one compact empty state with its next
// step. Whether the scope holds a finding is read once per dashboard read.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// ReasonNoFindings: no published finding, in any status, is in the scope.
const ReasonNoFindings = "no_findings"

// metricDiscoveryCoverage is the discovery coverage metric, read from the
// coverage ledger (not from findings).
const metricDiscoveryCoverage = "coverage.discovery"

type findingsProbeKey struct{}

// findingsProbe caches HasFindings for one dashboard read (one scope).
type findingsProbe struct {
	done bool
	has  bool
}

// withFindingsProbe returns a context whose reads share one HasFindings.
func withFindingsProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, findingsProbeKey{}, &findingsProbe{})
}

// hasFindings reports whether the scope holds any finding, cached for the
// read when the context carries a probe.
func (s *Service) hasFindings(ctx context.Context, scope dashboard.ReadScope) (bool, error) {
	p, _ := ctx.Value(findingsProbeKey{}).(*findingsProbe)
	if p != nil && p.done {
		return p.has, nil
	}
	has, err := s.facts.HasFindings(ctx, scope)
	if err != nil {
		return false, err
	}
	if p != nil {
		p.done, p.has = true, has
	}
	return has, nil
}

// countsFindings reports a metric whose whole figure is counted from
// findings: with none in scope it is not measured. The exposure flow and
// the KPI strip are partly read from other sources and decide per part;
// the levers and the brief already show nothing without findings; asset,
// coverage, certificate and attack path figures do not read findings, and
// crown jewels exposed is not measured by its own reason (no crown jewel
// designated) first.
func countsFindings(m dashboard.Metric) bool {
	switch m.Kind {
	case dashboard.MetricKindCount, dashboard.MetricKindDuration, dashboard.MetricKindSeries,
		dashboard.MetricKindItems:
		return true
	case dashboard.MetricKindRatio:
		return m.ID != metricDiscoveryCoverage
	case dashboard.MetricKindBreakdown:
		return m.ID == "exceptions.expiring"
	}
	return false
}
