package widgets

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// KPI tile keys, in strip order.
const (
	KPIPriorityOpen = "priority_open"
	KPIKEVOpen      = "kev_open"
	KPISLAWithin    = "sla_within"
	KPITimeToFix    = "time_to_fix"
	KPICoverage     = "coverage"
)

// KPITile is one figure of the KPI strip, computed exactly as the
// single-figure widget of its metric. Value is nil when not measured.
type KPITile struct {
	Key      string             `json:"key" enums:"priority_open,kev_open,sla_within,time_to_fix,coverage"`
	Metric   string             `json:"metric"`
	State    string             `json:"state" enums:"ready,not_measured"`
	Reason   string             `json:"reason,omitempty"`
	Value    *float64           `json:"value"`
	Unit     string             `json:"unit" enums:"count,percent,hours"`
	Previous *float64           `json:"previous,omitempty"`
	Polarity dashboard.Polarity `json:"polarity"`
	// N is the number of fixes a time to fix is measured on.
	N      *int64  `json:"n,omitempty"`
	Series []Point `json:"series,omitempty"`
	Drill  string  `json:"drill,omitempty"`
}

// KPIsValue is the KPI strip.
type KPIsValue struct {
	Tiles []KPITile `json:"tiles"`
}

func i2f(n int64) *float64 {
	f := float64(n)
	return &f
}

// kpis computes the five tiles for a scope and window.
func (s *Service) kpis(ctx context.Context, scope dashboard.ReadScope, win Window, compare bool) (*KPIsValue, error) {
	out := &KPIsValue{Tiles: make([]KPITile, 0, 5)}

	countTile := func(key, metric string, f dashboard.WidgetFilter) error {
		tmp := &WidgetValue{}
		if err := s.count(ctx, tmp, f, nil, win, compare, 0, scope); err != nil {
			return err
		}
		t := KPITile{Key: key, Metric: metric, State: StateReady, Unit: UnitCount, Polarity: dashboard.PolarityLowerBetter, Drill: drillHref(f)}
		if sv := tmp.Scalar; sv != nil {
			t.Value = i2f(sv.Value)
			if sv.Previous != nil {
				t.Previous = i2f(*sv.Previous)
			}
			t.Series = sv.Series
		}
		out.Tiles = append(out.Tiles, t)
		return nil
	}
	if err := countTile(KPIPriorityOpen, "exposure.priority_open", dashboard.WidgetFilter{PriorityClass: []string{"P0", "P1"}}); err != nil {
		return nil, err
	}
	if err := countTile(KPIKEVOpen, "intel.kev_open", dashboard.WidgetFilter{KEV: boolp(true)}); err != nil {
		return nil, err
	}

	num, den, err := s.facts.SLAWithin(ctx, scope, dashboard.WidgetFilter{})
	if err != nil {
		return nil, err
	}
	sla := KPITile{Key: KPISLAWithin, Metric: "sla.within", State: StateReady, Unit: UnitPercent, Polarity: dashboard.PolarityHigherBetter,
		Drill: drillHref(dashboard.WidgetFilter{SLAState: []string{"breached"}})}
	if den == 0 {
		sla.State, sla.Reason = StateNotMeasured, ReasonNoDenominator
	} else {
		v := pct(num, den)
		sla.Value = &v
	}
	out.Tiles = append(out.Tiles, sla)

	dur := &WidgetValue{State: StateReady}
	if err := s.duration(ctx, dur, dashboard.WidgetFilter{}, nil, win, compare, nil, scope); err != nil {
		return nil, err
	}
	ttf := KPITile{Key: KPITimeToFix, Metric: "fix.time_to_fix", State: dur.State, Reason: dur.Reason, Unit: UnitHours, Polarity: dashboard.PolarityLowerBetter}
	if dv := dur.Duration; dv != nil {
		n := dv.N
		ttf.N = &n
		ttf.Value = dv.MedianHours
		ttf.Previous = dv.PreviousMedianHours
	}
	out.Tiles = append(out.Tiles, ttf)

	cov := &WidgetValue{State: StateReady}
	if err := s.discoveryCoverage(ctx, cov, nil, false, scope); err != nil {
		return nil, err
	}
	ct := KPITile{Key: KPICoverage, Metric: metricDiscoveryCoverage, State: cov.State, Reason: cov.Reason, Unit: UnitPercent,
		Polarity: dashboard.PolarityHigherBetter, Drill: cov.Drill}
	if cov.Ratio != nil {
		ct.Value = cov.Ratio.ValuePct
	}
	out.Tiles = append(out.Tiles, ct)

	// No finding in scope: the findings tiles have nothing to count (a "0"
	// would read as all clear); the coverage tile is read from the ledger.
	has, err := s.hasFindings(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !has {
		for i := range out.Tiles {
			if out.Tiles[i].Key != KPICoverage {
				t := out.Tiles[i]
				out.Tiles[i] = KPITile{Key: t.Key, Metric: t.Metric, State: StateNotMeasured, Reason: ReasonNoFindings,
					Unit: t.Unit, Polarity: t.Polarity}
			}
		}
	}
	return out, nil
}

// kpisMetric fills the exposure.kpis widget.
func (s *Service) kpisMetric(ctx context.Context, v *WidgetValue, win Window, compare bool, scope dashboard.ReadScope) error {
	k, err := s.kpis(ctx, scope, win, compare)
	if err != nil {
		return err
	}
	v.KPIs = k
	return nil
}
