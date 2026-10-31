package widgets

// Levers, the weekly brief and the KPI strip (docs/architecture/dashboards.md,
// "Story widgets"). Every figure here is read through the FactReader with the
// scope the server built for the read, and is stored in the snapshot like
// any other widget.

import (
	"context"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Lever kinds, in tie-break order.
const (
	LeverKEVOpen     = "kev_open"
	LeverSLABreached = "sla_breached"
	LeverOneFix      = "one_fix"
	LeverBlindSpot   = "blind_spot"
)

// UnitHours is a KPI tile's duration unit (UnitCount and UnitPercent are
// the stage units).
const UnitHours = "hours"

const (
	// maxLevers is how many levers a widget shows.
	maxLevers = 3
	// blindSpotBelowPct: the blind spot lever takes the last slot while
	// discovery coverage is under this share.
	blindSpotBelowPct = 90.0
	// drillSuggestions lists the remediation suggestions, ranked by risk
	// points (the top fix is first).
	drillSuggestions = "/remediation/suggestions"
)

// leverOrder is the tie-break order of the lever kinds.
var leverOrder = map[string]int{LeverKEVOpen: 0, LeverSLABreached: 1, LeverOneFix: 2, LeverBlindSpot: 3}

// LeverEffect is a measured figure before and after the lever's list is
// gone: plain arithmetic on the same counts, never an estimate.
type LeverEffect struct {
	// Metric is the catalog metric the figure belongs to.
	Metric string  `json:"metric"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
	Unit   string  `json:"unit" enums:"count,percent"`
}

// Lever is one action that would reduce exposure. The web words it from
// Kind and the numbers; no free text but a fix title is sent.
type Lever struct {
	Kind string `json:"kind" enums:"kev_open,sla_breached,one_fix,blind_spot"`
	// Count is the size of the list the lever acts on (the drill list).
	Count int64 `json:"count"`
	// Assets is the distinct assets of a one-fix lever's findings.
	Assets *int64 `json:"assets,omitempty"`
	// Title is a one-fix lever's fix (a remediation suggestion title).
	Title string `json:"title,omitempty"`
	// Points is the risk points the lever clears (0 for a blind spot).
	Points int64       `json:"points"`
	Effect LeverEffect `json:"effect"`
	Drill  string      `json:"drill,omitempty"`
}

// LeversValue is the levers of a read, best first.
type LeversValue struct {
	Levers []Lever `json:"levers"`
}

func pct(num, den int64) float64 {
	if den <= 0 {
		return 0
	}
	return round1(float64(num) * 100 / float64(den))
}

// sumRows adds up count rows; with a priority class and severity group-by it
// also returns the count of classes P0-P1 and the risk points.
func sumRows(rows []dashboard.CountRow) (n, p01, points int64) {
	for _, r := range rows {
		n += r.Count
		if len(r.Keys) == 2 {
			if r.Keys[0] == "P0" || r.Keys[0] == "P1" {
				p01 += r.Count
			}
			points += dashboard.RiskPoints(r.Keys[0], r.Keys[1], r.Count)
		}
	}
	return n, p01, points
}

var classAndSeverity = []dashboard.Dimension{dashboard.DimPriorityClass, dashboard.DimSeverity}

// levers computes the lever candidates of a scope and picks at most three.
//
//nolint:cyclop // one block per lever kind
func (s *Service) levers(ctx context.Context, scope dashboard.ReadScope) (*LeversValue, error) {
	p01F := dashboard.WidgetFilter{PriorityClass: []string{"P0", "P1"}}
	priorityOpen, err := s.openCount(ctx, scope, p01F)
	if err != nil {
		return nil, err
	}
	var points []Lever

	kevF := dashboard.WidgetFilter{KEV: boolp(true)}
	kevRows, err := s.facts.CountOpen(ctx, scope, kevF, classAndSeverity)
	if err != nil {
		return nil, err
	}
	if n, k, pts := sumRows(kevRows); n > 0 {
		eff := LeverEffect{Metric: "exposure.priority_open", Before: float64(priorityOpen), After: float64(priorityOpen - k), Unit: UnitCount}
		if k == 0 {
			// No KEV finding is P0-P1: the measured change is KEV open itself.
			eff = LeverEffect{Metric: "intel.kev_open", Before: float64(n), After: 0, Unit: UnitCount}
		}
		points = append(points, Lever{Kind: LeverKEVOpen, Count: n, Points: pts, Effect: eff, Drill: drillHref(kevF)})
	}

	breachedF := dashboard.WidgetFilter{SLAState: []string{"breached"}, PriorityClass: []string{"P0", "P1"}}
	brRows, err := s.facts.CountOpen(ctx, scope, breachedF, classAndSeverity)
	if err != nil {
		return nil, err
	}
	if n, _, pts := sumRows(brRows); n > 0 {
		num, den, err := s.facts.SLAWithin(ctx, scope, dashboard.WidgetFilter{})
		if err != nil {
			return nil, err
		}
		if den > 0 {
			after := 100.0
			if den-n > 0 {
				after = pct(num, den-n)
			}
			points = append(points, Lever{Kind: LeverSLABreached, Count: n, Points: pts,
				Effect: LeverEffect{Metric: "sla.within", Before: pct(num, den), After: after, Unit: UnitPercent},
				Drill:  drillHref(breachedF)})
		}
	}

	fix, err := s.facts.TopFix(ctx, scope)
	if err != nil {
		return nil, err
	}
	if fix != nil && fix.Findings > 0 {
		assets := fix.Assets
		points = append(points, Lever{Kind: LeverOneFix, Count: fix.Findings, Assets: &assets, Title: fix.Title, Points: fix.Points,
			Effect: LeverEffect{Metric: "exposure.priority_open", Before: float64(priorityOpen), After: float64(priorityOpen - fix.PriorityOpen), Unit: UnitCount},
			Drill:  drillSuggestions})
	}

	sort.SliceStable(points, func(i, j int) bool {
		if points[i].Points != points[j].Points {
			return points[i].Points > points[j].Points
		}
		return leverOrder[points[i].Kind] < leverOrder[points[j].Kind]
	})

	// Unmeasured is not safe: a blind spot takes the last slot while
	// coverage is under target, whatever the points of the others.
	var blind *Lever
	disc, err := s.facts.Discovery(ctx, scope, s.now().Add(-asset.CoverageWindow))
	if err != nil {
		return nil, err
	}
	if uncovered := disc.Tracked - disc.Covered; disc.Tracked > 0 && uncovered > 0 {
		if cov := pct(disc.Covered, disc.Tracked); cov < blindSpotBelowPct {
			blind = &Lever{Kind: LeverBlindSpot, Count: uncovered,
				Effect: LeverEffect{Metric: metricDiscoveryCoverage, Before: cov, After: 100, Unit: UnitPercent},
				Drill:  drillUncovered}
		}
	}
	room := maxLevers
	if blind != nil {
		room--
	}
	if len(points) > room {
		points = points[:room]
	}
	out := &LeversValue{Levers: points}
	if blind != nil {
		out.Levers = append(out.Levers, *blind)
	}
	return out, nil
}

func boolp(b bool) *bool { return &b }

// leversMetric fills the exposure.levers widget.
func (s *Service) leversMetric(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	lv, err := s.levers(ctx, scope)
	if err != nil {
		return err
	}
	v.Levers = lv
	return nil
}
