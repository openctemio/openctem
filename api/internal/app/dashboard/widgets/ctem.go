package widgets

// The CTEM metrics (docs/architecture/dashboards.md, "CTEM metrics"): the
// five-stage loop, crown jewels with open P0/P1 findings, and the attack
// paths that reach crown jewels. Every figure is counted for the read's
// scope (ReadScope) and carries the list it counts; a stage without a
// denominator is not measured, never 0.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Stage keys, in loop order.
const (
	StageScoping    = "scoping"
	StageDiscovery  = "discovery"
	StagePrioritize = "prioritize"
	StageValidate   = "validate"
	StageMobilize   = "mobilize"
)

// Stage states.
const (
	StageGood        = "good"
	StageWarn        = "warn"
	StageCrit        = "crit"
	StageNotMeasured = "not_measured"
)

// Stage reasons and flags (machine codes the web translates).
const (
	ReasonNoTrackedAssets   = "no_tracked_assets"
	ReasonNothingToValidate = "nothing_to_validate"
	// ReasonNoCrownJewels: no crown jewel is designated in the scope, so
	// "none exposed" or "none reachable" would be a false all-clear.
	ReasonNoCrownJewels = "no_crown_jewels"
	// ReasonNoRelationshipData: the tenant has no asset relationships, so
	// "no crown jewel reachable" is not a measurement.
	ReasonNoRelationshipData = "no_relationship_data"
	FlagDesignate            = "designate_crown_jewels"
	FlagExploitableNow       = "exploitable_now"
	FlagNoneRunYet           = "none_run_yet"
	FlagOnTrack              = "on_track"
)

// Unit of a stage figure.
const (
	UnitCount   = "count"
	UnitPercent = "percent"
)

// validateWindow is the window of the retests a Validate stage counts.
const validateWindow = 30 * 24 * time.Hour

// crownJewelPriorities are the priority classes crown_jewels.exposed and
// the Scoping stage count by default.
var crownJewelPriorities = []string{"P0", "P1"}

// StageDetail is a stage's second figure (for example the breached
// findings under the share within SLA), with the list it counts.
type StageDetail struct {
	Key   string `json:"key" enums:"exposed,uncovered,kev,retests,breached"`
	Value int64  `json:"value"`
	Drill string `json:"drill,omitempty"`
}

// StageValue is one CTEM stage. Value is nil when the stage is not
// measured (Reason says why).
type StageValue struct {
	Key    string       `json:"key" enums:"scoping,discovery,prioritize,validate,mobilize"`
	State  string       `json:"state" enums:"good,warn,crit,not_measured"`
	Reason string       `json:"reason,omitempty"`
	Value  *float64     `json:"value"`
	Unit   string       `json:"unit" enums:"count,percent"`
	Drill  string       `json:"drill,omitempty"`
	Flag   string       `json:"flag,omitempty"`
	Detail *StageDetail `json:"detail,omitempty"`
}

// StagesValue is the CTEM loop. Focus is the index of the stage with the
// largest gap (the first off-track stage, else the first that needs
// attention); nil when every measured stage is on track.
type StagesValue struct {
	Stages []StageValue `json:"stages"`
	Focus  *int         `json:"focus"`
}

// PathRow is one reachable crown jewel.
type PathRow struct {
	AssetID       string  `json:"asset_id"`
	Name          string  `json:"name"`
	AssetType     string  `json:"asset_type"`
	Criticality   string  `json:"criticality"`
	ReachableFrom int     `json:"reachable_from"`
	EntryPoint    bool    `json:"entry_point"`
	Depth         int     `json:"depth"`
	Score         float64 `json:"score"`
}

// PathsValue is the attack paths that reach crown jewels in scope.
type PathsValue struct {
	// Reachable crown jewels in scope; Designated crown jewels in scope.
	Reachable  int64     `json:"reachable"`
	Designated int64     `json:"designated"`
	Rows       []PathRow `json:"rows"`
}

// AttackPathReader returns the reachable crown jewels of the whole tenant
// graph, in path-score order, and whether the tenant has relationship data.
// The widget keeps the ones in the read's scope.
type AttackPathReader interface {
	ReachableCrownJewels(ctx context.Context, tenantID shared.ID) ([]attack.CrownJewelPath, bool, error)
}

// SetAttackPaths wires the attack-path reader. Unwired, the attack-path
// metric reports not measured.
func (s *Service) SetAttackPaths(r AttackPathReader) { s.paths = r }

// Drill lists of the CTEM metrics. Each opens exactly what its figure counts.
const (
	drillCrownJewels = "/assets?is_crown_jewel=true&program_assets=exclude"
	drillUncovered   = "/assets?coverage=uncovered&program_assets=exclude"
	drillValidation  = "/validation"
	drillAttackPaths = "/attack-paths"
)

// drillCrownJewelsExposed is the open findings of the priorities on crown
// jewels, grouped by asset: the number of groups is the figure.
func drillCrownJewelsExposed(priorities []string) string {
	q := url.Values{}
	q.Set("state", "open")
	q.Set("priority_class", strings.Join(priorities, ","))
	q.Set("asset_crown_jewel", "true")
	q.Set("group", "asset_id")
	return "/findings?" + strings.ReplaceAll(q.Encode(), "%2C", ",")
}

func (s *Service) crownJewelsExposed(ctx context.Context, v *WidgetValue, f dashboard.WidgetFilter, scope dashboard.ReadScope) error {
	pr := f.PriorityClass
	if len(pr) == 0 {
		pr = crownJewelPriorities
	}
	c, err := s.facts.CrownJewels(ctx, scope, pr)
	if err != nil {
		return err
	}
	v.Drill = drillCrownJewelsExposed(pr)
	if c.Designated == 0 {
		// Nothing designated: 0 exposed would read as an all-clear.
		v.State, v.Reason = StateNotMeasured, ReasonNoCrownJewels
		return nil
	}
	v.Scalar = &ScalarValue{Value: c.Exposed}
	v.TargetMet = targetMet(v.Target, float64(c.Exposed))
	return nil
}

// discoveryCoverage is the coverage.discovery ratio: ledger-tracked assets
// in scope with a successful run in the coverage window, over all tracked
// assets in scope (the same read as the loop's Discovery stage). It opens the
// uncovered assets, which are what to act on.
func (s *Service) discoveryCoverage(ctx context.Context, v *WidgetValue, target *dashboard.WidgetTarget, compare bool, scope dashboard.ReadScope) error {
	disc, err := s.facts.Discovery(ctx, scope, s.now().Add(-asset.CoverageWindow))
	if err != nil {
		return err
	}
	v.Ratio = &RatioValue{Num: disc.Covered, Den: disc.Tracked}
	v.Drill = drillUncovered
	if disc.Tracked == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonNoTrackedAssets
		return nil
	}
	pct := round1(float64(disc.Covered) * 100 / float64(disc.Tracked))
	v.Ratio.ValuePct = &pct
	v.TargetMet = targetMet(target, pct)
	if compare {
		v.PreviousReason = ReasonNoHistoryForBy
	}
	return nil
}

//nolint:cyclop // one block per stage
func (s *Service) ctemLoop(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	now := s.now()
	cj, err := s.facts.CrownJewels(ctx, scope, crownJewelPriorities)
	if err != nil {
		return err
	}
	disc, err := s.facts.Discovery(ctx, scope, now.Add(-asset.CoverageWindow))
	if err != nil {
		return err
	}
	p0, err := s.openCount(ctx, scope, dashboard.WidgetFilter{PriorityClass: []string{"P0"}})
	if err != nil {
		return err
	}
	kevTrue := true
	kev, err := s.openCount(ctx, scope, dashboard.WidgetFilter{KEV: &kevTrue})
	if err != nil {
		return err
	}
	val, err := s.facts.Validation(ctx, scope, now.Add(-validateWindow))
	if err != nil {
		return err
	}
	within, den, err := s.facts.SLAWithin(ctx, scope, dashboard.WidgetFilter{})
	if err != nil {
		return err
	}
	breachedF := dashboard.WidgetFilter{SLAState: []string{"breached"}}
	breached, err := s.openCount(ctx, scope, breachedF)
	if err != nil {
		return err
	}

	stages := make([]StageValue, 0, 5)

	// Scoping: crown jewels designated, and how many carry open P0/P1.
	scoping := StageValue{Key: StageScoping, Unit: UnitCount, Value: f64(cj.Designated), State: StageGood, Drill: drillCrownJewels,
		Detail: &StageDetail{Key: "exposed", Value: cj.Exposed, Drill: drillCrownJewelsExposed(crownJewelPriorities)}}
	if cj.Designated == 0 {
		scoping.State, scoping.Flag = StageWarn, FlagDesignate
	}
	stages = append(stages, scoping)

	// Discovery: share of ledger-tracked assets with a recent successful run.
	discovery := StageValue{Key: StageDiscovery, Unit: UnitPercent, Drill: drillUncovered}
	if disc.Tracked == 0 {
		discovery.State, discovery.Reason = StageNotMeasured, ReasonNoTrackedAssets
	} else {
		pct := round1(float64(disc.Covered) * 100 / float64(disc.Tracked))
		discovery.Value, discovery.State = &pct, coverageState(pct)
		discovery.Detail = &StageDetail{Key: "uncovered", Value: disc.Tracked - disc.Covered, Drill: drillUncovered}
	}
	stages = append(stages, discovery)

	// Prioritize: open P0, and open KEV findings.
	p0Drill := drillHref(dashboard.WidgetFilter{PriorityClass: []string{"P0"}})
	prioritize := StageValue{Key: StagePrioritize, Unit: UnitCount, Value: f64(p0), State: openCountState(p0), Drill: p0Drill,
		Detail: &StageDetail{Key: "kev", Value: kev, Drill: drillHref(dashboard.WidgetFilter{KEV: &kevTrue})}}
	if p0 > 0 {
		prioritize.Flag = FlagExploitableNow
	}
	stages = append(stages, prioritize)

	// Validate: share of open findings with validation evidence; retests
	// completed in the window.
	validate := StageValue{Key: StageValidate, Unit: UnitPercent, Drill: drillValidation,
		Detail: &StageDetail{Key: "retests", Value: val.RetestsRun}}
	if val.Open == 0 {
		validate.State, validate.Reason = StageNotMeasured, ReasonNothingToValidate
	} else {
		pct := round1(float64(val.Validated) * 100 / float64(val.Open))
		validate.Value, validate.State = &pct, coverageState(pct)
		if val.Validated == 0 {
			validate.Flag = FlagNoneRunYet
		}
	}
	stages = append(stages, validate)

	// Mobilize: share of open findings with an SLA that is not breached.
	breachedDrill := drillHref(breachedF)
	mobilize := StageValue{Key: StageMobilize, Unit: UnitPercent, Drill: breachedDrill,
		Detail: &StageDetail{Key: "breached", Value: breached, Drill: breachedDrill}}
	if den == 0 {
		mobilize.State, mobilize.Reason = StageNotMeasured, ReasonNoDenominator
	} else {
		pct := round1(float64(within) * 100 / float64(den))
		mobilize.Value = &pct
		switch {
		case pct >= 90:
			mobilize.State, mobilize.Flag = StageGood, FlagOnTrack
		case pct >= 70:
			mobilize.State = StageWarn
		default:
			mobilize.State = StageCrit
		}
	}
	stages = append(stages, mobilize)

	v.Stages = &StagesValue{Stages: stages, Focus: focusOf(stages)}
	return nil
}

func (s *Service) attackPaths(ctx context.Context, v *WidgetValue, limit int, scope dashboard.ReadScope) error {
	if s.paths == nil {
		v.State, v.Reason = StateNotMeasured, ReasonFailed
		return nil
	}
	cj, err := s.facts.CrownJewels(ctx, scope, nil)
	if err != nil {
		return err
	}
	v.Drill = drillAttackPaths
	if cj.Designated == 0 {
		// No crown jewel in scope: "none reachable" would be a false all-clear.
		v.State, v.Reason = StateNotMeasured, ReasonNoCrownJewels
		return nil
	}
	all, hasGraph, err := s.paths.ReachableCrownJewels(ctx, scope.TenantID)
	if err != nil {
		return err
	}
	ids := make([]shared.ID, 0, len(all))
	for _, p := range all {
		ids = append(ids, p.AssetID)
	}
	// Only crown jewels the reader may see, that are not deleted or
	// program-only; nothing else of the graph leaves the server.
	visible, err := s.facts.VisibleAssets(ctx, scope, ids)
	if err != nil {
		return err
	}
	out := &PathsValue{Designated: cj.Designated, Rows: []PathRow{}}
	for _, p := range all {
		if !visible[p.AssetID] {
			continue
		}
		out.Reachable++
		if len(out.Rows) < limit {
			out.Rows = append(out.Rows, PathRow{AssetID: p.AssetID.String(), Name: p.Name, AssetType: p.AssetType, Criticality: p.Criticality,
				ReachableFrom: p.ReachableFrom, EntryPoint: p.IsEntryPoint, Depth: p.Depth, Score: round1(p.PathScore)})
		}
	}
	if out.Reachable == 0 && !hasGraph {
		// No relationships known: unreachable is unknown, not measured 0.
		v.State, v.Reason = StateNotMeasured, ReasonNoRelationshipData
		return nil
	}
	v.Paths = out
	return nil
}

func (s *Service) openCount(ctx context.Context, scope dashboard.ReadScope, f dashboard.WidgetFilter) (int64, error) {
	rows, err := s.facts.CountOpen(ctx, scope, f, nil)
	if err != nil {
		return 0, fmt.Errorf("count open: %w", err)
	}
	var n int64
	for _, r := range rows {
		n += r.Count
	}
	return n, nil
}

// coverageState is the state of a coverage share (discovery, validation).
func coverageState(pct float64) string {
	switch {
	case pct >= 80:
		return StageGood
	case pct >= 40:
		return StageWarn
	}
	return StageCrit
}

// openCountState is the state of an open count where 0 is good.
func openCountState(n int64) string {
	switch {
	case n >= 5:
		return StageCrit
	case n >= 1:
		return StageWarn
	}
	return StageGood
}

// focusOf picks the stage with the largest gap: the first off track, else
// the first that needs attention.
func focusOf(stages []StageValue) *int {
	for _, want := range []string{StageCrit, StageWarn} {
		for i, st := range stages {
			if st.State == want {
				i := i
				return &i
			}
		}
	}
	return nil
}

func f64(n int64) *float64 {
	v := float64(n)
	return &v
}
