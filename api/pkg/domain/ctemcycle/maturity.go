package ctemcycle

// CTEM-program maturity, made TRANSPARENT.
//
// A single "maturity score" is close to useless if an operator cannot
// see WHY it is what it is. So instead of an opaque number we return a
// breakdown: each component carries its raw metric value, a normalized
// 0–100 sub-score, its (effective) weight, and the resulting
// contribution. The composite is just the sum of contributions —
// reproducible by hand.
//
// The score must reflect only MEASURED signal. Each component declares a
// base weight, but a component is folded in only when it actually has an
// input to measure; the ACTIVE base weights are then renormalized to sum
// to 1.0 so the composite stays on a 0–100 scale. A component that is
// currently unscorable is still REPORTED (for transparency) but with an
// effective weight of 0, so it contributes nothing:
//
//	base weights   validation_coverage   0.30  // are fixes proven?
//	               resolution_throughput 0.25  // resolved / opened
//	               mttr_trend            0.20  // is MTTR improving?
//	               priority_stability    0.15  // low P-class churn
//	               scope_stability       0.10  // low scope drift
//
// When every component is active the effective weights are base/0.90 —
// e.g. a fully-scored tenant weights validation_coverage 0.30/0.90.
// scope_stability's drift source is deferred (always 0), so it carries
// no measured signal and is permanently excluded from Score until that
// source is wired — otherwise it would hand every tenant a fixed +10.
// mttr_trend is excluded when there is no prior cycle to compare against,
// and priority_stability is excluded when no findings were opened (there
// is then no prioritization work to be "stable" about) — either would
// otherwise inflate an inactive tenant toward a hollow ~35.
//
// Only the metrics defined in review.go feed the score. CTEM stage
// coverage is reported ALONGSIDE (StageCoverage) as an explainability
// aid but is deliberately NOT folded into the weighted number, so the
// score means exactly one thing: the quality of the measured program.
//
// Weights are intentionally simple, visible and tunable — change a
// const, the breakdown re-explains itself.
const (
	WeightValidationCoverage   = 0.30
	WeightResolutionThroughput = 0.25
	WeightMTTRTrend            = 0.20
	WeightPriorityStability    = 0.15
	WeightScopeStability       = 0.10 // reported only; excluded from Score (drift source deferred)
)

// MaturityComponent is one transparent, weighted input to the composite.
type MaturityComponent struct {
	Name         string  `json:"name"`
	RawValue     float64 `json:"raw_value"`    // underlying metric value
	Score        float64 `json:"score"`        // normalized 0–100
	Weight       float64 `json:"weight"`       // effective 0..1; active weights sum to 1.0
	Contribution float64 `json:"contribution"` // score * weight
	Detail       string  `json:"detail"`       // how the sub-score was derived
}

// CTEMStageCoverage records which of the five CTEM stages the latest
// closed cycle exercised, derived from the six metrics. Reported for
// transparency; not part of the weighted score.
type CTEMStageCoverage struct {
	Scoping        bool `json:"scoping"`        // a scope was frozen at activation
	Discovery      bool `json:"discovery"`      // findings were opened
	Prioritization bool `json:"prioritization"` // priority classes were applied/changed
	Validation     bool `json:"validation"`     // closed findings carried evidence
	Mobilization   bool `json:"mobilization"`   // findings were resolved
	CoveredCount   int  `json:"covered_count"`  // 0..5
}

// MaturityBreakdown is the full, explainable maturity result.
type MaturityBreakdown struct {
	Score          float64             `json:"score"` // sum of contributions, 0–100
	Components     []MaturityComponent `json:"components"`
	StageCoverage  CTEMStageCoverage   `json:"ctem_stage_coverage"`
	CyclesAnalyzed int                 `json:"cycles_analyzed"`
}

// ComputeMaturity builds the transparent breakdown from a tenant's
// closed cycles, ordered by closed_at ASCENDING. Level components read
// the latest cycle; trend components compare the latest to the prior
// cycle. Returns a zero-score breakdown when no cycles are given.
func ComputeMaturity(cycles []CycleMetrics) MaturityBreakdown {
	out := MaturityBreakdown{CyclesAnalyzed: len(cycles)}
	if len(cycles) == 0 {
		return out
	}
	latest := cycles[len(cycles)-1]
	var prev *CycleMetrics
	if len(cycles) >= 2 {
		prev = &cycles[len(cycles)-2]
	}

	opened := latest.Value(MetricFindingsOpened)
	resolved := latest.Value(MetricFindingsResolved)
	churn := latest.Value(MetricPClassChurn)
	drift := latest.Value(MetricScopeDriftSize)
	coverage := latest.Value(MetricValidationCoverage)
	mttr := latest.Value(MetricMTTRHours)

	// Each component declares a base weight and whether it is currently
	// scorable. Inactive components are reported but weighted 0; the active
	// base weights are renormalized to sum to 1.0 in finalize.
	var comps []weighted

	// 1. Validation coverage — already a percentage; always scorable.
	comps = append(comps, weighted{active: true, c: MaturityComponent{
		Name: "validation_coverage", RawValue: coverage, Score: clamp(coverage, 0, 100),
		Weight: WeightValidationCoverage,
		Detail: "share of closed findings with validation evidence (%)",
	}})

	// 2. Resolution throughput — resolved / opened, clamped to 100%; always
	// scorable (an inactive cycle genuinely resolved nothing → 0).
	ratio := 0.0
	switch {
	case opened > 0:
		ratio = resolved / opened
	case resolved > 0:
		ratio = 1 // resolved backlog with nothing newly opened → full credit
	}
	comps = append(comps, weighted{active: true, c: MaturityComponent{
		Name: "resolution_throughput", RawValue: ratio, Score: clamp(ratio*100, 0, 100),
		Weight: WeightResolutionThroughput,
		Detail: "findings_resolved / findings_opened this cycle",
	}})

	// 3. MTTR trend — only scorable with a prior cycle to compare against.
	// Without one there is no direction to measure, so it is excluded rather
	// than reading a hollow neutral 50.
	mttrScore := 0.0
	mttrDetail := "no prior cycle; unscored (excluded until a prior cycle exists)"
	mttrActive := false
	if prev != nil {
		if p := prev.Value(MetricMTTRHours); p > 0 {
			improvement := (p - mttr) / p // >0 means MTTR fell
			mttrScore = clamp(50+50*improvement, 0, 100)
			mttrDetail = "MTTR direction vs previous cycle (lower is better)"
			mttrActive = true
		}
	}
	comps = append(comps, weighted{active: mttrActive, c: MaturityComponent{
		Name: "mttr_trend", RawValue: mttr, Score: mttrScore,
		Weight: WeightMTTRTrend, Detail: mttrDetail,
	}})

	// 4. Priority stability — low P-class churn relative to work opened. Only
	// scorable when findings were opened; with none there is no prioritization
	// work to be "stable" about, so it is excluded rather than reading a
	// hollow 100.
	priScore := 0.0
	priDetail := "no findings opened; unscored"
	priActive := opened > 0
	if priActive {
		priScore = 100 * (1 - clamp(churn/opened, 0, 1))
		priDetail = "1 − min(1, p_class_churn / findings_opened)"
	}
	comps = append(comps,
		weighted{active: priActive, c: MaturityComponent{
			Name: "priority_stability", RawValue: churn, Score: priScore,
			Weight: WeightPriorityStability, Detail: priDetail,
		}},
		// 5. Scope stability — scope_drift_size is currently always 0 (the
		// scope-change event emitter is deferred), so this component carries no
		// measured signal. Reported for transparency but permanently excluded
		// from Score until that source is wired.
		weighted{active: false, c: MaturityComponent{
			Name: "scope_stability", RawValue: drift,
			Score:  100 * (1 - clamp(drift/nonZero(opened), 0, 1)),
			Weight: WeightScopeStability,
			Detail: "reported only; excluded from score (scope-drift source deferred)",
		}})

	out.finalize(comps)
	out.StageCoverage = stageCoverage(latest)
	return out
}

// weighted pairs a component with whether it currently carries measured
// signal (and so participates in the weighted composite).
type weighted struct {
	c      MaturityComponent
	active bool
}

// finalize renormalizes the ACTIVE base weights to sum to 1.0, fills each
// component's effective weight + contribution, and rolls the active
// contributions into the composite Score. Inactive components are appended
// with weight 0 / contribution 0. If no component is active, Score is 0.
func (b *MaturityBreakdown) finalize(comps []weighted) {
	var activeWeight float64
	for _, w := range comps {
		if w.active {
			activeWeight += w.c.Weight
		}
	}
	for _, w := range comps {
		c := w.c
		if w.active && activeWeight > 0 {
			c.Weight /= activeWeight
			c.Contribution = c.Score * c.Weight
			b.Score += c.Contribution
		} else {
			c.Weight = 0
			c.Contribution = 0
		}
		b.Components = append(b.Components, c)
	}
}

// stageCoverage derives CTEM stage coverage from a cycle's metrics. A
// closed cycle necessarily went through activation (scope frozen), so
// Scoping is always true here.
func stageCoverage(c CycleMetrics) CTEMStageCoverage {
	sc := CTEMStageCoverage{
		Scoping:        true,
		Discovery:      c.Value(MetricFindingsOpened) > 0,
		Prioritization: c.Value(MetricPClassChurn) > 0,
		Validation:     c.Value(MetricValidationCoverage) > 0,
		Mobilization:   c.Value(MetricFindingsResolved) > 0,
	}
	for _, ok := range []bool{sc.Scoping, sc.Discovery, sc.Prioritization, sc.Validation, sc.Mobilization} {
		if ok {
			sc.CoveredCount++
		}
	}
	return sc
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// nonZero returns v, or 1 when v <= 0, so it is safe as a divisor.
func nonZero(v float64) float64 {
	if v <= 0 {
		return 1
	}
	return v
}
