package ctemcycle

// CTEM-program maturity, made TRANSPARENT.
//
// A single "maturity score" is close to useless if an operator cannot
// see WHY it is what it is. So instead of an opaque number we return a
// breakdown: each component carries its raw metric value, a normalized
// 0–100 sub-score, its weight, and the resulting contribution. The
// composite is just the sum of contributions — reproducible by hand.
//
// Composite formula (weights are package consts below, and sum to 1.0
// so the composite stays on a 0–100 scale):
//
//	maturity = 0.30 * validation_coverage_score   // are fixes proven?
//	         + 0.25 * resolution_throughput_score  // resolved / opened
//	         + 0.20 * mttr_trend_score             // is MTTR improving?
//	         + 0.15 * priority_stability_score      // low P-class churn
//	         + 0.10 * scope_stability_score         // low scope drift
//
// Only the six metrics defined in review.go feed the score. CTEM stage
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
	WeightScopeStability       = 0.10
)

// MaturityComponent is one transparent, weighted input to the composite.
type MaturityComponent struct {
	Name         string  `json:"name"`
	RawValue     float64 `json:"raw_value"`    // underlying metric value
	Score        float64 `json:"score"`        // normalized 0–100
	Weight       float64 `json:"weight"`       // 0..1; all weights sum to 1.0
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

	// 1. Validation coverage — already a percentage.
	covScore := clamp(coverage, 0, 100)
	out.add(MaturityComponent{
		Name: "validation_coverage", RawValue: coverage, Score: covScore,
		Weight: WeightValidationCoverage,
		Detail: "share of closed findings with validation evidence (%)",
	})

	// 2. Resolution throughput — resolved / opened, clamped to 100%.
	ratio := 0.0
	switch {
	case opened > 0:
		ratio = resolved / opened
	case resolved > 0:
		ratio = 1 // resolved backlog with nothing newly opened → full credit
	}
	thrScore := clamp(ratio*100, 0, 100)
	out.add(MaturityComponent{
		Name: "resolution_throughput", RawValue: ratio, Score: thrScore,
		Weight: WeightResolutionThroughput,
		Detail: "findings_resolved / findings_opened this cycle",
	})

	// 3. MTTR trend — improving (lower) beats a neutral 50 baseline.
	mttrScore := 50.0
	mttrDetail := "no prior cycle; neutral baseline"
	if prev != nil {
		p := prev.Value(MetricMTTRHours)
		if p > 0 {
			improvement := (p - mttr) / p // >0 means MTTR fell
			mttrScore = clamp(50+50*improvement, 0, 100)
			mttrDetail = "MTTR direction vs previous cycle (lower is better)"
		}
	}
	out.add(MaturityComponent{
		Name: "mttr_trend", RawValue: mttr, Score: mttrScore,
		Weight: WeightMTTRTrend, Detail: mttrDetail,
	})

	// 4. Priority stability — low P-class churn relative to work opened.
	stabScore := 100 * (1 - clamp(churn/nonZero(opened), 0, 1))
	out.add(MaturityComponent{
		Name: "priority_stability", RawValue: churn, Score: stabScore,
		Weight: WeightPriorityStability,
		Detail: "1 − min(1, p_class_churn / findings_opened)",
	})

	// 5. Scope stability — low scope drift relative to work opened.
	// NOTE: scope_drift_size is currently always 0 (the scope-change
	// event emitter is deferred), so this component reads as fully
	// stable until that source is wired.
	scopeScore := 100 * (1 - clamp(drift/nonZero(opened), 0, 1))
	out.add(MaturityComponent{
		Name: "scope_stability", RawValue: drift, Score: scopeScore,
		Weight: WeightScopeStability,
		Detail: "1 − min(1, scope_drift_size / findings_opened) (drift source deferred)",
	})

	out.StageCoverage = stageCoverage(latest)
	return out
}

// add appends a component after filling its contribution and rolling it
// into the composite score.
func (b *MaturityBreakdown) add(c MaturityComponent) {
	c.Contribution = c.Score * c.Weight
	b.Components = append(b.Components, c)
	b.Score += c.Contribution
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
