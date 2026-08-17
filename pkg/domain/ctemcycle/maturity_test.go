package ctemcycle

import (
	"math"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.01 {
		t.Errorf("%s = %.4f, want %.4f", name, got, want)
	}
}

func TestComputeMaturity_TransparentBreakdown(t *testing.T) {
	base := time.Now().UTC()
	cycles := []CycleMetrics{
		{ // previous cycle: only MTTR matters for the trend component
			CycleID: shared.NewID(), Name: "Q1", ClosedAt: base.Add(-90 * 24 * time.Hour),
			Metrics: map[string]float64{MetricMTTRHours: 20},
		},
		{ // latest cycle drives the level components
			CycleID: shared.NewID(), Name: "Q2", ClosedAt: base,
			Metrics: map[string]float64{
				MetricFindingsOpened:     10,
				MetricFindingsResolved:   8,
				MetricPClassChurn:        2,
				MetricScopeDriftSize:     0,
				MetricValidationCoverage: 75,
				MetricMTTRHours:          10,
			},
		},
	}

	b := ComputeMaturity(cycles)

	if b.CyclesAnalyzed != 2 {
		t.Fatalf("CyclesAnalyzed = %d, want 2", b.CyclesAnalyzed)
	}
	if len(b.Components) != 5 {
		t.Fatalf("want 5 components, got %d", len(b.Components))
	}

	// Effective (renormalized) weights must sum to 1.0 so the composite stays
	// on a 0–100 scale. scope_stability is excluded (drift source deferred), so
	// the four active components' base weights are renormalized by /0.90.
	var weightSum float64
	byName := make(map[string]MaturityComponent, len(b.Components))
	for _, c := range b.Components {
		weightSum += c.Weight
		byName[c.Name] = c
		// Contribution must equal score*weight — the whole point of the
		// transparent breakdown.
		approx(t, c.Name+".contribution", c.Contribution, c.Score*c.Weight)
	}
	approx(t, "weightSum", weightSum, 1.0)

	// Active components carry base/0.90; scope_stability is excluded (weight 0).
	const norm = 0.90
	approx(t, "validation_coverage.weight", byName["validation_coverage"].Weight, WeightValidationCoverage/norm)
	approx(t, "resolution_throughput.weight", byName["resolution_throughput"].Weight, WeightResolutionThroughput/norm)
	approx(t, "mttr_trend.weight", byName["mttr_trend"].Weight, WeightMTTRTrend/norm)
	approx(t, "priority_stability.weight", byName["priority_stability"].Weight, WeightPriorityStability/norm)
	approx(t, "scope_stability.weight", byName["scope_stability"].Weight, 0)

	// Per-component sub-scores.
	approx(t, "validation_coverage.score", byName["validation_coverage"].Score, 75)
	approx(t, "resolution_throughput.score", byName["resolution_throughput"].Score, 80) // 8/10
	approx(t, "mttr_trend.score", byName["mttr_trend"].Score, 75)                       // 20→10 = 50% better
	approx(t, "priority_stability.score", byName["priority_stability"].Score, 80)       // 1-2/10
	approx(t, "scope_stability.score", byName["scope_stability"].Score, 100)            // drift 0 (reported, weight 0)

	// Composite = sum of contributions, over renormalized weights.
	want := (75*WeightValidationCoverage + 80*WeightResolutionThroughput +
		75*WeightMTTRTrend + 80*WeightPriorityStability) / norm
	approx(t, "score", b.Score, want)
	// A healthy tenant should still score high.
	if b.Score < 70 {
		t.Errorf("healthy tenant score = %.2f, want >= 70", b.Score)
	}

	// Stage coverage from the latest cycle: all five exercised.
	if b.StageCoverage.CoveredCount != 5 {
		t.Errorf("CoveredCount = %d, want 5 (%#v)", b.StageCoverage.CoveredCount, b.StageCoverage)
	}
}

func TestComputeMaturity_Empty(t *testing.T) {
	b := ComputeMaturity(nil)
	if b.Score != 0 || b.CyclesAnalyzed != 0 || len(b.Components) != 0 {
		t.Fatalf("empty maturity should be zero-valued, got %#v", b)
	}
}

func TestComputeMaturity_NoPriorCycleMTTRExcluded(t *testing.T) {
	cycles := []CycleMetrics{{
		CycleID: shared.NewID(), Name: "only", ClosedAt: time.Now().UTC(),
		Metrics: map[string]float64{MetricMTTRHours: 42, MetricFindingsOpened: 1},
	}}
	b := ComputeMaturity(cycles)
	for _, c := range b.Components {
		if c.Name == "mttr_trend" {
			// No prior cycle → mttr_trend carries no measured direction, so it
			// is excluded from the composite (weight 0), not scored a hollow 50.
			approx(t, "mttr_trend.weight(no prior)", c.Weight, 0)
			approx(t, "mttr_trend.contribution(no prior)", c.Contribution, 0)
			return
		}
	}
	t.Fatal("mttr_trend component missing")
}

// TestComputeMaturity_TrivialCycleNearZero pins the fix: a tenant with a single
// trivial closed cycle (nothing opened, nothing resolved, no coverage, no prior)
// used to score ~35 because scope_stability handed a fixed +10 and the hollow
// neutral-MTTR/priority defaults padded the rest. It must now score near 0.
func TestComputeMaturity_TrivialCycleNearZero(t *testing.T) {
	cycles := []CycleMetrics{{
		CycleID: shared.NewID(), Name: "trivial", ClosedAt: time.Now().UTC(),
		Metrics: map[string]float64{
			MetricFindingsOpened:     0,
			MetricFindingsResolved:   0,
			MetricPClassChurn:        0,
			MetricScopeDriftSize:     0,
			MetricValidationCoverage: 0,
			MetricMTTRHours:          0,
		},
	}}
	b := ComputeMaturity(cycles)

	if b.Score >= 20 {
		t.Fatalf("trivial-cycle score = %.2f, want < 20 (near 0)", b.Score)
	}

	// Only measured components may carry weight; unscorable ones are excluded.
	byName := make(map[string]MaturityComponent, len(b.Components))
	var weightSum float64
	for _, c := range b.Components {
		byName[c.Name] = c
		weightSum += c.Weight
		approx(t, c.Name+".contribution", c.Contribution, c.Score*c.Weight)
	}
	// scope_stability (deferred), mttr_trend (no prior) and priority_stability
	// (nothing opened) must all be excluded.
	approx(t, "scope_stability.weight", byName["scope_stability"].Weight, 0)
	approx(t, "mttr_trend.weight", byName["mttr_trend"].Weight, 0)
	approx(t, "priority_stability.weight", byName["priority_stability"].Weight, 0)
	// The two remaining active components still renormalize to sum 1.0.
	approx(t, "weightSum", weightSum, 1.0)
	// Both active components score 0 here → composite is exactly 0.
	approx(t, "score", b.Score, 0)
}
