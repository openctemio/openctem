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

	// Weights must sum to 1.0 so the composite stays on a 0–100 scale.
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

	// Per-component sub-scores.
	approx(t, "validation_coverage.score", byName["validation_coverage"].Score, 75)
	approx(t, "resolution_throughput.score", byName["resolution_throughput"].Score, 80) // 8/10
	approx(t, "mttr_trend.score", byName["mttr_trend"].Score, 75)                       // 20→10 = 50% better
	approx(t, "priority_stability.score", byName["priority_stability"].Score, 80)       // 1-2/10
	approx(t, "scope_stability.score", byName["scope_stability"].Score, 100)            // drift 0

	// Composite = sum of contributions.
	want := 75*WeightValidationCoverage + 80*WeightResolutionThroughput +
		75*WeightMTTRTrend + 80*WeightPriorityStability + 100*WeightScopeStability
	approx(t, "score", b.Score, want)

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

func TestComputeMaturity_NoPriorCycleNeutralMTTR(t *testing.T) {
	cycles := []CycleMetrics{{
		CycleID: shared.NewID(), Name: "only", ClosedAt: time.Now().UTC(),
		Metrics: map[string]float64{MetricMTTRHours: 42, MetricFindingsOpened: 1},
	}}
	b := ComputeMaturity(cycles)
	for _, c := range b.Components {
		if c.Name == "mttr_trend" {
			approx(t, "mttr_trend.score(neutral)", c.Score, 50)
			return
		}
	}
	t.Fatal("mttr_trend component missing")
}
