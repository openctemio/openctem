package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
)

// These tests cover the business-aligned criticality seam added to the risk
// scoring engine: CalculateScoreWithCriticality scores the criticality component
// from an EFFECTIVE criticality resolved by the app layer, instead of the asset's
// own. Floor semantics (effective only RAISES) are enforced by
// asset.EffectiveCriticality, exercised at the boundary below.

// TestCalculateScoreWithCriticality_EmptyMatchesOwn proves an empty effective
// criticality is byte-identical to the pre-change CalculateScore — the whole
// point of the nil-safe fallback.
func TestCalculateScoreWithCriticality_EmptyMatchesOwn(t *testing.T) {
	engine := asset.NewRiskScoringEngine(asset.LegacyRiskScoringConfig())
	for _, own := range []asset.Criticality{
		asset.CriticalityNone, asset.CriticalityLow, asset.CriticalityMedium,
		asset.CriticalityHigh, asset.CriticalityCritical,
	} {
		a := makeTestAsset(t, asset.ExposurePrivate, own, 2)
		want := engine.CalculateScore(a)
		got := engine.CalculateScoreWithCriticality(a, "")
		if got != want {
			t.Errorf("own=%s: empty effective should match CalculateScore, got %d want %d", own, got, want)
		}
		// Passing the asset's own criticality explicitly must also be identical.
		if same := engine.CalculateScoreWithCriticality(a, own); same != want {
			t.Errorf("own=%s: explicit own effective should match CalculateScore, got %d want %d", own, same, want)
		}
	}
}

// TestCalculateScoreWithCriticality_HigherEffectiveRaisesScore proves that
// raising the effective criticality (as a critical BU/service would) raises the
// score for an otherwise-identical asset.
func TestCalculateScoreWithCriticality_HigherEffectiveRaisesScore(t *testing.T) {
	engine := asset.NewRiskScoringEngine(asset.LegacyRiskScoringConfig())

	// Same private, low-criticality asset scored two ways.
	a := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityLow, 1)

	own := engine.CalculateScoreWithCriticality(a, asset.CriticalityLow)
	raised := engine.CalculateScoreWithCriticality(a, asset.CriticalityCritical)

	if raised <= own {
		t.Fatalf("critical effective criticality must raise the score: own=%d raised=%d", own, raised)
	}
}

// TestEffectiveCriticality_FloorOnly proves the resolver never lowers an asset's
// own criticality: a lower BU/service leaves it unchanged, a higher one raises
// it, and the higher of BU vs service wins. This is the guarantee the scoring
// path relies on to be "floor only, never lowers".
func TestEffectiveCriticality_FloorOnly(t *testing.T) {
	cases := []struct {
		name string
		own  asset.Criticality
		bctx asset.BusinessContext
		want asset.Criticality
	}{
		{
			name: "lower BU never lowers a high asset",
			own:  asset.CriticalityHigh,
			bctx: asset.BusinessContext{BusinessUnitCriticality: asset.CriticalityLow, BusinessUnitName: "IT"},
			want: asset.CriticalityHigh,
		},
		{
			name: "critical BU raises a low asset",
			own:  asset.CriticalityLow,
			bctx: asset.BusinessContext{BusinessUnitCriticality: asset.CriticalityCritical, BusinessUnitName: "Payments"},
			want: asset.CriticalityCritical,
		},
		{
			name: "critical service raises a medium asset",
			own:  asset.CriticalityMedium,
			bctx: asset.BusinessContext{BusinessServiceCriticality: asset.CriticalityCritical, BusinessServiceName: "Checkout"},
			want: asset.CriticalityCritical,
		},
		{
			name: "no context leaves own untouched",
			own:  asset.CriticalityMedium,
			bctx: asset.BusinessContext{},
			want: asset.CriticalityMedium,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := asset.EffectiveCriticality(tc.own, tc.bctx)
			if got != tc.want {
				t.Fatalf("EffectiveCriticality(%s, %+v) = %s, want %s", tc.own, tc.bctx, got, tc.want)
			}
		})
	}
}
