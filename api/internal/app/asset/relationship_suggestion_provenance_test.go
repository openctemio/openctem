package asset

import (
	"testing"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
)

// An approved relationship suggestion is an inferred edge a human confirmed.
// Approve/ApproveAll built the edge with NewRelationship (default manual/medium)
// and only set the description — so reviewed inferred edges were persisted as
// 'manual', indistinguishable from hand-drawn ones (all 47 live edges read
// 'manual'). confidenceFromScore maps the suggestion's numeric score to the
// edge confidence so a 0.95 suggestion is not laundered to the medium default.

func TestConfidenceFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  assetdom.RelationshipConfidence
	}{
		{0.95, assetdom.ConfidenceHigh}, // live suggestions sit here
		{0.90, assetdom.ConfidenceHigh},
		{0.80, assetdom.ConfidenceHigh}, // boundary
		{0.79, assetdom.ConfidenceMedium},
		{0.50, assetdom.ConfidenceMedium}, // boundary
		{0.49, assetdom.ConfidenceLow},
		{0.0, assetdom.ConfidenceLow},
	}
	for _, c := range cases {
		if got := confidenceFromScore(c.score); got != c.want {
			t.Errorf("confidenceFromScore(%.2f) = %q, want %q", c.score, got, c.want)
		}
	}
}
