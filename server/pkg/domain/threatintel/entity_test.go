package threatintel

import (
	"testing"
	"time"
)

func TestNewEPSSScore_ClampsRanges(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name                      string
		score, percentile         float64
		wantScore, wantPercentile float64
	}{
		{"in range", 0.42, 73.5, 0.42, 73.5},
		{"score above 1", 5.0, 50, 1, 50},
		{"score below 0", -0.3, 50, 0, 50},
		{"percentile above 100", 0.5, 250, 0.5, 100},
		{"percentile below 0", 0.5, -10, 0.5, 0},
		{"both out of range", 9, 9999, 1, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewEPSSScore("CVE-2024-0001", tc.score, tc.percentile, "v1", now)
			if s.Score() != tc.wantScore {
				t.Errorf("score: got %v want %v", s.Score(), tc.wantScore)
			}
			if s.Percentile() != tc.wantPercentile {
				t.Errorf("percentile: got %v want %v", s.Percentile(), tc.wantPercentile)
			}
		})
	}
}
