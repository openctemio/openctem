package compliance

import "testing"

func TestComplianceScore_ClampedAndCorrect(t *testing.T) {
	cases := []struct {
		name                              string
		total, implemented, notApplicable int64
		want                              float64
	}{
		{"half implemented", 10, 5, 0, 50},
		{"all implemented", 4, 4, 0, 100},
		{"not_applicable excluded from denominator", 10, 4, 2, 50}, // 4 / (10-2)
		{"none assessable → 100", 0, 0, 0, 100},
		{"stale total below live count clamps to 100", 3, 5, 0, 100}, // was >100%
		{"negative denominator clamps to 100", 2, 1, 5, 100},         // assessable <= 0
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &FrameworkStats{TotalControls: tc.total, Implemented: tc.implemented, NotApplicable: tc.notApplicable}
			got := s.ComplianceScore()
			if got != tc.want {
				t.Fatalf("ComplianceScore()=%v, want %v", got, tc.want)
			}
			if got < 0 || got > 100 {
				t.Fatalf("score %v out of [0,100]", got)
			}
		})
	}
}
