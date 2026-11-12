package tenant

import "testing"

func TestScopeSettings_InfoCoverage(t *testing.T) {
	var s ScopeSettings
	if !s.InfoCoverageOn() || s.InfoCoverageEvery() != 30 {
		t.Errorf("default: on %v, every %d", s.InfoCoverageOn(), s.InfoCoverageEvery())
	}
	off := false
	s.InfoCoverage, s.InfoCoverageDays = &off, 14
	if s.InfoCoverageOn() || s.InfoCoverageEvery() != 14 {
		t.Errorf("set: on %v, every %d", s.InfoCoverageOn(), s.InfoCoverageEvery())
	}
	for _, d := range []int{6, 91, -1} {
		if err := (ScopeSettings{InfoCoverageDays: d}).Validate(); err == nil {
			t.Errorf("%d days accepted", d)
		}
	}
	for _, d := range []int{0, 7, 90} {
		if err := (ScopeSettings{InfoCoverageDays: d}).Validate(); err != nil {
			t.Errorf("%d days refused: %v", d, err)
		}
	}
}
