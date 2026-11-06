package asset

import (
	"reflect"
	"testing"
)

func TestLoweredFields(t *testing.T) {
	base := PriorityInputs{Exposure: ExposurePublic, Criticality: CriticalityHigh, CrownJewel: true}
	cases := []struct {
		name  string
		after PriorityInputs
		want  []string
	}{
		{"unchanged", base, nil},
		{"public to isolated", PriorityInputs{ExposureIsolated, CriticalityHigh, true}, []string{"exposure"}},
		{"public to private", PriorityInputs{ExposurePrivate, CriticalityHigh, true}, []string{"exposure"}},
		{"public to restricted", PriorityInputs{ExposureRestricted, CriticalityHigh, true}, []string{"exposure"}},
		{"criticality lower", PriorityInputs{ExposurePublic, CriticalityLow, true}, []string{"criticality"}},
		{"criticality to none", PriorityInputs{ExposurePublic, CriticalityNone, true}, []string{"criticality"}},
		{"crown jewel removed", PriorityInputs{ExposurePublic, CriticalityHigh, false}, []string{"crown_jewel"}},
		{"all three", PriorityInputs{ExposureIsolated, CriticalityLow, false}, []string{"exposure", "criticality", "crown_jewel"}},
		{"raising is not lowering", PriorityInputs{ExposurePublic, CriticalityCritical, true}, nil},
	}
	for _, tc := range cases {
		if got := LoweredFields(base, tc.after); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// Raising exposure and marking a crown jewel are free.
	low := PriorityInputs{Exposure: ExposureIsolated, Criticality: CriticalityLow}
	if got := LoweredFields(low, PriorityInputs{ExposurePublic, CriticalityCritical, true}); got != nil {
		t.Errorf("raising reported as lowering: %v", got)
	}
	// Unknown and restricted are the same step.
	if got := LoweredFields(PriorityInputs{Exposure: ExposureRestricted}, PriorityInputs{Exposure: ExposureUnknown}); got != nil {
		t.Errorf("restricted -> unknown: %v", got)
	}
	if got := LoweredFields(PriorityInputs{Exposure: ExposureUnknown}, PriorityInputs{Exposure: ExposurePrivate}); len(got) != 1 {
		t.Errorf("unknown -> private: %v", got)
	}
}
