package scanprofile

import (
	"testing"
)

func TestQualityGate_Evaluate_Disabled(t *testing.T) {
	gate := NewQualityGate() // disabled by default
	counts := FindingCounts{
		Critical: 10,
		High:     20,
		Medium:   30,
		Low:      40,
		Info:     50,
		Total:    150,
	}

	result := gate.Evaluate(counts)

	if !result.Passed {
		t.Error("expected disabled quality gate to pass")
	}
	if len(result.Breaches) != 0 {
		t.Error("expected no breaches for disabled quality gate")
	}
}

func TestQualityGate_Evaluate_FailOnCritical(t *testing.T) {
	gate := QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		MaxCritical:    -1, // unlimited
		MaxHigh:        -1,
		MaxMedium:      -1,
		MaxTotal:       -1,
	}

	tests := []struct {
		name     string
		counts   FindingCounts
		expected bool
	}{
		{
			name:     "no critical - pass",
			counts:   FindingCounts{Critical: 0, High: 10},
			expected: true,
		},
		{
			name:     "has critical - fail",
			counts:   FindingCounts{Critical: 1, High: 0},
			expected: false,
		},
		{
			name:     "many critical - fail",
			counts:   FindingCounts{Critical: 100, High: 200},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gate.Evaluate(tt.counts)
			if result.Passed != tt.expected {
				t.Errorf("expected Passed=%v, got %v", tt.expected, result.Passed)
			}
		})
	}
}

func TestQualityGate_Evaluate_FailOnHigh(t *testing.T) {
	gate := QualityGate{
		Enabled:     true,
		FailOnHigh:  true,
		MaxCritical: -1,
		MaxHigh:     -1,
		MaxMedium:   -1,
		MaxTotal:    -1,
	}

	tests := []struct {
		name     string
		counts   FindingCounts
		expected bool
	}{
		{
			name:     "no high - pass",
			counts:   FindingCounts{Critical: 0, High: 0, Medium: 50},
			expected: true,
		},
		{
			name:     "has high - fail",
			counts:   FindingCounts{Critical: 0, High: 1, Medium: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gate.Evaluate(tt.counts)
			if result.Passed != tt.expected {
				t.Errorf("expected Passed=%v, got %v", tt.expected, result.Passed)
			}
		})
	}
}

func TestQualityGate_Evaluate_MaxThresholds(t *testing.T) {
	gate := QualityGate{
		Enabled:     true,
		MaxCritical: 2,
		MaxHigh:     5,
		MaxMedium:   10,
		MaxTotal:    50,
	}

	tests := []struct {
		name             string
		counts           FindingCounts
		expected         bool
		expectedBreaches int
	}{
		{
			name:             "under all limits - pass",
			counts:           FindingCounts{Critical: 1, High: 3, Medium: 5, Low: 10, Info: 5, Total: 24},
			expected:         true,
			expectedBreaches: 0,
		},
		{
			name:             "critical over limit - fail",
			counts:           FindingCounts{Critical: 5, High: 3, Medium: 5, Low: 10, Info: 5, Total: 28},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "high over limit - fail",
			counts:           FindingCounts{Critical: 1, High: 10, Medium: 5, Low: 10, Info: 5, Total: 31},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "medium over limit - fail",
			counts:           FindingCounts{Critical: 1, High: 3, Medium: 15, Low: 10, Info: 5, Total: 34},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "total over limit - fail",
			counts:           FindingCounts{Critical: 1, High: 3, Medium: 5, Low: 30, Info: 20, Total: 59},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "multiple over limits - fail with multiple breaches",
			counts:           FindingCounts{Critical: 10, High: 20, Medium: 30, Low: 40, Info: 50, Total: 150},
			expected:         false,
			expectedBreaches: 4, // critical, high, medium, total
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gate.Evaluate(tt.counts)
			if result.Passed != tt.expected {
				t.Errorf("expected Passed=%v, got %v", tt.expected, result.Passed)
			}
			if len(result.Breaches) != tt.expectedBreaches {
				t.Errorf("expected %d breaches, got %d", tt.expectedBreaches, len(result.Breaches))
			}
		})
	}
}

func TestQualityGate_Evaluate_UnlimitedThresholds(t *testing.T) {
	gate := QualityGate{
		Enabled:     true,
		MaxCritical: -1, // unlimited
		MaxHigh:     -1,
		MaxMedium:   -1,
		MaxTotal:    -1,
	}

	counts := FindingCounts{
		Critical: 1000,
		High:     2000,
		Medium:   3000,
		Low:      4000,
		Info:     5000,
		Total:    15000,
	}

	result := gate.Evaluate(counts)

	if !result.Passed {
		t.Error("expected unlimited thresholds to pass")
	}
	if len(result.Breaches) != 0 {
		t.Error("expected no breaches for unlimited thresholds")
	}
}

func TestQualityGate_Evaluate_ZeroThreshold(t *testing.T) {
	gate := QualityGate{
		Enabled:     true,
		MaxCritical: 0, // zero tolerance
		MaxHigh:     0,
		MaxMedium:   -1,
		MaxTotal:    -1,
	}

	tests := []struct {
		name     string
		counts   FindingCounts
		expected bool
	}{
		{
			name:     "zero findings - pass",
			counts:   FindingCounts{Critical: 0, High: 0, Medium: 100},
			expected: true,
		},
		{
			name:     "one critical - fail",
			counts:   FindingCounts{Critical: 1, High: 0, Medium: 0},
			expected: false,
		},
		{
			name:     "one high - fail",
			counts:   FindingCounts{Critical: 0, High: 1, Medium: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gate.Evaluate(tt.counts)
			if result.Passed != tt.expected {
				t.Errorf("expected Passed=%v, got %v", tt.expected, result.Passed)
			}
		})
	}
}

func TestQualityGate_Evaluate_CombinedConditions(t *testing.T) {
	// Strict gate: fail on critical OR high, and max 5 medium
	gate := QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		FailOnHigh:     true,
		MaxCritical:    -1, // unlimited (but FailOnCritical takes precedence)
		MaxHigh:        -1,
		MaxMedium:      5,
		MaxTotal:       -1,
	}

	tests := []struct {
		name             string
		counts           FindingCounts
		expected         bool
		expectedBreaches int
	}{
		{
			name:             "no critical/high, medium under limit - pass",
			counts:           FindingCounts{Critical: 0, High: 0, Medium: 3},
			expected:         true,
			expectedBreaches: 0,
		},
		{
			name:             "has critical - fail",
			counts:           FindingCounts{Critical: 1, High: 0, Medium: 0},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "has high - fail",
			counts:           FindingCounts{Critical: 0, High: 1, Medium: 0},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "medium over limit - fail",
			counts:           FindingCounts{Critical: 0, High: 0, Medium: 10},
			expected:         false,
			expectedBreaches: 1,
		},
		{
			name:             "all conditions violated - fail with multiple breaches",
			counts:           FindingCounts{Critical: 5, High: 10, Medium: 15},
			expected:         false,
			expectedBreaches: 3, // critical, high, medium
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gate.Evaluate(tt.counts)
			if result.Passed != tt.expected {
				t.Errorf("expected Passed=%v, got %v", tt.expected, result.Passed)
			}
			if len(result.Breaches) != tt.expectedBreaches {
				t.Errorf("expected %d breaches, got %d", tt.expectedBreaches, len(result.Breaches))
			}
		})
	}
}

func TestQualityGate_Evaluate_ReasonSet(t *testing.T) {
	gate := QualityGate{
		Enabled:        true,
		FailOnCritical: true,
	}

	counts := FindingCounts{Critical: 1}
	result := gate.Evaluate(counts)

	if result.Reason == "" {
		t.Error("expected reason to be set when gate fails")
	}
}

func TestQualityGate_Evaluate_CountsPreserved(t *testing.T) {
	gate := QualityGate{Enabled: true}
	counts := FindingCounts{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
		Info:     5,
		Total:    15,
	}

	result := gate.Evaluate(counts)

	if result.Counts != counts {
		t.Error("expected counts to be preserved in result")
	}
}

func TestNewQualityGate_DefaultValues(t *testing.T) {
	gate := NewQualityGate()

	if gate.Enabled {
		t.Error("expected new quality gate to be disabled by default")
	}
	if gate.MaxCritical != -1 {
		t.Errorf("expected MaxCritical=-1, got %d", gate.MaxCritical)
	}
	if gate.MaxHigh != -1 {
		t.Errorf("expected MaxHigh=-1, got %d", gate.MaxHigh)
	}
	if gate.MaxMedium != -1 {
		t.Errorf("expected MaxMedium=-1, got %d", gate.MaxMedium)
	}
	if gate.MaxTotal != -1 {
		t.Errorf("expected MaxTotal=-1, got %d", gate.MaxTotal)
	}
}
