package ctemcycle

import (
	"strings"
	"testing"
	"time"
)

func sampleMetrics() CycleMetricSet {
	return CycleMetricSet{
		MetricMTTRHours:          40,
		MetricFindingsOpened:     12,
		MetricFindingsResolved:   9,
		MetricPClassChurn:        3,
		MetricValidationCoverage: 75,
		MetricScopeDriftSize:     0,
		MetricP0Resolved:         4,
		MetricP1Resolved:         2,
		MetricP0OpenAtClose:      0,
		MetricP1OpenAtClose:      5,
		MetricRiskBefore:         60,
		MetricRiskAfter:          45,
		MetricRiskReductionPct:   25,
	}
}

func TestEvaluateCriterion_Table(t *testing.T) {
	m := sampleMetrics()
	cases := []struct {
		name       string
		metric     string
		target     string
		want       CriterionOutcome
		wantKey    string
		wantCmp    string
		wantThresh float64
	}{
		// MTTR in hours / days / weeks, with and without explicit comparators.
		{"mttr bare hours", "MTTR", "48", CriterionMet, MetricMTTRHours, "<=", 48},
		{"mttr lt hours", "mttr_hours", "<48", CriterionMet, MetricMTTRHours, "<", 48},
		{"mttr days", "MTTR", "< 14 days", CriterionMet, MetricMTTRHours, "<", 336},
		{"mttr 1d unmet", "MTTR", "<= 1d", CriterionUnmet, MetricMTTRHours, "<=", 24},
		{"mttr unicode", "mttr", "≤ 2 days", CriterionMet, MetricMTTRHours, "<=", 48},
		{"mttr_days bare number is days", "MTTR days", "1", CriterionUnmet, MetricMTTRHours, "<=", 24},
		{"mttr weeks", "Mean time to remediate", "under 1 week", CriterionMet, MetricMTTRHours, "<", 168},
		// Counts: higher-is-better default >=, lower-is-better default <=.
		{"p0 resolved default ge", "P0 resolved", "4", CriterionMet, MetricP0Resolved, ">=", 4},
		{"p0 resolved at least unmet", "p0_resolved", "at least 5", CriterionUnmet, MetricP0Resolved, ">=", 5},
		{"open p0 zero", "Open P0", "0", CriterionMet, MetricP0OpenAtClose, "<=", 0},
		{"open p1 zero unmet", "p1 open", "0", CriterionUnmet, MetricP1OpenAtClose, "<=", 0},
		{"resolved gt", "findings resolved", "> 9", CriterionUnmet, MetricFindingsResolved, ">", 9},
		{"resolved eq", "findings_resolved", "= 9", CriterionMet, MetricFindingsResolved, "=", 9},
		// Percentages.
		{"coverage pct", "validation coverage", ">= 70%", CriterionMet, MetricValidationCoverage, ">=", 70},
		{"coverage unmet", "Validation coverage", "at least 80 percent", CriterionUnmet, MetricValidationCoverage, ">=", 80},
		{"risk reduction", "Risk reduction", ">= 20%", CriterionMet, MetricRiskReductionPct, ">=", 20},
		{"risk reduction unmet", "risk reduced", "30", CriterionUnmet, MetricRiskReductionPct, ">=", 30},
		{"risk after", "risk after", "<= 50", CriterionMet, MetricRiskAfter, "<=", 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateCriterion(CharterSuccessCriterion{Name: tc.name, Metric: tc.metric, Target: tc.target}, m)
			if got.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s (reason %q)", got.Outcome, tc.want, got.Reason)
			}
			if got.MetricKey != tc.wantKey {
				t.Errorf("metric_key = %q, want %q", got.MetricKey, tc.wantKey)
			}
			if got.Comparator != tc.wantCmp {
				t.Errorf("comparator = %q, want %q", got.Comparator, tc.wantCmp)
			}
			if got.Threshold == nil || *got.Threshold != tc.wantThresh {
				t.Errorf("threshold = %v, want %v", got.Threshold, tc.wantThresh)
			}
			if got.Actual == nil {
				t.Errorf("actual must be set for a measured criterion")
			}
		})
	}
}

func TestEvaluateCriterion_NotMeasurable(t *testing.T) {
	m := sampleMetrics()
	cases := []struct {
		name, metric, target, reasonHas string
	}{
		{"no metric", "", "0", "no metric"},
		{"no target", "MTTR", "", "no target"},
		// Unknown metric names are never guessed at — not even near-misses.
		{"free text metric", "open KEV findings", "0", "not one the platform measures"},
		{"per-priority mttr not measured", "mttr_hours_p0", "<48", "not one the platform measures"},
		{"substring is not a match", "resolved", "5", "not one the platform measures"},
		{"prose target", "MTTR", "as fast as possible", "not a numeric comparison"},
		{"quarter target", "p0 resolved", "Q3", "not a numeric comparison"},
		{"percent on a count", "p0 resolved", ">= 90%", "does not fit"},
		{"days on a percent", "validation coverage", "5 days", "does not fit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateCriterion(CharterSuccessCriterion{Name: tc.name, Metric: tc.metric, Target: tc.target}, m)
			if got.Outcome != CriterionNotMeasurable {
				t.Fatalf("outcome = %s, want not_measurable", got.Outcome)
			}
			if !strings.Contains(got.Reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", got.Reason, tc.reasonHas)
			}
			if got.Actual != nil {
				t.Errorf("actual must be nil for a not-measurable criterion, got %v", *got.Actual)
			}
		})
	}
}

// A recognized metric with no data in the window (e.g. no risk snapshot
// before activation) is not measurable — never a silent 0 that passes "<= X".
func TestEvaluateCriterion_MissingDataIsNotMeasurable(t *testing.T) {
	m := CycleMetricSet{MetricMTTRHours: 10}
	got := EvaluateCriterion(CharterSuccessCriterion{Name: "risk", Metric: "risk after", Target: "<= 50"}, m)
	if got.Outcome != CriterionNotMeasurable {
		t.Fatalf("outcome = %s, want not_measurable", got.Outcome)
	}
	if got.MetricKey != MetricRiskAfter || got.Threshold == nil {
		t.Errorf("interpretation should still be recorded: %+v", got)
	}
	if !strings.Contains(got.Reason, "no data") {
		t.Errorf("reason = %q", got.Reason)
	}
}

// Stored metrics are DECIMAL(12,2); a boundary value must still satisfy a
// non-strict comparison and fail a strict one.
func TestEvaluateCriterion_Boundary(t *testing.T) {
	m := CycleMetricSet{MetricMTTRHours: 47.999999}
	if got := EvaluateCriterion(CharterSuccessCriterion{Metric: "mttr", Target: "<= 48"}, m); got.Outcome != CriterionMet {
		t.Errorf("<= 48 at 48.00: %s", got.Outcome)
	}
	if got := EvaluateCriterion(CharterSuccessCriterion{Metric: "mttr", Target: "< 48"}, m); got.Outcome != CriterionUnmet {
		t.Errorf("< 48 at 48.00: %s", got.Outcome)
	}
}

func TestEvaluateCharter_CountsAndCompletionRate(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	criteria := []CharterSuccessCriterion{
		{Name: "MTTR", Metric: "MTTR", Target: "< 14 days"},              // met
		{Name: "P0", Metric: "P0 resolved", Target: ">= 10"},             // unmet
		{Name: "Coverage", Metric: "validation coverage", Target: "70%"}, // met
		{Name: "KEV", Metric: "open KEV findings", Target: "0"},          // not measurable
		{}, // blank row: skipped
		{Name: "Culture", Metric: "", Target: ""}, // not measurable
	}
	ev := EvaluateCharter(criteria, sampleMetrics(), now)

	if len(ev.Criteria) != 5 {
		t.Fatalf("want 5 evaluated criteria (blank skipped), got %d", len(ev.Criteria))
	}
	if ev.Met != 2 || ev.Unmet != 1 || ev.NotMeasurable != 2 {
		t.Fatalf("counts met=%d unmet=%d nm=%d", ev.Met, ev.Unmet, ev.NotMeasurable)
	}
	if ev.CompletionRate == nil || *ev.CompletionRate != 66.67 {
		t.Fatalf("completion rate = %v, want 66.67 (2 met / 3 measurable)", ev.CompletionRate)
	}
	if !ev.EvaluatedAt.Equal(now) {
		t.Errorf("evaluated_at = %v", ev.EvaluatedAt)
	}
	// Order is preserved so the UI can line verdicts up with the charter.
	if ev.Criteria[0].Name != "MTTR" || ev.Criteria[3].Name != "KEV" {
		t.Errorf("order not preserved: %+v", ev.Criteria)
	}
}

// With nothing measurable there is no completion rate — not a rate of 0.
func TestEvaluateCharter_NoMeasurableCriteria(t *testing.T) {
	ev := EvaluateCharter([]CharterSuccessCriterion{
		{Name: "Culture", Metric: "team morale", Target: "high"},
	}, sampleMetrics(), time.Now())
	if ev.CompletionRate != nil {
		t.Fatalf("completion rate must be nil, got %v", *ev.CompletionRate)
	}
	if ev.NotMeasurable != 1 {
		t.Fatalf("not_measurable = %d", ev.NotMeasurable)
	}

	empty := EvaluateCharter(nil, sampleMetrics(), time.Now())
	if empty.CompletionRate != nil || len(empty.Criteria) != 0 {
		t.Fatalf("empty charter: %+v", empty)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		cmp   string
		value float64
		unit  string
	}{
		{"0", true, "", 0, ""},
		{"<48", true, "<", 48, ""},
		{" >= 90% ", true, ">=", 90, "%"},
		{"=< 3", true, "<=", 3, ""},
		{"no more than 3 findings", true, "<=", 3, "findings"},
		{"no less than 2", true, ">=", 2, ""},
		{"more than 1,000", true, ">", 1000, ""},
		{"1.5d", true, "", 1.5, "d"},
		{"== 4", true, "=", 4, ""},
		{"-5", false, "", 0, ""},
		{"all of them", false, "", 0, ""},
		{"", false, "", 0, ""},
		{"5 to 10", false, "", 0, ""},
	}
	for _, tc := range cases {
		got, ok := parseTarget(tc.in)
		if ok != tc.ok {
			t.Errorf("parseTarget(%q) ok=%v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.comparator != tc.cmp || got.value != tc.value || got.unit != tc.unit {
			t.Errorf("parseTarget(%q) = %+v, want cmp=%q value=%v unit=%q", tc.in, got, tc.cmp, tc.value, tc.unit)
		}
	}
}

func TestRecognizedCriterionMetrics(t *testing.T) {
	got := RecognizedCriterionMetrics()
	for _, want := range []string{MetricMTTRHours, MetricP0Resolved, MetricRiskReductionPct, MetricP0OpenAtClose} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("recognized metrics missing %q: %v", want, got)
		}
	}
	offered := false
	for _, g := range got {
		if g == MetricScopeDriftSize {
			offered = true
		}
	}
	if !offered {
		t.Errorf("scope_drift_size must be offered: it counts new external assets (RFC-036 §6.9)")
	}
}
