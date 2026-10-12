package ctemcycle

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Charter success-criteria evaluation.
//
// A charter's SuccessCriteria are free-form {name, metric, target} triples
// typed by a person. At cycle close each one is checked against the cycle's
// computed metrics and gets one of three outcomes:
//
//	met             the metric was recognized, the target parsed, and the
//	                measured value satisfies it
//	unmet           same, but the measured value does not satisfy it
//	not_measurable  the criterion cannot be checked by a machine: the metric
//	                name is not one we measure, the target is not a
//	                comparison we can parse, the unit does not fit the metric,
//	                or the cycle has no data for that metric
//
// The mapping is deliberately strict. A metric name matches only an exact
// alias (after lower-casing and collapsing punctuation to "_"), never a
// substring or a fuzzy guess: "open KEV findings" is not "findings opened",
// and a wrong verdict is worse than an honest "not measurable". The reason
// for every not_measurable outcome is recorded so the charter author can fix
// the wording for the next cycle.

// CriterionOutcome is the verdict for one success criterion.
type CriterionOutcome string

const (
	CriterionMet           CriterionOutcome = "met"
	CriterionUnmet         CriterionOutcome = "unmet"
	CriterionNotMeasurable CriterionOutcome = "not_measurable"
)

// Metric keys computed at close in addition to the six in review.go. They
// exist so the most common charter criteria ("resolve every P0", "cut risk by
// 20%") have something real to be checked against.
const (
	MetricP0Resolved       = "p0_resolved"
	MetricP1Resolved       = "p1_resolved"
	MetricP0OpenAtClose    = "p0_open_at_close"
	MetricP1OpenAtClose    = "p1_open_at_close"
	MetricRiskBefore       = "risk_before"
	MetricRiskAfter        = "risk_after"
	MetricRiskReductionPct = "risk_reduction_pct"
	// MetricCharterCompletionRate is met / (met + unmet) × 100. It is only
	// stored when at least one criterion was measurable — a cycle whose
	// criteria are all free text has no completion rate, not a rate of 0.
	MetricCharterCompletionRate = "charter_completion_rate"
)

// Units a metric is expressed in. Thresholds are converted to the metric's
// base unit before comparison.
const (
	UnitHours   = "hours"
	UnitCount   = "count"
	UnitPercent = "percent"
	UnitScore   = "score"
)

// CriterionEvaluation is the persisted verdict for one charter criterion.
// Name/Metric/Target echo the charter as written; the remaining fields show
// how it was interpreted, so a verdict can always be checked by hand.
type CriterionEvaluation struct {
	Name   string `json:"name"`
	Metric string `json:"metric"`
	Target string `json:"target"`
	// MetricKey is the cycle metric the criterion resolved to (empty when
	// the metric name was not recognized).
	MetricKey string `json:"metric_key,omitempty"`
	// Comparator is one of <=, <, >=, >, = (empty when the target did not
	// parse).
	Comparator string `json:"comparator,omitempty"`
	// Threshold is the target converted to Unit.
	Threshold *float64 `json:"threshold,omitempty"`
	// Actual is the measured value in Unit (nil when there was no data).
	Actual  *float64         `json:"actual,omitempty"`
	Unit    string           `json:"unit,omitempty"`
	Outcome CriterionOutcome `json:"outcome"`
	// Reason explains a not_measurable outcome.
	Reason string `json:"reason,omitempty"`
}

// CharterEvaluation is the result of checking every success criterion of a
// cycle's charter at close. Stored on ctem_cycles.charter_evaluation.
type CharterEvaluation struct {
	EvaluatedAt   time.Time             `json:"evaluated_at"`
	Criteria      []CriterionEvaluation `json:"criteria"`
	Met           int                   `json:"met"`
	Unmet         int                   `json:"unmet"`
	NotMeasurable int                   `json:"not_measurable"`
	// CompletionRate is met / (met + unmet) × 100, rounded to 2 decimals.
	// Nil when no criterion was measurable.
	CompletionRate *float64 `json:"completion_rate,omitempty"`
}

// metricSpec describes a metric criteria can refer to.
type metricSpec struct {
	key  string
	unit string
	// lowerIsBetter picks the default comparator when a target has none:
	// "MTTR: 48h" means ≤ 48h, "P0 resolved: 5" means ≥ 5.
	lowerIsBetter bool
	// defaultDays: a bare number is read as days instead of hours
	// (for aliases like "mttr_days").
	defaultDays bool
}

var (
	specMTTRHours   = metricSpec{key: MetricMTTRHours, unit: UnitHours, lowerIsBetter: true}
	specMTTRDays    = metricSpec{key: MetricMTTRHours, unit: UnitHours, lowerIsBetter: true, defaultDays: true}
	specOpened      = metricSpec{key: MetricFindingsOpened, unit: UnitCount, lowerIsBetter: true}
	specResolved    = metricSpec{key: MetricFindingsResolved, unit: UnitCount}
	specP0Resolved  = metricSpec{key: MetricP0Resolved, unit: UnitCount}
	specP1Resolved  = metricSpec{key: MetricP1Resolved, unit: UnitCount}
	specP0Open      = metricSpec{key: MetricP0OpenAtClose, unit: UnitCount, lowerIsBetter: true}
	specP1Open      = metricSpec{key: MetricP1OpenAtClose, unit: UnitCount, lowerIsBetter: true}
	specChurn       = metricSpec{key: MetricPClassChurn, unit: UnitCount, lowerIsBetter: true}
	specCoverage    = metricSpec{key: MetricValidationCoverage, unit: UnitPercent}
	specRiskReduced = metricSpec{key: MetricRiskReductionPct, unit: UnitPercent}
	specRiskAfter   = metricSpec{key: MetricRiskAfter, unit: UnitScore, lowerIsBetter: true}
	specScopeDrift  = metricSpec{key: MetricScopeDriftSize, unit: UnitCount, lowerIsBetter: true}
)

// metricAliases maps a normalized metric name to the metric it measures.
// Only exact matches count. scope_drift_size counts the external-surface
// assets first seen during the cycle (RFC-036 §6.9).
var metricAliases = map[string]metricSpec{
	"mttr":                     specMTTRHours,
	"mttr_hours":               specMTTRHours,
	"mean_time_to_remediate":   specMTTRHours,
	"mean_time_to_remediation": specMTTRHours,
	"mean_time_to_resolve":     specMTTRHours,
	"mttr_days":                specMTTRDays,
	"findings_opened":          specOpened,
	"opened_findings":          specOpened,
	"new_findings":             specOpened,
	"findings_discovered":      specOpened,
	"findings_resolved":        specResolved,
	"resolved_findings":        specResolved,
	"p0_resolved":              specP0Resolved,
	"resolved_p0":              specP0Resolved,
	"p0_findings_resolved":     specP0Resolved,
	"p1_resolved":              specP1Resolved,
	"resolved_p1":              specP1Resolved,
	"p1_findings_resolved":     specP1Resolved,
	"p0_open":                  specP0Open,
	"open_p0":                  specP0Open,
	"open_p0_findings":         specP0Open,
	"p0_open_at_close":         specP0Open,
	"p1_open":                  specP1Open,
	"open_p1":                  specP1Open,
	"open_p1_findings":         specP1Open,
	"p1_open_at_close":         specP1Open,
	"p_class_churn":            specChurn,
	"priority_churn":           specChurn,
	"validation_coverage":      specCoverage,
	"validation_coverage_pct":  specCoverage,
	"risk_reduction":           specRiskReduced,
	"risk_reduction_pct":       specRiskReduced,
	"risk_reduced":             specRiskReduced,
	"risk_after":               specRiskAfter,
	"risk_score_after":         specRiskAfter,
	"risk_at_close":            specRiskAfter,
	"scope_drift_size":         specScopeDrift,
	"scope_drift":              specScopeDrift,
	"new_external_assets":      specScopeDrift,
}

// RecognizedCriterionMetrics returns the canonical metric names a criterion
// can use, sorted — for error messages and UI hints.
func RecognizedCriterionMetrics() []string {
	seen := map[string]struct{}{}
	for alias, spec := range metricAliases {
		if alias == spec.key || alias == "mttr" || alias == "mttr_days" {
			seen[alias] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// normalizeMetricName lower-cases and collapses punctuation/whitespace runs
// to "_": "Mean time to remediate" → "mean_time_to_remediate", "P0 open" →
// "p0_open".
func normalizeMetricName(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "_"), "_")
}

// targetPhrases rewrites word comparators to symbols. Order matters: longer
// phrases first so "no more than" is not read as "more than".
var targetPhrases = []struct{ phrase, op string }{
	{"no more than", "<="},
	{"no less than", ">="},
	{"at most", "<="},
	{"at least", ">="},
	{"maximum", "<="},
	{"minimum", ">="},
	{"less than", "<"},
	{"more than", ">"},
	{"fewer than", "<"},
	{"greater than", ">"},
	{"under", "<"},
	{"below", "<"},
	{"over", ">"},
	{"above", ">"},
	{"max", "<="},
	{"min", ">="},
}

var targetPattern = regexp.MustCompile(`^(<=|>=|==|<|>|=)?\s*(\d+(?:\.\d+)?)\s*([a-z%]*)$`)

// parsedTarget is a target string reduced to comparator + number + unit word.
type parsedTarget struct {
	comparator string // may be empty: caller applies the metric default
	value      float64
	unit       string // raw unit word, lower-case; may be empty
}

// parseTarget reads targets such as "0", "<48", "< 14 days", ">= 90%",
// "≤ 7d", "at least 5", "under 2 weeks". It returns ok=false for anything
// else (e.g. "all critical assets", "Q3").
func parseTarget(raw string) (parsedTarget, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.NewReplacer("≤", "<=", "≥", ">=", "=<", "<=", "=>", ">=", ",", "").Replace(s)
	for _, p := range targetPhrases {
		if strings.HasPrefix(s, p.phrase+" ") {
			s = p.op + strings.TrimSpace(strings.TrimPrefix(s, p.phrase))
			break
		}
	}
	s = strings.TrimSpace(s)
	m := targetPattern.FindStringSubmatch(s)
	if m == nil {
		return parsedTarget{}, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return parsedTarget{}, false
	}
	cmp := m[1]
	if cmp == "==" {
		cmp = "="
	}
	return parsedTarget{comparator: cmp, value: v, unit: m[3]}, true
}

// toBaseUnit converts a parsed target value into the metric's base unit.
// ok=false means the unit does not fit the metric (e.g. "%" on a count).
func toBaseUnit(spec metricSpec, value float64, unit string) (float64, bool) {
	switch spec.unit {
	case UnitHours:
		switch unit {
		case "":
			if spec.defaultDays {
				return value * 24, true
			}
			return value, true
		case "h", "hr", "hrs", "hour", "hours":
			return value, true
		case "d", "day", "days":
			return value * 24, true
		case "w", "wk", "wks", "week", "weeks":
			return value * 24 * 7, true
		}
	case UnitCount:
		switch unit {
		case "", "finding", "findings":
			return value, true
		}
	case UnitPercent:
		switch unit {
		case "", "%", "pct", "percent":
			return value, true
		}
	case UnitScore:
		switch unit {
		case "", "pt", "pts", "point", "points":
			return value, true
		}
	}
	return 0, false
}

// compareEpsilon absorbs the DECIMAL(12,2) rounding of stored metrics so a
// value stored as 48.00 still satisfies "<= 48".
const compareEpsilon = 1e-9

func satisfies(actual float64, cmp string, threshold float64) bool {
	switch cmp {
	case "<=":
		return actual <= threshold+compareEpsilon
	case "<":
		return actual < threshold-compareEpsilon
	case ">=":
		return actual >= threshold-compareEpsilon
	case ">":
		return actual > threshold+compareEpsilon
	case "=":
		return math.Abs(actual-threshold) <= compareEpsilon
	}
	return false
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// EvaluateCriterion checks one criterion against the cycle's metric set.
func EvaluateCriterion(c CharterSuccessCriterion, metrics CycleMetricSet) CriterionEvaluation {
	out := CriterionEvaluation{
		Name:    strings.TrimSpace(c.Name),
		Metric:  strings.TrimSpace(c.Metric),
		Target:  strings.TrimSpace(c.Target),
		Outcome: CriterionNotMeasurable,
	}
	if out.Metric == "" || out.Target == "" {
		out.Reason = "criterion has no metric or no target"
		return out
	}

	spec, ok := metricAliases[normalizeMetricName(out.Metric)]
	if !ok {
		out.Reason = fmt.Sprintf("metric %q is not one the platform measures; use one of: %s",
			out.Metric, strings.Join(RecognizedCriterionMetrics(), ", "))
		return out
	}
	out.MetricKey = spec.key
	out.Unit = spec.unit

	t, ok := parseTarget(out.Target)
	if !ok {
		out.Reason = fmt.Sprintf("target %q is not a numeric comparison (e.g. \"<= 48h\", \">= 90%%\", \"0\")", out.Target)
		return out
	}
	threshold, ok := toBaseUnit(spec, t.value, t.unit)
	if !ok {
		out.Reason = fmt.Sprintf("unit %q does not fit metric %s (measured in %s)", t.unit, spec.key, spec.unit)
		return out
	}
	cmp := t.comparator
	if cmp == "" {
		cmp = ">="
		if spec.lowerIsBetter {
			cmp = "<="
		}
	}
	threshold = round2(threshold)
	out.Comparator = cmp
	out.Threshold = &threshold

	actual, ok := metrics[spec.key]
	if !ok {
		out.Reason = "no data for this metric in the cycle window"
		return out
	}
	actual = round2(actual)
	out.Actual = &actual

	if satisfies(actual, cmp, threshold) {
		out.Outcome = CriterionMet
	} else {
		out.Outcome = CriterionUnmet
	}
	return out
}

// EvaluateCharter checks every success criterion against the cycle's
// metrics. Criteria that are entirely blank are skipped.
func EvaluateCharter(criteria []CharterSuccessCriterion, metrics CycleMetricSet, now time.Time) CharterEvaluation {
	ev := CharterEvaluation{
		EvaluatedAt: now.UTC(),
		Criteria:    make([]CriterionEvaluation, 0, len(criteria)),
	}
	for _, c := range criteria {
		if strings.TrimSpace(c.Name) == "" && strings.TrimSpace(c.Metric) == "" && strings.TrimSpace(c.Target) == "" {
			continue
		}
		r := EvaluateCriterion(c, metrics)
		switch r.Outcome {
		case CriterionMet:
			ev.Met++
		case CriterionUnmet:
			ev.Unmet++
		default:
			ev.NotMeasurable++
		}
		ev.Criteria = append(ev.Criteria, r)
	}
	if measurable := ev.Met + ev.Unmet; measurable > 0 {
		rate := round2(100 * float64(ev.Met) / float64(measurable))
		ev.CompletionRate = &rate
	}
	return ev
}
