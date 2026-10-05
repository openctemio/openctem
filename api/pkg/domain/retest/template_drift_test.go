package retest

import (
	"strings"
	"testing"
)

func TestApplyTemplateDrift(t *testing.T) {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	for name, tc := range map[string]struct {
		outcome  Outcome
		baseline string
		check    CheckResult
		want     Outcome
	}{
		"same digest keeps fixed":          {OutcomeFixed, a, CheckResult{Outcome: "not_detected", TemplateDigest: a}, OutcomeFixed},
		"same digest keeps still present":  {OutcomeStillPresent, a, CheckResult{Outcome: "detected", TemplateDigest: a}, OutcomeStillPresent},
		"other digest: fixed inconclusive": {OutcomeFixed, a, CheckResult{Outcome: "not_detected", TemplateDigest: b}, OutcomeUnknown},
		"other digest: match inconclusive": {OutcomeStillPresent, a, CheckResult{Outcome: "detected", TemplateDigest: b}, OutcomeUnknown},
		"missing digest: inconclusive":     {OutcomeFixed, a, CheckResult{Outcome: "not_detected"}, OutcomeUnknown},
		"no baseline: as before":           {OutcomeFixed, "", CheckResult{Outcome: "not_detected"}, OutcomeFixed},
		"unknown stays unknown":            {OutcomeUnknown, a, CheckResult{Outcome: "error", TemplateDigest: b}, OutcomeUnknown},
		"missing check stays":              {OutcomeUnknown, a, CheckResult{Missing: true}, OutcomeUnknown},
	} {
		got, reason := ApplyTemplateDrift(tc.outcome, "orig", tc.baseline, tc.check)
		if got != tc.want {
			t.Errorf("%s: %s (%s), want %s", name, got, reason, tc.want)
		}
		if got == OutcomeUnknown && tc.outcome != OutcomeUnknown && !strings.Contains(reason, "inconclusive") {
			t.Errorf("%s: reason %q does not say inconclusive", name, reason)
		}
	}
}
