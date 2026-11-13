package retest

import (
	"strings"
	"testing"
)

func TestApplyTemplateDrift(t *testing.T) {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	fixed := Verdict{Outcome: OutcomeConfirmedFixed, Code: ReasonNotMatched, Reason: "orig"}
	present := Verdict{Outcome: OutcomeStillVulnerable, Code: ReasonMatched, Reason: "orig"}
	notRepro := Verdict{Outcome: OutcomeNotReproduced, Code: ReasonNoEndpointProof, Reason: "orig"}
	for name, tc := range map[string]struct {
		v        Verdict
		baseline string
		digest   string
		require  bool
		want     Outcome
	}{
		"same digest keeps a fix":                       {fixed, a, a, true, OutcomeConfirmedFixed},
		"same digest keeps a match":                     {present, a, a, true, OutcomeStillVulnerable},
		"other digest: fix inconclusive":                {fixed, a, b, true, OutcomeInconclusive},
		"other digest: match inconclusive":              {present, a, b, false, OutcomeInconclusive},
		"missing digest: fix inconclusive (validate)":   {fixed, a, "", true, OutcomeInconclusive},
		"missing digest: fix inconclusive (tool)":       {fixed, a, "", false, OutcomeInconclusive},
		"missing digest: match stands (tool)":           {present, a, "", false, OutcomeStillVulnerable},
		"missing digest: match inconclusive (validate)": {present, a, "", true, OutcomeInconclusive},
		"no baseline: as decided":                       {fixed, "", "", true, OutcomeConfirmedFixed},
		"not reproduced stays":                          {notRepro, a, b, true, OutcomeNotReproduced},
	} {
		got := ApplyTemplateDrift(tc.v, tc.baseline, tc.digest, tc.require)
		if got.Outcome != tc.want {
			t.Errorf("%s: %s (%s), want %s", name, got.Outcome, got.Reason, tc.want)
		}
		if got.Outcome == OutcomeInconclusive && got.Code != ReasonTemplateChanged {
			t.Errorf("%s: code %s", name, got.Code)
		}
	}
}
