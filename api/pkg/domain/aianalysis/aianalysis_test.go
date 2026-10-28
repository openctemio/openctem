package aianalysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func f64(v float64) *float64 { return &v }

// The direction is computed from the finding's facts; a payload that tries to
// state its own direction (or any unknown field) is refused before that.
func TestNormalizePayload_RefusesUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"verdict":"likely_false_positive","reason":"r","direction":"additive"}`,
		`{"severity":"low","reason":"r","state":"applied"}`,
		`{"text":"s","approved":true}`,
		`{"text":"s"} {"text":"t"}`,
	} {
		k := KindVerdict
		switch {
		case strings.Contains(raw, "severity"):
			k = KindSeverity
		case strings.Contains(raw, "text"):
			k = KindSummary
		}
		if _, err := NormalizePayload(k, json.RawMessage(raw)); err == nil {
			t.Errorf("%s accepted, want refused", raw)
		}
	}
}

func TestNormalizePayload_CleansAndBounds(t *testing.T) {
	out, err := NormalizePayload(KindSummary, json.RawMessage(`{"text":"  hello\u200b\u0007 world  "}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"text":"hello world"}` {
		t.Fatalf("got %s", out)
	}
	if _, err := NormalizePayload(KindSummary, json.RawMessage(`{"text":"`+strings.Repeat("x", MaxSummaryRunes+1)+`"}`)); err == nil {
		t.Fatal("over-long summary accepted")
	}
	if _, err := NormalizePayload(KindVerdict, json.RawMessage(`{"verdict":"closed","reason":""}`)); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	steps, err := NormalizePayload(KindRemediationSteps, json.RawMessage(`{"steps":[{"step":9,"description":"a"},{"step":3,"description":"b","effort":"high"}]}`))
	if err != nil || !strings.Contains(string(steps), `"step":1`) || !strings.Contains(string(steps), `"step":2`) {
		t.Fatalf("steps renumbered: %s %v", steps, err)
	}
}

func TestComputeDirection(t *testing.T) {
	medium := approvalpolicy.Facts{Severity: "medium"}
	cases := []struct {
		k    Kind
		raw  string
		want Direction
	}{
		{KindSeverity, `{"severity":"high","reason":""}`, DirectionRaisesRisk},
		{KindSeverity, `{"severity":"low","reason":""}`, DirectionLowersRisk},
		{KindSeverity, `{"severity":"medium","reason":""}`, DirectionAdditive},
		{KindVerdict, `{"verdict":"likely_false_positive","reason":""}`, DirectionLowersRisk},
		{KindVerdict, `{"verdict":"true_positive","reason":""}`, DirectionAdditive},
		{KindRemediationSteps, `{"steps":[]}`, DirectionAdditive},
		{KindSeverity, `not json`, DirectionLowersRisk},
	}
	for _, c := range cases {
		if got := ComputeDirection(c.k, json.RawMessage(c.raw), medium); got != c.want {
			t.Errorf("%s %s = %s, want %s", c.k, c.raw, got, c.want)
		}
	}
}

func TestDecideAuto(t *testing.T) {
	sg := func(k Kind, d Direction, c *float64, reasons ...string) *Suggestion {
		return &Suggestion{Kind: k, Direction: d, Confidence: c, ReviewReasons: reasons}
	}
	cases := []struct {
		name string
		mode Mode
		s    *Suggestion
		want AutoAction
	}{
		{"suggest keeps open", ModeSuggest, sg(KindSummary, DirectionAdditive, f64(0.99)), AutoKeepOpen},
		{"additive applied", ModeAutoApply, sg(KindSummary, DirectionAdditive, f64(0.99)), AutoApply},
		{"below confidence", ModeAutoApply, sg(KindSummary, DirectionAdditive, f64(0.5)), AutoKeepOpen},
		{"no confidence", ModeAutoApply, sg(KindSummary, DirectionAdditive, nil), AutoKeepOpen},
		{"needs review", ModeAutoApply, sg(KindSummary, DirectionAdditive, f64(0.99), ReviewNoEvidence), AutoKeepOpen},
		{"false positive to approval", ModeAutoApply, sg(KindVerdict, DirectionLowersRisk, f64(0.99)), AutoRequestApproval},
		{"severity raise waits for a person", ModeAutoApply, sg(KindSeverity, DirectionRaisesRisk, f64(0.99)), AutoKeepOpen},
		{"severity lower waits for a person", ModeAutoApply, sg(KindSeverity, DirectionLowersRisk, f64(0.99)), AutoKeepOpen},
		{"same severity is not applied", ModeAutoApply, sg(KindSeverity, DirectionAdditive, f64(0.99)), AutoKeepOpen},
		{"off", ModeOff, sg(KindSummary, DirectionAdditive, f64(0.99)), AutoKeepOpen},
	}
	for _, c := range cases {
		if got := DecideAuto(c.mode, DefaultMinConfidence, c.s); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestShouldDowngrade(t *testing.T) {
	if ShouldDowngrade(ModeAutoApply, Decisions{Total: 9, Overrides: 9}) {
		t.Fatal("fewer than the minimum decisions must not downgrade")
	}
	if ShouldDowngrade(ModeAutoApply, Decisions{Total: 50, Overrides: 9}) {
		t.Fatal("18% must not downgrade")
	}
	if !ShouldDowngrade(ModeAutoApply, Decisions{Total: 50, Overrides: 10}) {
		t.Fatal("20% must downgrade")
	}
	if ShouldDowngrade(ModeSuggest, Decisions{Total: 50, Overrides: 50}) {
		t.Fatal("only auto_apply downgrades")
	}
}

func TestPolicyValidateAndLoosens(t *testing.T) {
	base := DefaultPolicy(shared.NewID(), UseCaseTriage, true)
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.DataClassCeiling = DataClassTenantOnly
	if bad.Validate() == nil {
		t.Fatal("tenant-only data must not go to the built-in executor")
	}
	bad = base
	bad.MinConfidence = 0.2
	if bad.Validate() == nil {
		t.Fatal("confidence floor not enforced")
	}
	auto := base
	auto.Mode = ModeAutoApply
	if !auto.LoosensFrom(base) {
		t.Fatal("turning auto-apply on loosens")
	}
	restricted := base
	restricted.DataClassCeiling = DataClassRestricted
	if !restricted.LoosensFrom(base) {
		t.Fatal("raising the ceiling above internal loosens")
	}
	if base.LoosensFrom(auto) {
		t.Fatal("turning auto-apply off does not loosen")
	}
	if DefaultPolicy(shared.NewID(), UseCaseTriage, false).Mode != ModeOff {
		t.Fatal("default is off before consent")
	}
}

func TestCheckEvidence(t *testing.T) {
	known := map[string]bool{"bundle:finding.title": true}
	ev, reasons := CheckEvidence([]Evidence{{Ref: "bundle:finding.title", Quote: "q"}}, known)
	if len(ev) != 1 || len(reasons) != 0 {
		t.Fatalf("resolved evidence: %v %v", ev, reasons)
	}
	ev, reasons = CheckEvidence([]Evidence{{Ref: "bundle:finding.title"}, {Ref: "tool:9"}}, known)
	if len(ev) != 1 || len(reasons) != 1 || reasons[0] != ReviewUnresolvedEvidence {
		t.Fatalf("one fabricated reference: %v %v", ev, reasons)
	}
	if _, reasons = CheckEvidence(nil, known); len(reasons) != 1 || reasons[0] != ReviewNoEvidence {
		t.Fatalf("no evidence: %v", reasons)
	}
}
