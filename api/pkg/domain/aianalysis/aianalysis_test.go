package aianalysis

import (
	"encoding/json"
	"strings"
	"testing"
)

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
