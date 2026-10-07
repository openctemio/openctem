package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestParseSkippedTargets(t *testing.T) {
	list := json.RawMessage(`[
		{"target":"api.example.com","reason":"unresolvable","rule":"targets","detail":"cannot resolve api.example.com"},
		{"target":"*.example.com","reason":"wildcard_pattern"},
		{"target":"10.0.0.1","reason":"made_up","rule":"targets.deny"},
		{"target":"","reason":"unresolvable"},
		{"target":42},
		{"target":"evil‮.example.com\nline2","reason":"denied_by_policy","detail":"x\u0000y"}
	]`)
	got, total := ParseSkippedTargets(list, 2)
	if len(got) != 4 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if got[0] != (SkippedTarget{Target: "api.example.com", Reason: SkipReasonUnresolvable, Rule: "targets", Detail: "cannot resolve api.example.com"}) {
		t.Errorf("first %+v", got[0])
	}
	if got[1].Reason != SkipReasonWildcard || got[2].Reason != SkipReasonRefused {
		t.Errorf("reasons %q %q: an unknown reason reads as refused", got[1].Reason, got[2].Reason)
	}
	// Sensor-supplied text is one clean line.
	if strings.ContainsAny(got[3].Target, "‮\n") || strings.ContainsRune(got[3].Detail, 0) {
		t.Errorf("not cleaned: %q %q", got[3].Target, got[3].Detail)
	}
	if total != 4 {
		t.Errorf("total %d: at least the entries listed", total)
	}
}

func TestParseSkippedTargets_Bounds(t *testing.T) {
	var entries []map[string]string
	for i := range MaxTaskSkippedTargets + 10 {
		entries = append(entries, map[string]string{"target": fmt.Sprintf("h%d.example.com", i), "reason": "unresolvable",
			"detail": strings.Repeat("d", 5000)})
	}
	raw, _ := json.Marshal(entries)
	got, total := ParseSkippedTargets(raw, 500)
	if len(got) != MaxTaskSkippedTargets || total != 500 {
		t.Fatalf("listed %d, total %d", len(got), total)
	}
	if n := len([]rune(got[0].Detail)); n > maxSkippedDetailRunes {
		t.Fatalf("detail is %d runes", n)
	}
	if _, total := ParseSkippedTargets(nil, MaxSkippedTargetsTotal*10); total != MaxSkippedTargetsTotal {
		t.Fatalf("total %d not capped", total)
	}
	if got, total := ParseSkippedTargets(json.RawMessage(`{"not":"a list"}`), -3); got != nil || total != 0 {
		t.Fatalf("malformed: %+v %d", got, total)
	}
}

func TestSkippedSummary(t *testing.T) {
	if SkippedSummary(nil, 0) != "" {
		t.Fatal("no skips, no summary")
	}
	list := []SkippedTarget{{Target: "api.example.com", Reason: SkipReasonUnresolvable}}
	if got := SkippedSummary(list, 1); got != "Completed with 1 target(s) skipped by the sensor's local policy: api.example.com (unresolvable)" {
		t.Errorf("summary %q", got)
	}
	var many []SkippedTarget
	for i := range 7 {
		many = append(many, SkippedTarget{Target: fmt.Sprintf("h%d", i), Reason: SkipReasonDenied})
	}
	if got := SkippedSummary(many, 9); !strings.HasSuffix(got, "h4 (denied_by_policy), and 4 more") {
		t.Errorf("summary %q", got)
	}
	if got := SkippedSummary(nil, 3); got != "Completed with 3 target(s) skipped by the sensor's local policy" {
		t.Errorf("summary without a list %q", got)
	}
}
