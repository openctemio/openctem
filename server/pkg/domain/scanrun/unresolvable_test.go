package scanrun

import (
	"strings"
	"testing"
)

func TestParseUnresolvableRefusal(t *testing.T) {
	entry := func(h string) string {
		return `"` + h + `": cannot resolve scan target host "` + h + `" (refusing to scan an unverifiable target): lookup ` + h + `: no such host`
	}
	all := "invalid scan target: 12 of 12 targets refused: "
	var listed []string
	for i := 0; i < 10; i++ {
		listed = append(listed, entry("h"+string(rune('a'+i))+".example.com"))
	}
	all += strings.Join(listed, "; ") + "; and 2 more"

	hosts, total, ok := ParseUnresolvableRefusal(all)
	if !ok || total != 12 || len(hosts) != 10 || hosts[0] != "ha.example.com" {
		t.Fatalf("hosts=%v total=%d ok=%v", hosts, total, ok)
	}
	// One target: no count prefix.
	if _, total, ok := ParseUnresolvableRefusal("invalid scan target: " + entry("a.example.com")); !ok || total != 1 {
		t.Fatalf("single: total=%d ok=%v", total, ok)
	}
	for name, msg := range map[string]string{
		"not all of them":     "invalid scan target: 2 of 3 targets refused: " + entry("a.example.com") + "; " + entry("b.example.com"),
		"a denied one listed": "invalid scan target: 2 of 2 targets refused: " + entry("a.example.com") + `; "10.0.0.1": scan target IP 10.0.0.1 is in a blocked range`,
		"counts do not add":   "invalid scan target: 5 of 5 targets refused: " + entry("a.example.com") + "; and 1 more",
		"another error":       "scanner not found: nuclei",
		"empty":               "",
	} {
		if _, _, ok := ParseUnresolvableRefusal(msg); ok {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestSkippedUnresolvableWording(t *testing.T) {
	list := []SkippedTarget{{Target: "a.example.com", Reason: SkipReasonTargetUnresolvable}, {Target: "b.example.com", Reason: SkipReasonTargetUnresolvable}}
	if got := SkippedSummary(list, 4); got != "4 name(s) no longer resolve: a.example.com, b.example.com, and 2 more" {
		t.Fatalf("summary = %q", got)
	}
	if n := UnresolvableCount(list, 4); n != 4 {
		t.Fatalf("count = %d", n)
	}
	mixed := append(list, SkippedTarget{Target: "*.example.com", Reason: SkipReasonWildcard})
	if n := UnresolvableCount(mixed, 5); n != 2 {
		t.Fatalf("mixed count = %d, want only the listed names", n)
	}
	if strings.Contains(SkippedSummary(mixed, 5), "no longer resolve") {
		t.Fatal("a mixed skip is not worded as no longer resolving")
	}
}

func TestSensorUnresolvableReasonIsNormalised(t *testing.T) {
	got, _ := ParseSkippedTargets([]byte(`[{"target":"a.example.com","reason":"unresolvable"}]`), 1)
	if len(got) != 1 || got[0].Reason != SkipReasonTargetUnresolvable {
		t.Fatalf("got %+v", got)
	}
}
