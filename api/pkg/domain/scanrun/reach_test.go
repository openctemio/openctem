package scanrun

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseReach(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Reach
		all  bool
	}{
		{"absent", ``, Reach{}, false},
		{"not an object", `"nope"`, Reach{}, false},
		{"array", `[1,2]`, Reach{}, false},
		{"no targets count", `{"reached":0,"unreached":3}`, Reach{}, false},
		{"targets not a number", `{"targets":"3","reached":0,"unreached":3}`, Reach{}, false},
		{"all unreached", `{"v":1,"targets":3,"reached":0,"unreached":3,"classes":{"timeout":2,"no_route":1}}`,
			Reach{Present: true, Targets: 3, Unreached: 3, Classes: map[string]int{ReachTimeout: 2, ReachNoRoute: 1}}, true},
		{"some reached", `{"targets":12,"reached":9,"unreached":3}`,
			Reach{Present: true, Targets: 12, Reached: 9, Unreached: 3}, false},
		{"nothing tried", `{"targets":0,"reached":0,"unreached":0}`, Reach{Present: true}, false},
		{"negative and NaN-like counts", `{"targets":-5,"reached":-1,"unreached":-2}`, Reach{Present: true}, false},
		{"huge counts capped", `{"targets":1e300,"reached":0,"unreached":1e300}`,
			Reach{Present: true, Targets: MaxReachTargets, Unreached: MaxReachTargets}, true},
		{"reached above targets", `{"targets":2,"reached":7,"unreached":4}`,
			Reach{Present: true, Targets: 2, Reached: 2}, false},
		{"unreached above the rest", `{"targets":3,"reached":1,"unreached":9}`,
			Reach{Present: true, Targets: 3, Reached: 1, Unreached: 2}, false},
		{"unknown classes dropped", `{"targets":1,"reached":0,"unreached":1,"classes":{"timeout":1,"evil\n":5,"no_route":-3,"dns_failure":"x"}}`,
			Reach{Present: true, Targets: 1, Unreached: 1, Classes: map[string]int{ReachTimeout: 1}}, true},
	}
	for _, c := range cases {
		got := ParseReach(json.RawMessage(c.raw))
		if got.Present != c.want.Present || got.Targets != c.want.Targets || got.Reached != c.want.Reached ||
			got.Unreached != c.want.Unreached || len(got.Classes) != len(c.want.Classes) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
			continue
		}
		for k, v := range c.want.Classes {
			if got.Classes[k] != v {
				t.Errorf("%s: class %s = %d, want %d", c.name, k, got.Classes[k], v)
			}
		}
		if got.AllUnreached() != c.all {
			t.Errorf("%s: AllUnreached = %v, want %v", c.name, got.AllUnreached(), c.all)
		}
	}
}

func TestParseUnreachedTargets(t *testing.T) {
	var list []map[string]any
	for i := range MaxTaskUnreachedTargets + 5 {
		list = append(list, map[string]any{"target": "192.0.2." + strings.Repeat("9", i%3+1), "class": ReachTimeout})
	}
	list = append([]map[string]any{
		{"target": "evil\n\x1b[31mhost" + strings.Repeat("y", 400), "class": ReachNoRoute, "detail": "a\nb"},
		{"target": "", "class": ReachTimeout},
		{"target": "x", "class": "unknown_class"},
		{"target": "reached.example.com", "class": ReachReached},
		{"target": "closed.example.com", "class": ReachPortClosed},
		{"target": 7, "class": ReachTimeout},
	}, list...)
	raw, _ := json.Marshal(list)
	got, total := ParseUnreachedTargets(raw, 3)
	if len(got) != MaxTaskUnreachedTargets || total != MaxTaskUnreachedTargets+6 {
		t.Fatalf("%d listed, total %d", len(got), total)
	}
	first := got[0]
	if strings.ContainsAny(first.Target, "\n\x1b") || len([]rune(first.Target)) > maxUnreachedTargetRunes || strings.Contains(first.Detail, "\n") {
		t.Fatalf("not cleaned: %q / %q", first.Target, first.Detail)
	}
	for _, u := range got {
		if !unreachedClass(u.Class) {
			t.Fatalf("a target whose path works is listed as unreached: %+v", u)
		}
	}
	if l, n := ParseUnreachedTargets(json.RawMessage(`{"a":1}`), 5); l != nil || n != 5 {
		t.Fatalf("malformed list: %v %d", l, n)
	}
	if _, n := ParseUnreachedTargets(nil, MaxReachTargets*10); n != MaxReachTargets {
		t.Fatalf("total not capped: %d", n)
	}
	if _, n := ParseUnreachedTargets(nil, -4); n != 0 {
		t.Fatalf("negative total: %d", n)
	}
}

func TestUnreachedMessages(t *testing.T) {
	r := Reach{Present: true, Targets: 12, Reached: 9, Unreached: 3, Classes: map[string]int{ReachTimeout: 2, ReachNoRoute: 1, ReachReached: 9}}
	list := []UnreachedTarget{{Target: "192.0.2.7", Class: ReachTimeout}, {Target: "2001:db8::7", Class: ReachNoRoute}}
	want := "Completed with 3 of 12 target(s) unreachable from the sensor (timeout 2, no_route 1): 192.0.2.7 (timeout), 2001:db8::7 (no_route), and 1 more"
	if s := UnreachedSummary(r, list, 3); s != want {
		t.Fatalf("summary %q", s)
	}
	if s := UnreachedSummary(Reach{Present: true, Targets: 4, Reached: 4}, nil, 0); s != "" {
		t.Fatalf("summary without unreached targets: %q", s)
	}
	all := Reach{Present: true, Targets: 2, Unreached: 2, Classes: map[string]int{ReachNoRoute: 2}}
	want = "No target was reachable from the sensor (2 target(s): no_route 2): 192.0.2.7 (timeout)"
	if s := UnreachableFailure(all, list[:1], 1); s != want {
		t.Fatalf("failure %q", s)
	}
}
