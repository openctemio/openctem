package licensepolicy

import (
	"errors"
	"strings"
	"testing"
)

var cat = Catalog{
	"mit": "permissive", "apache-2.0": "permissive", "bsd-3-clause": "permissive",
	"gpl-2.0-only": "copyleft", "gpl-3.0": "copyleft", "gpl-3.0-only": "copyleft", "agpl-3.0": "copyleft",
	"lgpl-2.1-only": "weak_copyleft", "cc0-1.0": "public_domain",
}

func policy(t *testing.T, p Policy) *Policy {
	t.Helper()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestParse(t *testing.T) {
	n, err := Parse("MIT OR (GPL-2.0-only WITH Classpath-exception-2.0 AND bsd-3-clause)")
	if err != nil {
		t.Fatal(err)
	}
	if n.Op != OpOr || len(n.Children) != 2 || n.Children[1].Op != OpAnd ||
		n.Children[1].Children[0].Exception != "Classpath-exception-2.0" {
		t.Fatalf("tree: %+v", n)
	}
	if n, err := Parse("MIT and Apache-2.0 or ISC"); err != nil || n.Op != OpOr || n.Children[0].Op != OpAnd {
		t.Fatalf("AND binds tighter than OR, case-insensitive operators: %+v %v", n, err)
	}
	for _, bad := range []string{"", "MIT OR", "(MIT", "MIT)", "MIT WITH", "AND", "Apache 2.0", "MIT WITH A WITH B",
		"MIT;rm", strings.Repeat("(", 40) + "MIT" + strings.Repeat(")", 40), strings.Repeat("MIT OR ", 100) + "MIT"} {
		if _, err := Parse(bad); !errors.Is(err, ErrExpression) {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"MIT", "MIT OR Apache-2.0", "(A AND B) OR C WITH D", "((((", "GPL-2.0+"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := &Policy{Enabled: true}
		_ = p.Normalize()
		v := p.Evaluate([]string{s}, "", cat)
		if v.Action.rank() < 0 {
			t.Fatalf("no verdict for %q", s)
		}
	})
}

func TestEvaluate(t *testing.T) {
	p := policy(t, Policy{Enabled: true, Unknown: ActionDeny, Rules: []Rule{
		{Match: "GPL-3.0-only", Action: ActionDeny},
		{Match: "category:copyleft", Action: ActionDeny},
		{Match: "category:copyleft", Action: ActionAllow, Scopes: []string{"test", "development"}},
		{Match: "category:weak_copyleft", Action: ActionReview},
		{Match: "GPL-2.0-only WITH Classpath-exception-2.0", Action: ActionAllow},
		{Match: "LicenseRef-acme", Action: ActionAllow},
	}})
	cases := []struct {
		licenses []string
		scope    string
		want     Action
		rule     string
	}{
		{[]string{"MIT"}, "", ActionAllow, "default"},
		{[]string{"GPL-3.0-only"}, "runtime", ActionDeny, "GPL-3.0-only"},
		// OR: the most permissive allowed choice.
		{[]string{"MIT OR GPL-3.0-only"}, "", ActionAllow, "default"},
		{[]string{"GPL-3.0-only OR MIT"}, "", ActionAllow, "default"},
		// AND: every term must be acceptable.
		{[]string{"MIT AND GPL-3.0-only"}, "", ActionDeny, "GPL-3.0-only"},
		// Several declared licenses: all must be acceptable.
		{[]string{"MIT", "LGPL-2.1-only"}, "", ActionReview, "category:weak_copyleft"},
		// Category rule, and a scope-limited rule that does not apply at runtime.
		{[]string{"AGPL-3.0"}, "runtime", ActionDeny, "category:copyleft"},
		// The first matching rule wins: the runtime-wide deny comes first.
		{[]string{"AGPL-3.0"}, "test", ActionDeny, "category:copyleft"},
		// WITH exception: the exact rule first.
		{[]string{"GPL-2.0-only WITH Classpath-exception-2.0"}, "", ActionAllow, "GPL-2.0-only WITH Classpath-exception-2.0"},
		{[]string{"GPL-2.0-only WITH Other-exception"}, "", ActionDeny, "category:copyleft"},
		// "+" falls back to the base id.
		{[]string{"GPL-3.0-only+"}, "", ActionDeny, "GPL-3.0-only"},
		// Unknown: not an SPDX license the catalog knows, free text, none.
		{[]string{"LicenseRef-other"}, "", ActionDeny, "unknown"},
		{[]string{"LicenseRef-acme"}, "", ActionAllow, "LicenseRef-acme"},
		{[]string{"Apache License 2.0"}, "", ActionDeny, "unknown"},
		{nil, "", ActionDeny, "unknown"},
		{[]string{"cc0-1.0"}, "", ActionAllow, "default"},
	}
	for _, c := range cases {
		v := p.Evaluate(c.licenses, c.scope, cat)
		if v.Action != c.want || v.Rule != c.rule {
			t.Errorf("Evaluate(%v, %q) = %+v, want %s by %s", c.licenses, c.scope, v, c.want, c.rule)
		}
	}

	// A test-scope allow placed before the deny applies only to test.
	p2 := policy(t, Policy{Enabled: true, Rules: []Rule{
		{Match: "category:copyleft", Action: ActionAllow, Scopes: []string{"test"}},
		{Match: "category:copyleft", Action: ActionDeny},
	}})
	if v := p2.Evaluate([]string{"GPL-3.0"}, "test", cat); v.Action != ActionAllow {
		t.Errorf("copyleft in a test dependency: %+v", v)
	}
	if v := p2.Evaluate([]string{"GPL-3.0"}, "", cat); v.Action != ActionDeny {
		t.Errorf("copyleft at runtime (no scope counts as runtime): %+v", v)
	}
	if !p2.Opens(ActionDeny) || p2.Opens(ActionReview) {
		t.Error("deny opens a finding, review only on opt-in")
	}
	p2.ReviewFindings = true
	if !p2.Opens(ActionReview) || p2.Opens(ActionAllow) {
		t.Error("review opens a finding with review_findings")
	}
}

func TestNormalize(t *testing.T) {
	p := Policy{Rules: []Rule{{Match: " Category:Copyleft ", Action: ActionDeny, Scopes: []string{"Test", "test"}}}}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Default != ActionAllow || p.Unknown != ActionReview || p.Rules[0].Match != "category:copyleft" ||
		len(p.Rules[0].Scopes) != 1 {
		t.Fatalf("defaults and cleaning: %+v", p)
	}
	for name, bad := range map[string]Policy{
		"default deny":   {Default: ActionDeny},
		"unknown allow":  {Unknown: ActionAllow},
		"bad action":     {Rules: []Rule{{Match: "MIT", Action: "block"}}},
		"bad category":   {Rules: []Rule{{Match: "category:viral", Action: ActionDeny}}},
		"bad match":      {Rules: []Rule{{Match: "MIT OR GPL-3.0", Action: ActionDeny}}},
		"bad scope":      {Rules: []Rule{{Match: "MIT", Action: ActionDeny, Scopes: []string{"prod"}}}},
		"empty match":    {Rules: []Rule{{Match: " ", Action: ActionDeny}}},
		"too many rules": {Rules: make([]Rule, MaxRules+1)},
		"injection":      {Rules: []Rule{{Match: "MIT'); DROP TABLE x;--", Action: ActionDeny}}},
	} {
		if err := bad.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}
