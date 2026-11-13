package contentrule

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fpRule(id string, ms ...Matcher) Rule {
	return Rule{ID: id, Name: id, Technology: &Technology{Name: "Thing", Category: "web_server", CPE: "cpe:2.3:a:acme:thing:{version}:*:*:*:*:*:*:*"}, Matchers: ms}
}

func secRule(id, pattern string, kws ...string) Rule {
	return Rule{ID: id, Name: id, Secret: &Secret{Category: CategoryToken, Severity: "high"},
		Matchers: []Matcher{{Location: LocBody, Keywords: kws, Pattern: pattern}}}
}

func compile(t *testing.T, kind Kind, rules ...Rule) *Engine {
	t.Helper()
	e, errs := Compile([]RuleSet{{Kind: kind, Origin: Origin{Scope: ScopePlatform, Pack: "p", Version: "1", Digest: "sha256:x"}, Rules: rules}})
	if len(errs) > 0 {
		t.Fatalf("compile: %v", errs)
	}
	return e
}

func TestValidateRefusesUnsafeOrInertRules(t *testing.T) {
	cases := map[string]struct {
		kind Kind
		rule Rule
	}{
		"backreference":         {KindSecret, secRule("r1", `(a)\1`, "abc")},
		"lookahead":             {KindSecret, secRule("r1", `a(?=b)`, "abc")},
		"empty match":           {KindSecret, secRule("r1", `a*`, "abc")},
		"too long":              {KindSecret, secRule("r1", strings.Repeat("a", MaxPatternLen+1), "abc")},
		"too complex":           {KindSecret, secRule("r1", `(?:[a-z0-9]{200}){200}`, "abc")},
		"repeat bound":          {KindSecret, secRule("r1", `a{300}`, "abc")},
		"unknown named group":   {KindSecret, secRule("r1", `(?P<other>abc)`, "abc")},
		"body without keywords": {KindSecret, secRule("r1", `abc`)},
		"short keyword":         {KindSecret, secRule("r1", `abc`, "ab")},
		"too many groups":       {KindSecret, secRule("r1", `(a)(b)(c)(d)(e)(f)(g)(h)(i)`, "abc")},
		"secret without pattern": {KindSecret, Rule{ID: "r1", Name: "r", Secret: &Secret{Category: "token", Severity: "high"},
			Matchers: []Matcher{{Location: LocBody, Keywords: []string{"abc"}}}}},
		"secret on cookie": {KindSecret, Rule{ID: "r1", Name: "r", Secret: &Secret{Category: "token", Severity: "high"},
			Matchers: []Matcher{{Location: LocCookie, Pattern: "abc"}}}},
		"secret condition all": {KindSecret, Rule{ID: "r1", Name: "r", Condition: "all", Secret: &Secret{Category: "token", Severity: "high"},
			Matchers: []Matcher{{Location: LocBody, Keywords: []string{"abc"}, Pattern: "abc"}}}},
		"bad severity":        {KindSecret, Rule{ID: "r1", Name: "r", Secret: &Secret{Category: "token", Severity: "urgent"}, Matchers: []Matcher{{Location: LocBody, Keywords: []string{"abc"}, Pattern: "abc"}}}},
		"fp without tech":     {KindFingerprint, Rule{ID: "r1", Name: "r", Matchers: []Matcher{{Location: LocTitle, Pattern: "abc"}}}},
		"bad cpe":             {KindFingerprint, Rule{ID: "r1", Name: "r", Technology: &Technology{Name: "x", CPE: "cpe:/a:x"}, Matchers: []Matcher{{Location: LocTitle, Pattern: "abc"}}}},
		"bad favicon":         {KindFingerprint, fpRule("r1", Matcher{Location: LocFavicon, Hashes: []string{"abc"}})},
		"bad id":              {KindFingerprint, fpRule("R!", Matcher{Location: LocTitle, Pattern: "abc"})},
		"control in name":     {KindFingerprint, Rule{ID: "r1", Name: "a\x00b", Technology: &Technology{Name: "x"}, Matchers: []Matcher{{Location: LocTitle, Pattern: "abc"}}}},
		"header without name": {KindFingerprint, fpRule("r1", Matcher{Location: LocHeader, Pattern: "abc"})},
	}
	for name, c := range cases {
		if err := c.rule.Validate(c.kind); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := secRule("r1", `\b(?P<secret>tok_[a-z0-9]{20})\b`, "tok_")
	if err := ok.Validate(KindSecret); err != nil {
		t.Fatalf("valid rule refused: %v", err)
	}
}

// RE2 is linear: the classic catastrophic-backtracking patterns are
// accepted and still finish on adversarial input well inside the budget.
func TestScanBacktrackingPatternsStayLinear(t *testing.T) {
	body := []byte("aaa" + strings.Repeat("a", 1<<20) + "!")
	for _, p := range []string{`(a+)+$`, `(a|aa)+b`, `(?:a*)*c`, `(.*a){20}x`} {
		e := compile(t, KindSecret, secRule("r1", p, "aaa"))
		start := time.Now()
		res := e.Scan(context.Background(), Document{Body: body}, DefaultBudget, nil)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s took %s", p, d)
		}
		if res.Truncated != true {
			t.Errorf("%s: body over the cap not reported truncated", p)
		}
	}
}

func TestScanStopsAtTheRegexRunBudget(t *testing.T) {
	var b strings.Builder
	for range 5000 {
		b.WriteString("key_ xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
	}
	rules := make([]Rule, 0, 40)
	for i := range 40 {
		rules = append(rules, secRule("r"+string(rune('a'+i%26))+string(rune('a'+i/26)), `key_[0-9]{9}`, "key_", "xxx"))
	}
	e := compile(t, KindSecret, rules...)
	res := e.Scan(context.Background(), Document{Body: []byte(b.String())}, Budget{MaxRegexRuns: 100, MaxMatches: 50, Timeout: time.Second}, nil)
	if res.Stopped != "regex_runs" {
		t.Fatalf("stopped = %q, want regex_runs", res.Stopped)
	}
}

func TestScanMasksSecrets(t *testing.T) {
	secret := "tok_abcdefghij0123456789"
	e := compile(t, KindSecret, secRule("demo-token", `\b(?P<secret>tok_[a-z0-9]{20})\b`, "tok_"))
	body := "line one\nconst k = \"" + secret + "\";\n"
	res := e.Scan(context.Background(), Document{URL: "https://a.example/app.js", Body: []byte(body)}, DefaultBudget,
		func(v string) string { return "fp:" + string(rune(len(v))) })
	if len(res.Secrets) != 1 {
		t.Fatalf("secrets = %+v", res.Secrets)
	}
	s := res.Secrets[0]
	if s.Line != 2 || s.Column != 12 || s.Length != len(secret) || s.Field != "body" || s.Fingerprint == "" {
		t.Errorf("match = %+v", s)
	}
	if s.Preview != "tok_…6789" {
		t.Errorf("preview = %q", s.Preview)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "abcdefghij") {
		t.Fatalf("result holds the secret: %s", raw)
	}
	// The same value twice is one match.
	res = e.Scan(context.Background(), Document{Body: []byte(body + body)}, DefaultBudget, nil)
	if len(res.Secrets) != 1 || res.Secrets[0].Fingerprint != "" {
		t.Errorf("dedup / no key: %+v", res.Secrets)
	}
}

func TestScanFingerprints(t *testing.T) {
	e := compile(t, KindFingerprint,
		fpRule("server-thing", Matcher{Location: LocHeader, Header: "server", Keywords: []string{"thing"}, Pattern: `(?i)^thing(?:/(?P<version>\d+(?:\.\d+){1,3}))?`}),
		Rule{ID: "both", Name: "both", Condition: "all", Technology: &Technology{Name: "Both"}, Matchers: []Matcher{
			{Location: LocCookie, Keywords: []string{"sess_a"}}, {Location: LocTitle, Keywords: []string{"portal"}}}},
		Rule{ID: "fav", Name: "fav", Technology: &Technology{Name: "Fav"}, Matchers: []Matcher{{Location: LocFavicon, Hashes: []string{"-123"}}}},
		Rule{ID: "next", Name: "next", Technology: &Technology{Name: "Next"}, Matchers: []Matcher{{Location: LocScript, Keywords: []string{"/_next/static/"}}}},
	)
	res := e.Scan(context.Background(), Document{
		Headers: map[string]string{"server": "Thing/1.25.3"}, Cookies: []string{"SESS_A"}, Title: "Acme",
		Favicon: "-123", Scripts: []string{"/_next/static/chunks/main.js"},
	}, DefaultBudget, nil)
	got := map[string]TechMatch{}
	for _, tm := range res.Technologies {
		got[tm.RuleID] = tm
	}
	if tm := got["server-thing"]; tm.Version != "1.25.3" || tm.CPE != "cpe:2.3:a:acme:thing:1.25.3:*:*:*:*:*:*:*" || tm.Confidence != DefaultConfidence || tm.Origin.Source() != "rules:p@1" {
		t.Errorf("server-thing = %+v", tm)
	}
	if _, ok := got["both"]; ok {
		t.Error("condition all matched with one matcher")
	}
	if _, ok := got["fav"]; !ok {
		t.Error("favicon not matched")
	}
	if _, ok := got["next"]; !ok {
		t.Error("script not matched")
	}
	if FillCPE("cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*", "") != "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*" {
		t.Error("empty version not *")
	}
	if FillCPE("cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*", "1:2") != "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*" {
		t.Error("a version with ':' must not break the CPE")
	}
}

func TestCompileSkipsBadRulesAndPrefixesOrganizationRules(t *testing.T) {
	good := secRule("good", `tok_[a-z]{5}`, "tok_")
	bad := secRule("bad", `(a)\1`, "abc")
	e, errs := Compile([]RuleSet{{Kind: KindSecret, Origin: Origin{Scope: ScopeOrganization}, Rules: []Rule{good, bad}}})
	if len(errs) != 1 || e.Rules() != 1 {
		t.Fatalf("errs=%v rules=%d", errs, e.Rules())
	}
	res := e.Scan(context.Background(), Document{Body: []byte("x tok_abcde y")}, DefaultBudget, nil)
	if len(res.Secrets) != 1 || res.Secrets[0].RuleID != "org.good" || res.Secrets[0].Origin.Source() != "rules:organization" {
		t.Fatalf("secrets = %+v", res.Secrets)
	}
}

func TestScanHostileInput(t *testing.T) {
	e := compile(t, KindSecret, secRule("r1", `(?P<secret>tok_.{5})`, "tok_"))
	body := []byte("tok_\xff\xfe\x00ab tok_")
	res := e.Scan(context.Background(), Document{Body: body, Title: strings.Repeat("x", 10000)}, DefaultBudget, nil)
	for _, s := range res.Secrets {
		if !strings.Contains(s.Preview, "…") && s.Preview != "" {
			t.Errorf("unsanitized preview %q", s.Preview)
		}
	}
	if !res.Truncated {
		t.Error("over-long title not reported truncated")
	}
	var nilEngine *Engine
	if r := nilEngine.Scan(context.Background(), Document{Body: body}, DefaultBudget, nil); len(r.Secrets) != 0 {
		t.Error("nil engine matched")
	}
}

func TestParseFileRefusesUnknownKeys(t *testing.T) {
	if _, err := ParseFile([]byte("schema: 1\nrules:\n  - id: a1\n    name: a\n    patern: x\n")); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := ParseFile([]byte("schema: 2\nrules: []\n")); err == nil {
		t.Error("schema 2 accepted")
	}
}
