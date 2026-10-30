package template

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var badOpengrepRegexes = map[string]string{
	"nested plus":          `(a+)+$`,
	"nested star":          `(a*)*b`,
	"alt same":             `(a|a)*`,
	"alt prefix":           `(a|ab)+c`,
	"alt class overlap":    `(\d|\w)+x`,
	"star in repeat":       `(.*a){10}`,
	"word space star":      `(\w+\s*)*$`,
	"x+x+ in plus":         `(x+x+)+y`,
	"named group nested":   `(?<n>[a-z]+)+$`,
	"backref digit":        `(a)\1`,
	"backref named":        `(?P<q>['"]).*?(?P=q)`,
	"backref k":            `(?<q>a)\k<q>`,
	"too long":             strings.Repeat("a", maxOpengrepRegexLen+1),
	"lookahead nested":     `(?=x)(a+)+`,
	"unparseable":          `(`,
	"alt under counted":    `(?:ab|a){2,}`,
	"anything then nested": `^(\s*.*)*$`,
}

var goodOpengrepRegexes = []string{
	`password`,
	`(?i)api[_-]?key["\s]*[:=]["\s]*([a-z0-9]{32})`,
	`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
	`(foo|bar|baz)+`,
	`(\w+,)*\w+`,
	`(\w+\s)*done`,
	`(\d{1,3}\.){3}\d{1,3}`,
	`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`,
	`(?i)(password|passwd|secret|token)\s*[:=]\s*['"][^'"]{6,}['"]`,
	`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`,
	`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
	`(?<!\w)eval\s*\(`,
	`foo(?=bar)\w+`,
	`\bmd5\b|\bsha1\b`,
	`(?s)<script.*?</script>`,
	`https?://[^\s"']+`,
	`(?:\s+--[a-z-]+)*`,
	`a++b`,
	`\h+x`,
	`(?:[a-z]+\.)+[a-z]+`,
}

func TestCheckBacktrackingRegex_Bad(t *testing.T) {
	for name, p := range badOpengrepRegexes {
		if why := checkBacktrackingRegex(p); why == "" {
			t.Errorf("%s: %q should be rejected", name, p)
		}
	}
}

func TestCheckBacktrackingRegex_Good(t *testing.T) {
	for _, p := range goodOpengrepRegexes {
		if why := checkBacktrackingRegex(p); why != "" {
			t.Errorf("%q wrongly rejected: %s", p, why)
		}
	}
}

func ruleWith(key, regex string) []byte {
	return []byte("rules:\n  - id: r1\n    message: m\n    languages: [python]\n    severity: ERROR\n    patterns:\n      - pattern: foo($X)\n      - " + key + "\n")
}

func TestSemgrepValidator_RejectsUnsafeRegexFields(t *testing.T) {
	v := &SemgrepValidator{}
	cases := map[string]string{
		"pattern-regex":     "pattern-regex: '(a+)+$'",
		"pattern-not-regex": "pattern-not-regex: '(a|a)*'",
		"metavariable":      "metavariable-regex:\n          metavariable: $X\n          regex: '(.*a){10}'",
		"fix-regex":         "fix-regex:\n          regex: '(a+)+'\n          replacement: b",
		"backref":           `pattern-regex: '(a)\1'`,
	}
	for name, field := range cases {
		res := v.Validate(ruleWith(field, ""))
		var found bool
		for _, e := range res.Errors {
			if e.Code == "UNSAFE_REGEX" && strings.Contains(e.Field, "rules[0].patterns[1]") && strings.Contains(e.Message, "line ") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want UNSAFE_REGEX with field and line, got %+v", name, res.Errors)
		}
	}
	// the top-level pattern-regex form is checked too
	top := []byte("rules:\n  - id: r\n    message: m\n    languages: [regex]\n    severity: ERROR\n    pattern-regex: '(a+)+$'\n")
	if res := v.Validate(top); !res.HasErrors() {
		t.Error("top-level pattern-regex not checked")
	}
}

func TestSemgrepValidator_AcceptsSafeRegexFields(t *testing.T) {
	v := &SemgrepValidator{}
	for _, p := range goodOpengrepRegexes {
		doc := map[string]any{"rules": []any{map[string]any{
			"id": "r", "message": "m", "languages": []any{"python"}, "severity": "ERROR",
			"patterns": []any{
				map[string]any{"pattern-regex": p},
				map[string]any{"metavariable-regex": map[string]any{"metavariable": "$X", "regex": p}},
			},
		}}}
		b, _ := yaml.Marshal(doc)
		if res := v.Validate(b); res.HasErrors() {
			t.Errorf("%q rejected: %s", p, res.ErrorMessages())
		}
	}
}

// Every opengrep rule file shipped in this repository must pass the validator.
func TestRepoOpengrepRulesPass(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	v := &SemgrepValidator{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(data), "pattern-regex") && !strings.Contains(string(data), "metavariable-regex") {
			return nil
		}
		if res := v.Validate(data); res.HasErrors() {
			t.Errorf("%s: %s", path, res.ErrorMessages())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
