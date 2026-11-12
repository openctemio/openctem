package contentpack

import (
	"context"
	"strings"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

func regexRule(regex string) []byte {
	return []byte("rules:\n  - id: r1\n    message: m\n    languages: [python]\n    severity: ERROR\n    pattern-regex: '" + regex + "'\n")
}

func TestLintSemgrepRejectsBacktrackingRegex(t *testing.T) {
	for _, bad := range []string{`(a+)+$`, `(a|a)*`, `(.*a){10}`, `(a)\1`} {
		rep := Lint(context.Background(), dom.KindSemgrepRules, []dom.File{{Path: "r.yaml", Data: regexRule(bad)}})
		var ok bool
		for _, e := range rep.Errors {
			if e.Code == "UNSAFE_REGEX" && strings.Contains(e.Message, "line 6") {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%q: want UNSAFE_REGEX error with line, got %+v", bad, rep.Errors)
		}
	}
	rep := Lint(context.Background(), dom.KindSemgrepRules, []dom.File{{Path: "r.yaml", Data: regexRule(`(\w+,)*\w+`)}})
	if len(rep.Errors) != 0 {
		t.Errorf("safe regex rejected: %+v", rep.Errors)
	}
}
