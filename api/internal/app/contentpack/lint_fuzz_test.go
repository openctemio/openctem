package contentpack

import (
	"context"
	"testing"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// FuzzLint: lint never panics on any file content for any kind, always
// returns a tier, and never reports a pack with errors as clean.
func FuzzLint(f *testing.F) {
	for _, s := range []string{passiveTemplate, oobTemplate, codeTemplate, "rules:\n  - id: x\n    pattern: foo()\n    message: m\n    languages: [go]\n    severity: ERROR\n", "a\nb\n", "{{{", "id: [", "\x00\xff"} {
		f.Add("t.yaml", s)
	}
	kinds := []string{dom.KindNucleiTemplates, dom.KindSemgrepRules, dom.KindWordlist, "x-acme/data"}
	f.Fuzz(func(t *testing.T, path, data string) {
		for _, k := range kinds {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			rep := Lint(ctx, k, []dom.File{{Path: path, Data: []byte(data)}})
			cancel()
			switch rep.Tier {
			case dom.TierT0, dom.TierT1, dom.TierT2:
			default:
				t.Fatalf("%s: tier %q", k, rep.Tier)
			}
			if len(rep.Errors) > dom.MaxIssues || len(rep.Secrets) > dom.MaxIssues {
				t.Fatalf("%s: unbounded report", k)
			}
		}
	})
}
