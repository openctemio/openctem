package contentpack

import (
	"context"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

const goodSecretRules = `schema: 1
rules:
  - id: demo-token
    name: Demo token
    secret: {category: token, severity: high}
    matchers:
      - location: body
        keywords: [tok_]
        pattern: '\btok_[a-z0-9]{20}\b'
`

func TestLintRulePacks(t *testing.T) {
	ctx := context.Background()
	rep := Lint(ctx, dom.KindSecretRules, []dom.File{{Path: "rules.yaml", Data: []byte(goodSecretRules)}, {Path: "NOTICE", Data: []byte("ours")}})
	if len(rep.Errors) != 0 || rep.Items != 1 || rep.Tier != dom.TierT0 {
		t.Fatalf("good pack: %+v", rep)
	}
	// The same rule in two files, a rule of the wrong kind's shape, an
	// unsafe pattern and an unknown key are refused.
	bad := map[string]string{
		"duplicate":  goodSecretRules,
		"wrong-kind": "schema: 1\nrules:\n  - id: x1\n    name: x\n    technology: {name: nginx}\n    matchers:\n      - location: title\n        pattern: nginx\n",
		"unsafe":     "schema: 1\nrules:\n  - id: x2\n    name: x\n    secret: {category: token, severity: high}\n    matchers:\n      - location: body\n        keywords: [abc]\n        pattern: '(a)\\1'\n",
		"unknown":    "schema: 1\nrules:\n  - id: x3\n    name: x\n    regex: abc\n",
	}
	for name, body := range bad {
		rep := Lint(ctx, dom.KindSecretRules, []dom.File{{Path: "rules.yaml", Data: []byte(goodSecretRules)}, {Path: name + ".yaml", Data: []byte(body)}})
		if len(rep.Errors) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if rep := Lint(ctx, dom.KindWebFingerprints, []dom.File{{Path: "NOTICE", Data: []byte("x")}}); len(rep.Errors) == 0 {
		t.Error("a rule pack without rules is accepted")
	}
	if err := dom.ValidateTenantKind(dom.KindSecretRules); err == nil {
		t.Error("an organization may upload a rule pack")
	}
	if err := dom.ValidateTenantKind(dom.KindNucleiTemplates); err != nil {
		t.Error(err)
	}
}
