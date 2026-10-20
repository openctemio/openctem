package retestcheck

import (
	"context"
	"strings"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const okTemplate = `id: xss-search-check
info:
  name: Reflected XSS on search
  author: security-team
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
`

func codes(a *Analysis) string {
	out := make([]string, 0, len(a.Issues))
	for _, i := range a.Issues {
		out = append(out, i.Code)
	}
	return strings.Join(out, ",")
}

func TestAnalyzeTemplate_OK(t *testing.T) {
	a := AnalyzeTemplate(context.Background(), []byte(okTemplate))
	if !a.Valid() {
		t.Fatalf("issues: %+v", a.Issues)
	}
	if a.NucleiID != "xss-search-check" || a.FirstPath != "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" || a.Tier != dom.TierT0 {
		t.Fatalf("got id=%q path=%q tier=%q", a.NucleiID, a.FirstPath, a.Tier)
	}
}

// SECURITY: a check stays on the finding's target, runs no code, calls no
// third party, carries no credentials.
func TestAnalyzeTemplate_Refusals(t *testing.T) {
	cases := map[string]struct {
		body string
		code string
	}{
		"absolute url":      {strings.Replace(okTemplate, `"{{BaseURL}}/search`, `"https://evil.example/search`, 1), "OFF_TARGET"},
		"host suffix":       {strings.Replace(okTemplate, `"{{BaseURL}}/search`, `"{{BaseURL}}.evil.example/search`, 1), "OFF_TARGET"},
		"userinfo":          {strings.Replace(okTemplate, `"{{BaseURL}}/search`, `"{{BaseURL}}@evil.example/search`, 1), "OFF_TARGET"},
		"port change":       {strings.Replace(okTemplate, `"{{BaseURL}}/search`, `"{{BaseURL}}:8443/search`, 1), "OFF_TARGET"},
		"protocol-relative": {strings.Replace(okTemplate, `"{{BaseURL}}/search`, `"{{BaseURL}}//evil.example/search`, 1), "OFF_TARGET"},
		"redirects":         {strings.Replace(okTemplate, "    matchers:", "    redirects: true\n    matchers:", 1), "NOT_ALLOWED"},
		"credential header": {strings.Replace(okTemplate, "    matchers:", "    headers:\n      Authorization: Bearer abc\n    matchers:", 1), "CREDENTIAL"},
		"dns protocol":      {okTemplate + "dns:\n  - name: \"{{FQDN}}\"\n    type: A\n    matchers:\n      - type: word\n        words: [\"x\"]\n", "NOT_ALLOWED"},
		"code":              {okTemplate + "code:\n  - engine: [sh]\n    source: id\n", ""},
		"raw off host": {`id: raw-check
info:
  name: raw
  author: a
  severity: low
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: evil.example
    matchers:
      - type: status
        status: [200]
`, "OFF_TARGET"},
		"raw absolute": {`id: raw-check
info:
  name: raw
  author: a
  severity: low
http:
  - raw:
      - |
        GET http://evil.example/admin HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status: [200]
`, "OFF_TARGET"},
		"oob":      {strings.Replace(okTemplate, `/search?q=`, `/search?cb={{interactsh-url}}&q=`, 1), "OUT_OF_BAND"},
		"empty":    {"", "EMPTY"},
		"not yaml": {"::: not yaml", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := AnalyzeTemplate(context.Background(), []byte(tc.body))
			if a.Valid() {
				t.Fatalf("accepted: %+v", a)
			}
			if tc.code != "" && !strings.Contains(codes(a), tc.code) {
				t.Fatalf("want %s, got %s (%+v)", tc.code, codes(a), a.Issues)
			}
		})
	}
}

func TestAnalyzeTemplate_RawOnTarget(t *testing.T) {
	a := AnalyzeTemplate(context.Background(), []byte(`id: raw-check
info:
  name: raw
  author: a
  severity: low
http:
  - raw:
      - |
        GET /admin?x=1 HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status: [200]
`))
	if !a.Valid() || a.FirstPath != "/admin?x=1" {
		t.Fatalf("got %+v", a)
	}
}

func TestAnalyzeTemplate_IntrusiveIsT2(t *testing.T) {
	body := strings.Replace(okTemplate, "method: GET", "method: DELETE", 1)
	a := AnalyzeTemplate(context.Background(), []byte(body))
	if !a.Valid() || a.Tier != dom.TierT2 {
		t.Fatalf("want a valid T2 check, got tier=%q issues=%+v", a.Tier, a.Issues)
	}
}

func TestCompiledAssertionPassesRules(t *testing.T) {
	as := &dom.HTTPAssertion{Method: "GET", Path: "/admin", Matchers: []dom.Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Part: "body", Words: []string{"Django administration"}},
	}}
	content, err := as.Compile("0f0e0d0c-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	a := AnalyzeTemplate(context.Background(), content)
	if !a.Valid() || a.FirstPath != "/admin" || a.NucleiID != "retest-check-0f0e0d0c0000" {
		t.Fatalf("got %+v\n%s", a, content)
	}
}

func TestValidate_AssertionFieldsNamedFromBody(t *testing.T) {
	svc := &Service{}
	v, err := svc.validate(context.Background(), shared.NewID(), shared.NewID(), Input{Kind: dom.KindHTTPAssertion,
		Assertion: &dom.HTTPAssertion{Method: "GET", Path: "x", Matchers: []dom.Matcher{{Type: "status", Status: []int{200}}}}})
	if err != nil || v.Valid || len(v.Issues) == 0 || v.Issues[0].Field != "assertion.path" {
		t.Fatalf("got %+v %v", v, err)
	}
}
