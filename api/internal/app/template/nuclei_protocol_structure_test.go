package template

import "testing"

// The code/javascript/headless blocklist matched the YAML literal "\ncode:",
// so the same template written as JSON (valid YAML, and a format nuclei
// loads) or as a YAML flow mapping passed validation. The check now runs on
// the parsed document, whatever its surface syntax.
func TestNucleiValidator_ExecProtocolsRejectedInAnySyntax(t *testing.T) {
	v := &NucleiValidator{}

	cases := map[string]string{
		"json code": `{"id":"pwn","info":{"name":"x","severity":"info"},` +
			`"code":[{"engine":["sh"],"source":"id"}]}`,
		"json javascript": `{"id":"pwn","info":{"name":"x","severity":"info"},` +
			`"javascript":[{"code":"1"}]}`,
		"json headless": `{"id":"pwn","info":{"name":"x","severity":"info"},` +
			`"headless":[{"steps":[{"action":"navigate"}]}]}`,
		"json with spaces before colon": `{"id": "pwn", "info": {"name": "x", "severity": "info"}, ` +
			`"code" : [{"engine": ["sh"], "source": "id"}]}`,
		"json unicode-escaped key": `{"id":"pwn","info":{"name":"x","severity":"info"},` +
			`"code":[{"engine":["sh"],"source":"id"}]}`,
		"json upper-case key (encoding/json matches it case-insensitively)": `{"id":"pwn",` +
			`"info":{"name":"x","severity":"info"},"CODE":[{"engine":["sh"],"source":"id"}]}`,
		"yaml flow mapping": `{id: pwn, info: {name: x, severity: info}, code: [{engine: [sh], source: id}]}`,
		"yaml first-line key": `code:
  - engine: [sh]
    source: id
id: pwn
info: {name: x, severity: info}
`,
		"yaml merge key": `base: &b
  code:
    - engine: [sh]
      source: id
id: pwn
info: {name: x, severity: info}
<<: *b
`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			res := v.Validate([]byte(content))
			if !hasErrorCode(res, "DANGEROUS_PATTERN") {
				t.Fatalf("template with an exec protocol was not rejected as dangerous: %+v", res.Errors)
			}
		})
	}
}

// A plain JSON HTTP template is still accepted.
func TestNucleiValidator_BenignJSONTemplateAccepted(t *testing.T) {
	v := &NucleiValidator{}
	res := v.Validate([]byte(`{"id":"ok","info":{"name":"barcode encoder","severity":"low",` +
		`"description":"checks the code path"},"http":[{"method":"GET","path":["{{BaseURL}}/"],` +
		`"matchers":[{"type":"status","status":[200]}]}]}`))
	if res.HasErrors() {
		t.Fatalf("benign JSON template rejected: %+v", res.Errors)
	}
}

func hasErrorCode(res *ValidationResult, code string) bool {
	for _, e := range res.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}
