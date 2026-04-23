package template

import "testing"

// TestNucleiValidator_BlocksCodeProtocol locks in the fix for the
// blocklist gap where Nuclei's `code:` protocol (and its siblings
// `javascript:` / `headless:`) were accepted because the earlier
// blocklist only caught shell one-liners. A template that declares
// `code: engine: sh source: <arbitrary>` executes the source string
// on the scanner host by design — the validator MUST reject it before
// dispatch.
func TestNucleiValidator_BlocksCodeProtocol(t *testing.T) {
	v := &NucleiValidator{}

	cases := []struct {
		name    string
		content string
	}{
		{
			name: "code protocol top-level key",
			content: `id: pwn
info:
  name: benign-looking
  severity: info
code:
  - engine: sh
    source: |
      id
`,
		},
		{
			name: "headless protocol",
			content: `id: pwn
info: { name: x, severity: info }
headless:
  - steps:
      - action: script
        args:
          code: "alert(1)"
`,
		},
		{
			name: "javascript protocol",
			content: `id: pwn
info: { name: x, severity: info }
javascript:
  - code: "new Function('return 1')()"
`,
		},
		{
			name: "protocol: code explicit field",
			content: `id: pwn
info: { name: x, severity: info }
protocol: code
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !v.hasDangerousPatterns([]byte(tc.content)) {
				t.Fatalf("validator accepted template with dangerous protocol; content:\n%s", tc.content)
			}
		})
	}
}

// TestNucleiValidator_BenignTemplateAccepted guards against false
// positives — a plain HTTP matcher-only template must still pass. The
// `code:` substring anchored with a preceding newline prevents the
// blocklist from catching words like "encoded:" or "barcode:".
func TestNucleiValidator_BenignTemplateAccepted(t *testing.T) {
	v := &NucleiValidator{}

	benign := `id: cve-2024-1234
info:
  name: Example product SSRF
  severity: high
  tags: cve,ssrf
  description: innocuous-code-path
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/healthz"
    matchers:
      - type: status
        status: [200]
`
	if v.hasDangerousPatterns([]byte(benign)) {
		t.Fatal("validator rejected benign template — blocklist too aggressive")
	}
}
