package template

import "testing"

// TestNucleiValidator_RejectsReDoSMatcher locks in the fix: a Nuclei
// template whose matcher regex is a known ReDoS shape must fail
// validation with an UNSAFE_REGEX code, not silently pass and hand
// the scanner worker a CPU-burning pattern.
func TestNucleiValidator_RejectsReDoSMatcher(t *testing.T) {
	v := &NucleiValidator{}
	tpl := []byte(`id: redos
info:
  name: catastrophic
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        regex:
          - "(a+)+b"
`)

	res := v.Validate(tpl)
	if res.Valid {
		t.Fatal("expected validation to fail for ReDoS matcher")
	}
	foundUnsafe := false
	for _, e := range res.Errors {
		if e.Code == "UNSAFE_REGEX" {
			foundUnsafe = true
			break
		}
	}
	if !foundUnsafe {
		t.Fatalf("expected UNSAFE_REGEX error code; got errors=%v", res.Errors)
	}
}

// TestNucleiValidator_AcceptsSafeMatcher is the negative control — a
// benign matcher must NOT be flagged.
func TestNucleiValidator_AcceptsSafeMatcher(t *testing.T) {
	v := &NucleiValidator{}
	tpl := []byte(`id: safe
info:
  name: ok
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        regex:
          - "^Server: nginx/[0-9.]+"
`)

	res := v.Validate(tpl)
	for _, e := range res.Errors {
		if e.Code == "UNSAFE_REGEX" {
			t.Fatalf("benign matcher incorrectly rejected: %+v", res.Errors)
		}
	}
}
