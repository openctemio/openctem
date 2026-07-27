package semgrep

import (
	"encoding/json"
	"testing"
)

// semgrep's own schema (semgrep_output_v1.atd) declares core_error.type as a
// CONSTRUCTOR, which serializes as an ARRAY — e.g.
//
//	"type": ["PartialParsing", [{"path": "a.go", ...}]]
//
// Real semgrep emits exactly this whenever a file only partially parses, which
// is routine on large or mixed-language repos.
//
// Typing that field as a Go string made json.Unmarshal fail for the WHOLE
// document, so Convert returned an error and CanConvert returned false: every
// finding in that scan was discarded and the upload was rejected as
// "could not auto-detect scanner format". Same class as the KEV `cwes` bug.
const partialParsingOutput = `{
  "version": "1.149.0",
  "errors": [
    {
      "code": 3,
      "level": "warn",
      "message": "Syntax error at line a.go:12",
      "type": ["PartialParsing", [{"path": "a.go", "start": {"line": 12, "col": 1}}]]
    }
  ],
  "results": [
    {
      "check_id": "go.lang.security.audit.dangerous-exec",
      "path": "cmd/main.go",
      "start": {"line": 10, "col": 2},
      "end": {"line": 10, "col": 40},
      "extra": {"message": "dangerous exec", "severity": "ERROR", "lines": "exec.Command(x)"}
    }
  ]
}`

func TestSemgrepOutput_PartialParsingDoesNotDiscardTheScan(t *testing.T) {
	var out SemgrepOutput
	if err := json.Unmarshal([]byte(partialParsingOutput), &out); err != nil {
		t.Fatalf("a partially-parsed file must not sink the whole report: %v", err)
	}

	// The findings — the only thing we actually consume — must survive.
	if len(out.Results) != 1 {
		t.Fatalf("results = %d, want 1 (the finding alongside the parse warning)", len(out.Results))
	}
	if got := out.Results[0].CheckID; got != "go.lang.security.audit.dangerous-exec" {
		t.Errorf("check_id = %q, want the real rule id", got)
	}
}

// The ordinary scalar form must keep working — semgrep emits a plain string for
// error types that carry no payload.
func TestSemgrepOutput_ScalarErrorTypeStillParses(t *testing.T) {
	const scalar = `{"errors":[{"code":2,"level":"error","message":"boom","type":"SemgrepError"}],"results":[]}`
	var out SemgrepOutput
	if err := json.Unmarshal([]byte(scalar), &out); err != nil {
		t.Fatalf("scalar error type must still parse: %v", err)
	}
}
