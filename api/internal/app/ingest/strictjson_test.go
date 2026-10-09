package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

const v2TestReportID = "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"

// v2ValidReport is a minimal complete v2 segment.
const v2ValidReport = `{
  "version": "1.0",
  "metadata": {"id": "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b", "timestamp": "2026-10-01T12:00:00Z", "coverage_type": "full"},
  "tool": {"name": "semgrep", "version": "1.90.0"},
  "assets": [{"id": "a1", "type": "repository", "value": "github.com/acme/app"}],
  "findings": [{"type": "vulnerability", "title": "SQL injection", "severity": "high", "rule_id": "r1", "asset_ref": "a1",
                "properties": {"n": 1.5, "s": "café 😀"}}]
}`

func TestCheckIJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"valid", v2ValidReport, nil},
		{"duplicate key top level", `{"version":"1.0","version":"2.0"}`, ErrJSONDuplicateMember},
		{"duplicate key nested", `{"a":{"b":1,"b":2}}`, ErrJSONDuplicateMember},
		{"duplicate key via escape", `{"a":1,"a":2}`, ErrJSONDuplicateMember},
		{"same key in sibling objects is fine", `{"x":[{"a":1},{"a":2}],"y":{"a":3}}`, nil},
		{"lone high surrogate", `{"a":"\ud800"}`, ErrJSONLoneSurrogate},
		{"lone low surrogate", `{"a":"\udc00"}`, ErrJSONLoneSurrogate},
		{"high then non-low", `{"a":"\ud800A"}`, ErrJSONLoneSurrogate},
		{"surrogate pair ok", `{"a":"😀"}`, nil},
		{"escaped backslash then u", `{"a":"\\ud800"}`, nil},
		{"invalid utf8", "{\"a\":\"\xff\"}", ErrJSONInvalidUTF8},
		{"number overflow", `{"a":1E400}`, ErrJSONNumberRange},
		{"trailing garbage", `{"a":1} x`, ErrJSONSyntax},
		{"second object", `{"a":1}{"b":2}`, ErrJSONTrailingData},
		{"trailing whitespace ok", "{\"a\":1}\n\t ", nil},
		{"top-level array", `[1]`, ErrJSONNotObject},
		{"top-level string", `"x"`, ErrJSONNotObject},
		{"empty", ``, ErrJSONSyntax},
		{"unterminated", `{"a":1`, ErrJSONSyntax},
		{"trailing comma", `{"a":1,}`, ErrJSONSyntax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckIJSON([]byte(c.in), 64); !errors.Is(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestCheckIJSON_Depth(t *testing.T) {
	nest := func(n int) string {
		// n levels: the top-level object is level 1.
		return strings.Repeat(`{"a":`, n-1) + "{}" + strings.Repeat("}", n-1)
	}
	if err := CheckIJSON([]byte(nest(64)), 64); err != nil {
		t.Fatalf("depth 64: %v", err)
	}
	if err := CheckIJSON([]byte(nest(65)), 64); !errors.Is(err, ErrJSONTooDeep) {
		t.Fatalf("depth 65: %v", err)
	}
	arr := `{"a":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + "}"
	if err := CheckIJSON([]byte(arr), 64); !errors.Is(err, ErrJSONTooDeep) {
		t.Fatalf("array depth 65: %v", err)
	}
}

func TestParseV2Report(t *testing.T) {
	limits := protov2.DefaultLimits()
	r, err := ParseV2Report([]byte(v2ValidReport), v2TestReportID, limits)
	if err != nil {
		t.Fatalf("valid report: %v", err)
	}
	if r.Tool.Name != "semgrep" || len(r.Findings) != 1 {
		t.Fatalf("decoded %+v", r)
	}

	replace := func(old, new string) string {
		if !strings.Contains(v2ValidReport, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(v2ValidReport, old, new, 1)
	}
	cases := []struct {
		name    string
		in      string
		problem protov2.ProblemType
		pointer string
	}{
		{"unknown field", replace(`"version": "1.0",`, `"version": "1.0", "tenant_id": "x",`), protov2.ProblemSchemaInvalid, ""},
		{"unknown nested field", replace(`"rule_id": "r1"`, `"rule_id": "r1", "sensor_id": "x"`), protov2.ProblemSchemaInvalid, ""},
		{"wrapped form refused", `{"report":` + v2ValidReport + `}`, protov2.ProblemSchemaInvalid, ""},
		{"wrong type", replace(`"version": "1.0"`, `"version": 1`), protov2.ProblemSchemaInvalid, ""},
		{"duplicate key", replace(`"version": "1.0",`, `"version": "1.0", "version": "1.0",`), protov2.ProblemInvalidJSON, ""},
		{"version major 2", replace(`"version": "1.0"`, `"version": "2.0"`), protov2.ProblemVersionMismatch, ""},
		{"version missing", replace(`"version": "1.0",`, ``), protov2.ProblemSchemaInvalid, "/version"},
		{"tool missing", replace(`"tool": {"name": "semgrep", "version": "1.90.0"},`, ``), protov2.ProblemSchemaInvalid, "/tool/name"},
		{"tool name empty", replace(`"name": "semgrep"`, `"name": " "`), protov2.ProblemSchemaInvalid, "/tool/name"},
		{"metadata id differs", replace(`"id": "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"`, `"id": "other"`), protov2.ProblemSchemaInvalid, "/metadata/id"},
		{"bad severity", replace(`"severity": "high"`, `"severity": "urgent"`), protov2.ProblemSchemaInvalid, "/findings/0/severity"},
		{"bad finding type", replace(`"type": "vulnerability"`, `"type": "nope"`), protov2.ProblemSchemaInvalid, "/findings/0/type"},
		{"missing title", replace(`"title": "SQL injection"`, `"title": ""`), protov2.ProblemSchemaInvalid, "/findings/0/title"},
		{"bad asset type", replace(`"type": "repository"`, `"type": "spaceship"`), protov2.ProblemSchemaInvalid, "/assets/0/type"},
		{"asset value missing", replace(`"value": "github.com/acme/app"`, `"value": ""`), protov2.ProblemSchemaInvalid, "/assets/0/value"},
		// An endpoint parameter never carries a value: a value member is a
		// schema error, not ignored (RFC-056).
		{"endpoint param value", replace(`"version": "1.0",`, `"version": "1.0", "endpoints": [{"origin": "https://a.example.com", "path": "/x",
			"params": [{"location": "query", "name": "token", "value": "SECRET"}]}],`), protov2.ProblemSchemaInvalid, ""},
		{"duplicate asset id", replace(`"assets": [`, `"assets": [{"id": "a1", "type": "domain", "value": "x.example"},`), protov2.ProblemSchemaInvalid, "/assets/1/id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseV2Report([]byte(c.in), v2TestReportID, limits)
			var re *V2ReportError
			if !errors.As(err, &re) {
				t.Fatalf("got %v", err)
			}
			if re.Problem != c.problem {
				t.Fatalf("problem %s, want %s", re.Problem, c.problem)
			}
			if c.pointer != "" {
				found := false
				for _, e := range re.Errors {
					if e.Pointer == c.pointer {
						found = true
					}
				}
				if !found {
					t.Fatalf("no error at %s: %+v", c.pointer, re.Errors)
				}
			}
		})
	}

	// metadata.id may be empty.
	if _, err := ParseV2Report([]byte(replace(`"id": "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b", `, ``)), v2TestReportID, limits); err != nil {
		t.Fatalf("empty metadata.id: %v", err)
	}
}

func TestParseV2Report_SegmentLimits(t *testing.T) {
	limits := protov2.DefaultLimits()
	limits.MaxFindingsPerSegment = 2
	limits.MaxAssetsPerSegment = 1
	f := `{"type":"vulnerability","title":"t","severity":"low","asset_ref":"a1"}`
	tooManyFindings := strings.Replace(v2ValidReport, `"findings": [`, `"findings": [`+f+","+f+",", 1)
	_, err := ParseV2Report([]byte(tooManyFindings), v2TestReportID, limits)
	var re *V2ReportError
	if !errors.As(err, &re) || re.Problem != protov2.ProblemReportTooLarge {
		t.Fatalf("findings: %v", err)
	}
	tooManyAssets := strings.Replace(v2ValidReport, `"assets": [`, `"assets": [{"id":"a2","type":"domain","value":"x.example"},`, 1)
	if _, err := ParseV2Report([]byte(tooManyAssets), v2TestReportID, limits); !errors.As(err, &re) || re.Problem != protov2.ProblemReportTooLarge {
		t.Fatalf("assets: %v", err)
	}
}

func TestValidateReportV2_ErrorsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"1.0","metadata":{"timestamp":"2026-10-01T12:00:00Z"},"tool":{"name":"t"},"findings":[`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"type":"vulnerability","title":"","severity":"bad"}`)
	}
	b.WriteString("]}")
	_, err := ParseV2Report([]byte(b.String()), v2TestReportID, protov2.DefaultLimits())
	var re *V2ReportError
	if !errors.As(err, &re) || len(re.Errors) != protov2.MaxItemErrors {
		t.Fatalf("got %v", err)
	}
	// Details are fixed templates: no sensor bytes.
	for _, e := range re.Errors {
		if strings.Contains(e.Detail, "bad") {
			t.Fatalf("detail quotes input: %q", e.Detail)
		}
	}
}

// FuzzStrictCTIS: the strict decoder never panics, and whatever it accepts is
// a document encoding/json accepts too, in valid UTF-8, so the two parsers
// cannot read different reports from one accepted body.
func FuzzStrictCTIS(f *testing.F) {
	seeds := []string{
		v2ValidReport,
		`{"version":"1.0","version":"1.0"}`,
		`{"a":"\ud800"}`,
		`{"a":1E400}`,
		`{"a":1} x`,
		`{"report":{"version":"1.0"}}`,
		"{\"a\":\"\xff\"}",
		`{"version":"1.0","metadata":{"timestamp":"2026-10-01T12:00:00Z"},"tool":{"name":"x"},"assets":[],"findings":[]}`,
		strings.Repeat(`{"a":`, 70) + "1" + strings.Repeat("}", 70),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		report, err := DecodeStrictReport(data, protov2.DefaultMaxJSONDepth, ReportBounds(protov2.DefaultLimits()))
		if err != nil {
			return
		}
		if !json.Valid(data) || !utf8.Valid(data) {
			t.Fatalf("strict decoder accepted what encoding/json rejects: %q", data)
		}
		if report == nil {
			t.Fatal("nil report without error")
		}
		_, _ = ParseV2Report(data, v2TestReportID, protov2.DefaultLimits())
	})
}

func TestCheckIJSONBounded(t *testing.T) {
	b := JSONBounds{TopArrays: map[string]int{"findings": 2}, MaxArrayLen: 3, MaxContainers: 8, MaxValues: 12}
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"within every bound", `{"findings":[{},{}],"x":[1,2,3]}`, nil},
		{"top-level array over its own bound", `{"findings":[{},{},{}]}`, ErrJSONTooManyItems},
		{"other top-level array uses MaxArrayLen", `{"assets":[1,2,3]}`, nil},
		{"other top-level array over MaxArrayLen", `{"assets":[1,2,3,4]}`, ErrJSONTooManyItems},
		{"nested array named findings is not top-level", `{"a":{"findings":[1,2,3]}}`, nil},
		{"nested array over MaxArrayLen", `{"a":[[1,2,3,4]]}`, ErrJSONTooManyItems},
		{"too many containers", `{"a":{},"b":{},"c":{},"d":{},"e":{},"f":{},"g":{},"h":{}}`, ErrJSONTooManyItems},
		{"too many values", `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10,"k":11,"l":12}`, ErrJSONTooManyItems},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckIJSONBounded([]byte(c.in), 64, b); !errors.Is(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	// The unbounded pre-pass is unchanged.
	if err := CheckIJSON([]byte(`{"findings":[{},{},{},{},{}]}`), 64); err != nil {
		t.Fatalf("CheckIJSON: %v", err)
	}
}

// A segment over its item limit is refused as report-too-large before it is
// decoded (the decoded structs of a flood of empty objects are ~280 times
// the body).
func TestParseV2Report_ItemFloodIsTooLargeBeforeDecode(t *testing.T) {
	limits := protov2.DefaultLimits()
	limits.MaxFindingsPerSegment = 10
	flood := `{"version":"1.0","metadata":{"timestamp":"2026-10-01T12:00:00Z"},"tool":{"name":"semgrep"},"findings":[` +
		strings.TrimSuffix(strings.Repeat("{},", 11), ",") + `]}`
	_, err := ParseV2Report([]byte(flood), v2TestReportID, limits)
	var verr *V2ReportError
	if !errors.As(err, &verr) || verr.Problem != protov2.ProblemReportTooLarge {
		t.Fatalf("err = %v, want report-too-large", err)
	}
	// Ten findings are within the limit.
	ok := strings.Replace(flood, "{},{}]", "{}]", 1)
	if _, err := DecodeStrictReport([]byte(ok), 64, ReportBounds(limits)); err != nil {
		t.Fatalf("10 findings: %v", err)
	}
}
