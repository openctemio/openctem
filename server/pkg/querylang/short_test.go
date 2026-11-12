package querylang

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

func buildShort(t *testing.T, ent *Entity, src string, pr Principal) (*Plan, error) {
	t.Helper()
	q, _, err := ParseFilter(ent, src)
	if err != nil {
		return nil, err
	}
	return Build(q, src, pr, BuildOptions{Now: func() time.Time { return testNow }})
}

func docJSON(t *testing.T, doc map[string]any) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// shortCases are short texts, the document they build and their canonical
// text. The document keeps relative times relative.
var shortCases = []struct {
	src, doc, canonical string
}{
	{`severity=critical`, `{"filter":{"field":"severity","op":"in","value":"critical"},"v":1}`, `severity=critical`},
	{`severity:critical`, `{"filter":{"field":"severity","op":"in","value":"critical"},"v":1}`, `severity=critical`},
	{`SEVERITY:Critical,high`, `{"filter":{"field":"severity","op":"in","value":["critical","high"]},"v":1}`, `severity>=high`},
	{`severity>=high`, `{"filter":{"field":"severity","op":"in","value":["critical","high"]},"v":1}`, `severity>=high`},
	{`severity<medium`, `{"filter":{"field":"severity","op":"in","value":["low","info","none"]},"v":1}`, `severity<=low`},
	{`priority>P2`, `{"filter":{"field":"priority_class","op":"in","value":["P0","P1"]},"v":1}`, `priority_class>=P1`},
	{`-status:accepted`, `{"filter":{"field":"status","op":"not_in","value":"accepted"},"v":1}`, `status!=accepted`},
	{`status!=accepted,false_positive`, `{"filter":{"field":"status","op":"not_in","value":["accepted","false_positive"]},"v":1}`, `-status:accepted,false_positive`},
	{`kev=true`, `{"filter":{"field":"is_in_kev","op":"eq","value":true},"v":1}`, `is_in_kev=true`},
	{`kev!=true`, `{"filter":{"field":"is_in_kev","op":"eq","value":false},"v":1}`, `is_in_kev=false`},
	{`last_seen<7d`, `{"filter":{"field":"last_seen_at","op":"gt","value":"-P7D"},"v":1}`, `last_seen_at<7d`},
	{`age>=30d`, `{"filter":{"field":"first_detected_at","op":"lte","value":"-P30D"},"v":1}`, `first_detected_at>=30d`},
	{`last_seen<-7d`, `{"filter":{"field":"last_seen_at","op":"lt","value":"-P7D"},"v":1}`, `last_seen_at>7d`},
	{`last_seen>90m`, `{"filter":{"field":"last_seen_at","op":"lt","value":"-PT90M"},"v":1}`, `last_seen_at>90m`},
	{`first_detected_at>2026-01-01`, `{"filter":{"field":"first_detected_at","op":"gt","value":"2026-01-01"},"v":1}`, `first_detected_at>2026-01-01`},
	{`port:8000..8999`, `{"filter":{"all":[{"field":"network_port","op":"gte","value":8000},{"field":"network_port","op":"lte","value":8999}]},"v":1}`, `network_port>=8000 network_port<=8999`},
	{`port:443,8443`, `{"filter":{"field":"network_port","op":"in","value":[443,8443]},"v":1}`, `network_port:443,8443`},
	{`cvss:7..`, `{"filter":{"field":"cvss_score","op":"gte","value":7},"v":1}`, `cvss_score>=7`},
	{`epss>=0.5`, `{"filter":{"field":"epss_score","op":"gte","value":0.5},"v":1}`, `epss_score>=0.5`},
	{`domain=*.example.com`, `{"filter":{"field":"asset_domain","op":"in","value":"*.example.com"},"v":1}`, `asset.domain=*.example.com`},
	{`asset.name=api-*`, `{"filter":{"field":"asset_name","op":"in","value":"api-*"},"v":1}`, `asset.name=api-*`},
	{`ip:10.0.0.0/8,192.168.0.0/16`, `{"filter":{"field":"asset_ip","op":"in","value":["10.0.0.0/8","192.168.0.0/16"]},"v":1}`, `asset.ip:10.0.0.0/8,192.168.0.0/16`},
	{`10.0.0.0/24`, `{"filter":{"field":"asset_ip","op":"in","value":"10.0.0.0/24"},"v":1}`, `asset.ip=10.0.0.0/24`},
	{`fe80::1`, `{"filter":{"field":"asset_ip","op":"in","value":"fe80::1"},"v":1}`, `asset.ip=fe80::1`},
	{`cve-2024-3400`, `{"filter":{"field":"cve_id","op":"in","value":"CVE-2024-3400"},"v":1}`, `cve_id=CVE-2024-3400`},
	{`log4j`, `{"q":"log4j","v":1}`, `log4j`},
	{`  log4j   apache  `, `{"q":"log4j apache","v":1}`, `log4j apache`},
	{`"sql injection"`, `{"q":"sql injection","v":1}`, `sql injection`},
	{`"10.0.0.1"`, `{"q":"10.0.0.1","v":1}`, `"10.0.0.1"`},
	{`log4j severity=high apache`, `{"filter":{"field":"severity","op":"in","value":"high"},"q":"log4j apache","v":1}`, `severity=high log4j apache`},
	{`severity=high AND kev=true`, `{"filter":{"all":[{"field":"severity","op":"in","value":"high"},{"field":"is_in_kev","op":"eq","value":true}]},"v":1}`, `severity=high is_in_kev=true`},
	{`(severity=critical OR kev=true) -status:accepted`, `{"filter":{"all":[{"any":[{"field":"severity","op":"in","value":"critical"},{"field":"is_in_kev","op":"eq","value":true}]},{"field":"status","op":"not_in","value":"accepted"}]},"v":1}`, `(severity=critical OR is_in_kev=true) status!=accepted`},
	{`severity=critical or severity=high kev=true`, `{"filter":{"any":[{"field":"severity","op":"in","value":"critical"},{"all":[{"field":"severity","op":"in","value":"high"},{"field":"is_in_kev","op":"eq","value":true}]}]},"v":1}`, `severity=critical OR severity=high is_in_kev=true`},
	{`NOT (kev=true OR epss>=0.5)`, `{"filter":{"not":{"any":[{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.5}]}},"v":1}`, `-(is_in_kev=true OR epss_score>=0.5)`},
	{`assignee is empty`, `{"filter":{"field":"assigned_to","op":"is_null","value":true},"v":1}`, `assigned_to is empty`},
	{`-assignee is empty`, `{"filter":{"field":"assigned_to","op":"is_null","value":false},"v":1}`, `assigned_to is not empty`},
	{`file_path~"src/main"`, `{"filter":{"field":"file_path","op":"contains","value":"src/main"},"v":1}`, `file_path~src/main`},
	{`tool="nu*"`, `{"filter":{"field":"tool_name","op":"in","value":"nu*"},"v":1}`, `tool_name="nu*"`},
	{`tool = nuclei`, `{"filter":{"field":"tool_name","op":"in","value":"nuclei"},"v":1}`, `tool_name=nuclei`},
	{`rule="true"`, `{"filter":{"field":"rule_id","op":"in","value":"true"},"v":1}`, `rule_id="true"`},
	{`findings where severity = critical`, `{"filter":{"field":"severity","op":"in","value":"critical"},"v":1}`, `severity=critical`},
	{``, `{"v":1}`, ``},
}

func TestShortForm_Documents(t *testing.T) {
	for _, c := range shortCases {
		p, err := buildShort(t, Findings, c.src, memberAll())
		if err != nil {
			t.Errorf("%q: %v", c.src, err)
			continue
		}
		if got := docJSON(t, p.FilterDocument()); got != c.doc {
			t.Errorf("%q\n got %s\nwant %s", c.src, got, c.doc)
		}
	}
}

// Parse(Print(doc)) == doc, and printing is stable.
func TestShortForm_RoundTrip(t *testing.T) {
	for _, c := range shortCases {
		p, err := buildShort(t, Findings, c.src, memberAll())
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		doc := p.FilterDocument()
		q, err := FromDocument(Findings, doc)
		if err != nil {
			t.Fatalf("%q: FromDocument: %v", c.src, err)
		}
		text := FormatShort(Findings, q)
		if c.canonical != "" && text != c.canonical {
			t.Errorf("%q prints %q, want %q", c.src, text, c.canonical)
		}
		p2, err := buildShort(t, Findings, text, memberAll())
		if err != nil {
			t.Fatalf("%q: canonical %q does not build: %v", c.src, text, err)
		}
		if a, b := docJSON(t, doc), docJSON(t, p2.FilterDocument()); a != b {
			t.Errorf("%q: canonical %q builds %s, want %s", c.src, text, b, a)
		}
		q2, _ := FromDocument(Findings, p2.FilterDocument())
		if again := FormatShort(Findings, q2); again != text {
			t.Errorf("%q: printing not stable: %q then %q", c.src, text, again)
		}
		// The long form of the same document builds the same filter.
		long := Format(q)
		p3, err := Compile(long, memberAll(), BuildOptions{Now: func() time.Time { return testNow }})
		if err != nil {
			t.Fatalf("%q: long form %q: %v", c.src, long, err)
		}
		if a, b := docJSON(t, p.Document()), docJSON(t, p3.Document()); a != b {
			t.Errorf("%q: long form %q builds %s, want %s", c.src, long, b, a)
		}
	}
}

func TestShortForm_Problems(t *testing.T) {
	cases := []struct {
		src, code, at string
		suggest       string // one expected suggestion, if any
	}{
		{`foo=bar`, CodeUnknownField, "foo", ""},
		{`severty=high`, CodeUnknownField, "severty", "severity"},
		{`last_sen<7d`, CodeUnknownField, "last_sen", "last_seen"},
		{`severity=urgent`, CodeUnknownValue, "urgent", ""},
		{`severity=criticl`, CodeUnknownValue, "criticl", "critical"},
		{`severity>=urgent`, CodeUnknownValue, "urgent", ""},
		{`severity>critical`, CodeBadValue, "severity>critical", ""},
		{`kev~abc`, CodeOperator, "~", "="},
		{`last_seen=7d`, CodeOperator, "=", "<"},
		{`tool=nu*`, CodePattern, "nu*", ""},
		{`file_path~ab`, CodeBadValue, "ab", ""},
		{`ip=10.0.0.300`, CodeBadValue, "10.0.0.300", ""},
		{`(severity=high`, CodeSyntax, "(", ""},
		{`severity=high)`, CodeSyntax, ")", ""},
		{`severity=`, CodeSyntax, "=", ""},
		{`severity=high OR`, CodeSyntax, "OR", ""},
		{`AND kev=true`, CodeSyntax, "AND", ""},
		{`"open`, CodeSyntax, `"open`, ""},
		{`last_seen>=7d,30d`, CodeSyntax, ",", ""},
		{`assets where type = host`, CodeWrongEntity, "assets", ""},
		{`findings where severity = high | count`, CodePipeline, "| count", ""},
	}
	for _, c := range cases {
		_, err := buildShort(t, Findings, c.src, memberAll())
		qe, ok := AsError(err)
		if !ok {
			t.Errorf("%q: want a %s problem, got %v", c.src, c.code, err)
			continue
		}
		d := qe.Details[0]
		if d.Code != c.code || c.src[d.Start:d.End] != c.at {
			t.Errorf("%q: got %s at %q (%s), want %s at %q", c.src, d.Code, c.src[d.Start:d.End], d.Message, c.code, c.at)
		}
		if c.suggest != "" && !slices.Contains(d.Suggestions, c.suggest) {
			t.Errorf("%q: suggestions %v miss %q", c.src, d.Suggestions, c.suggest)
		}
	}
}

// No message repeats a value from the query.
func TestShortForm_ProblemsNeverEchoValues(t *testing.T) {
	const secret = "zzsecretzz"
	for _, src := range []string{
		`severity=` + secret, `severity>=` + secret, `ip=` + secret, `kev=` + secret, `last_seen<` + secret,
		`port=` + secret, `"` + secret, `cvss:` + secret + `..9`, `tool=` + secret + `*`, `assignee=` + secret,
		`first_detected_at>` + secret,
	} {
		_, err := buildShort(t, Findings, src, memberAll())
		qe, ok := AsError(err)
		if !ok {
			t.Errorf("%q: want a problem, got %v", src, err)
			continue
		}
		for _, d := range qe.Details {
			if strings.Contains(strings.ToLower(d.Message), secret) || slices.Contains(d.Suggestions, secret) {
				t.Errorf("%q: problem echoes the value: %+v", src, d)
			}
		}
	}
}

func TestShortForm_PermissionsAndBareTyping(t *testing.T) {
	findingsOnly := member(permission.FindingsRead.String())
	// Without assets:read a bare address stays text, a named one is unknown.
	p, err := buildShort(t, Findings, `10.0.0.1`, findingsOnly)
	if err != nil {
		t.Fatalf("bare address: %v", err)
	}
	if got := docJSON(t, p.FilterDocument()); got != `{"q":"10.0.0.1","v":1}` {
		t.Errorf("bare address without assets:read = %s", got)
	}
	// A forbidden field and a nonsense one get the same kind of answer: the
	// same code at the same place, and suggestions from usable fields only.
	answer := func(src string) ErrorDetail {
		_, err := buildShort(t, Findings, src, findingsOnly)
		qe, ok := AsError(err)
		if !ok {
			t.Fatalf("%q: want a problem, got %v", src, err)
		}
		return qe.Details[0]
	}
	forbidden, nonsense := answer(`asset.ip=10.0.0.1`), answer(`asset.iq=10.0.0.1`)
	if forbidden.Code != nonsense.Code || forbidden.Span != nonsense.Span ||
		strings.Replace(forbidden.Message, "asset.ip", "asset.iq", 1) != nonsense.Message ||
		!slices.Equal(forbidden.Suggestions, nonsense.Suggestions) {
		t.Errorf("forbidden %+v and nonsense %+v differ", forbidden, nonsense)
	}
	for _, s := range answer(`asset.ip=10.0.0.1`).Suggestions {
		if strings.HasPrefix(s, "asset.") {
			t.Errorf("suggests a forbidden field %q", s)
		}
	}
	// "Did you mean" never offers a field the caller may not use.
	if d := answer(`criticalty=high`); slices.Contains(d.Suggestions, "criticality") {
		t.Errorf("suggests the asset field criticality without assets:read: %v", d.Suggestions)
	}
	// Assets type bare addresses to ip; CVE ids stay text there.
	pa, err := buildShort(t, Assets, `192.168.1.0/24 CVE-2024-1234`, memberAll())
	if err != nil {
		t.Fatal(err)
	}
	if got := docJSON(t, pa.FilterDocument()); got != `{"filter":{"field":"ip","op":"in","value":"192.168.1.0/24"},"q":"CVE-2024-1234","v":1}` {
		t.Errorf("assets bare = %s", got)
	}
}

func TestShortForm_Limits(t *testing.T) {
	long := strings.Repeat("a", MaxQueryBytes+1)
	if _, err := buildShort(t, Findings, long, memberAll()); err == nil {
		t.Error("over-long text parsed")
	}
	many := strings.Repeat("kev=true ", 60)
	if _, err := buildShort(t, Findings, many, memberAll()); err == nil {
		t.Error("60 conditions built")
	}
	deep := strings.Repeat("(", 40) + "kev=true" + strings.Repeat(")", 40)
	if _, err := buildShort(t, Findings, deep, memberAll()); err == nil {
		t.Error("deep nesting built")
	}
	if _, err := buildShort(t, Findings, "kev=true\x00", memberAll()); err == nil {
		t.Error("control character parsed")
	}
}
