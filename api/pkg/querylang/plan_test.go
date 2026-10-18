package querylang

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

var (
	testTenant = shared.MustIDFromString("11111111-1111-1111-1111-111111111111")
	testUser   = shared.MustIDFromString("22222222-2222-2222-2222-222222222222")
	testNow    = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
)

func hasAll(string) bool { return true }

func hasOnly(perms ...string) func(string) bool {
	return func(p string) bool {
		for _, x := range perms {
			if x == p {
				return true
			}
		}
		return false
	}
}

// member is a restricted member holding perms.
func member(perms ...string) Principal {
	return Principal{TenantID: testTenant, UserID: testUser,
		Scope: &shared.DataScope{TenantID: testTenant, UserID: testUser}, Has: hasOnly(perms...)}
}

func memberAll() Principal {
	return Principal{TenantID: testTenant, UserID: testUser,
		Scope: &shared.DataScope{TenantID: testTenant, UserID: testUser}, Has: hasAll}
}

func build(t *testing.T, src string, pr Principal) (*Plan, error) {
	t.Helper()
	return Compile(src, pr, BuildOptions{Now: func() time.Time { return testNow }})
}

func mustBuild(t *testing.T, src string, pr Principal) *Plan {
	t.Helper()
	p, err := build(t, src, pr)
	if err != nil {
		t.Fatalf("Compile(%q): %v", src, err)
	}
	return p
}

func TestBuildErrors(t *testing.T) {
	cases := []struct {
		src, at, msg string
	}{
		{"widgets | count", "widgets", "unknown entity"},
		{"findings where tenant_id = x", "tenant_id", "unknown field"},
		{"findings where program_asset = true", "program_asset", "unknown field"},
		{"findings where asset_type = domain", "asset_type", "unknown field"}, // relation fields only by path
		{"assets where deleted = true", "deleted", "unknown field"},
		{"assets where program_only = false", "program_only", "unknown field"},
		{"findings where severity = bogus", "bogus", "must be one of"},
		{"findings where severity > high", ">", `">" is not allowed`},
		{"findings where cve_id ~ \"log4j\"", "~", `"~" is not allowed`},
		{"findings where state in (open, fixed)", "in", `"in" is not allowed`},
		{"findings where epss_score > abc", "abc", "must be a number"},
		{"findings where is_in_kev = maybe", "maybe", "must be a JSON boolean"},
		{"findings where is_in_kev != maybe", "maybe", "must be true or false"},
		{"findings where first_detected_at < -11y", "-11y", "longer than ten years"},
		{"findings where first_detected_at < \"yesterday\"", `"yesterday"`, "RFC 3339"},
		{"findings where severity is empty", "is empty", `"is empty" is not allowed`},
		{"findings where cvss_score between 1 and x", "x", "must be a number"},
		{"findings where not (severity = critical or (status = new and not cvss_score > 5))", "not cvss_score > 5", "nested too deep"},
		{"findings | count by title", "title", "cannot group by"},
		{"findings | count by state", "state", "cannot group by"},
		{"findings | count by severity, status, source", "count by severity, status, source", "at most 2 groups"},
		{"findings | bucket created_at by day | count by severity, status", "count by severity, status", "at most 2 groups"},
		{"findings | bucket severity by day", "severity", "cannot bucket"},
		{"findings | stats avg(severity)", "severity", "numeric field"},
		{"findings | stats distinct(cvss_score)", "cvss_score", "distinct needs"},
		{"findings | stats count(severity)", "severity", "takes no field"},
		{"findings | stats sum(cvss_score) as count, count()", "", "two output columns"},
		{"findings | count | count by severity", "count by severity", "only one count"},
		{"findings | count by severity | bucket created_at by day", "bucket created_at by day", "bucket comes before"},
		{"findings | limit 5", "limit 5", "need count by"},
		{"findings | count by severity | top 101 by count", "top 101 by count", "top takes 1 to 100"},
		{"findings | count by severity | limit 1001", "limit 1001", "limit takes 1 to 1000"},
		{"findings | count by severity | top 5 by nope", "nope", "not an output column"},
		{"findings | count by severity | sort count | top 1 by count", "top 1 by count", "one top or one sort"},
		{"findings | count by severity | limit 1 | limit 2", "limit 2", "only one limit"},
		{"findings | count by severity | sort a, b, c, d", "sort a, b, c, d", "at most 3 sort keys"},
		{"findings | bucket created_at by day | count | sort count | limit 1 | limit 2 | limit 3 | limit 4", "limit 4", "at most 6 stages"},
	}
	for _, c := range cases {
		_, err := build(t, c.src, memberAll())
		qe, ok := AsError(err)
		if !ok {
			t.Errorf("%q: want *Error, got %v", c.src, err)
			continue
		}
		found := false
		for _, d := range qe.Details {
			if strings.Contains(d.Message, c.msg) && (c.at == "" || c.src[d.Start:d.End] == c.at) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want %q at %q, got %+v", c.src, c.msg, c.at, qe.Details)
		}
	}
}

// Fields that need a permission the caller lacks behave exactly like
// fields that do not exist: no oracle.
func TestFieldPermissions(t *testing.T) {
	findingsOnly := member("findings:read")
	for _, src := range []string{
		"findings where asset.type = domain",
		"findings where asset.criticality = high",
		"findings where asset.tag = pci",
		"findings | count by asset.type",
		"findings | stats distinct(asset.exposure)",
	} {
		_, err := build(t, src, findingsOnly)
		if err == nil {
			t.Errorf("%q compiled without assets:read", src)
			continue
		}
		if strings.Contains(err.Error(), "permission") {
			t.Errorf("%q: the error reveals a permission: %v", src, err)
		}
		if _, err := build(t, src, member("findings:read", "assets:read")); err != nil {
			t.Errorf("%q with assets:read: %v", src, err)
		}
	}
	// The same message for an unknown field and a forbidden one.
	_, e1 := build(t, "findings where asset.type = domain", findingsOnly)
	_, e2 := build(t, "findings where asset.nonexistent = domain", findingsOnly)
	m1, m2 := e1.(*Error).Details[0].Message, e2.(*Error).Details[0].Message
	if strings.Replace(m1, "asset.type", "X", 1) != strings.Replace(m2, "asset.nonexistent", "X", 1) {
		t.Errorf("forbidden and unknown differ: %q vs %q", m1, m2)
	}
	// The schema hides them too.
	for _, f := range Findings.Schema(hasOnly("findings:read")).Fields {
		if strings.HasPrefix(f.Path, "asset.") {
			t.Errorf("schema shows %s without assets:read", f.Path)
		}
		if f.Path == "program_asset" || f.Path == "tenant_id" {
			t.Errorf("schema shows %s", f.Path)
		}
	}
}

func TestEntityPermission(t *testing.T) {
	_, err := build(t, "assets | count", member("findings:read"))
	if err == nil || !strings.Contains(err.Error(), "permission to query assets") {
		t.Errorf("assets without assets:read: %v", err)
	}
	if _, err := build(t, "findings | count", member("assets:read")); err == nil {
		t.Error("findings without findings:read compiled")
	}
	if _, err := build(t, "findings | count", Principal{TenantID: testTenant, UserID: testUser, Admin: true}); err != nil {
		t.Errorf("admin: %v", err)
	}
	if _, err := build(t, "findings | count", Principal{UserID: testUser, Has: hasAll}); err == nil {
		t.Error("principal without a tenant compiled")
	}
}

func TestPlanShape(t *testing.T) {
	p := mustBuild(t, "findings where severity in (critical, high) | bucket first_detected_at by week | stats count(), avg(cvss_score) by asset.type | sort avg_cvss_score desc | limit 50", memberAll())
	wantCols := []Column{{"first_detected_at", ColumnTime}, {"asset.type", ColumnDimension}, {"count", ColumnMeasure}, {"avg_cvss_score", ColumnMeasure}}
	if !reflect.DeepEqual(p.Columns, wantCols) {
		t.Errorf("columns = %+v", p.Columns)
	}
	if p.Limit != 50 || !reflect.DeepEqual(p.Order, []OrderRef{{3, true}, {0, false}, {1, false}}) {
		t.Errorf("limit %d order %+v", p.Limit, p.Order)
	}
	if p.Score < 10 || p.Score > MaxScore {
		t.Errorf("score %d", p.Score)
	}
	// No stage: a plain count.
	p = mustBuild(t, "assets", memberAll())
	if len(p.Aggs) != 1 || p.Aggs[0].Func != AggCount || len(p.Order) != 0 {
		t.Errorf("default pipeline: %+v", p.Aggs)
	}
	// count by: count descending, ties by the groups.
	p = mustBuild(t, "findings | count by severity, source | top 10 by count", memberAll())
	if p.Limit != 10 || !reflect.DeepEqual(p.Order, []OrderRef{{2, true}, {0, false}, {1, false}}) {
		t.Errorf("top: limit %d order %+v", p.Limit, p.Order)
	}
}

func TestComplexityLimit(t *testing.T) {
	var terms []string
	for i := 0; i < 30; i++ {
		terms = append(terms, "asset.type = domain")
	}
	src := "findings where " + strings.Join(terms, " and ") + " | count by asset.type, asset.environment"
	_, err := build(t, src, memberAll())
	if err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Errorf("want a complexity error, got %v", err)
	}
	var leaves []string
	for i := 0; i < filterspec.MaxLeaves+1; i++ {
		leaves = append(leaves, "cvss_score > 1")
	}
	_, err = build(t, "findings where "+strings.Join(leaves, " or "), memberAll())
	if err == nil || !strings.Contains(err.Error(), "too many conditions") {
		t.Errorf("want too many conditions, got %v", err)
	}
}

// The mandatory filters are part of every plan, whatever the query says.
func TestMandatoryFiltersAlwaysApplied(t *testing.T) {
	for _, src := range []string{
		"findings",
		"findings where status = draft",
		"findings where status in (draft, in_review) or severity = critical",
		"findings where not (status != draft)",
		"findings where branch_only = true",
	} {
		p := mustBuild(t, src, memberAll())
		eff := p.EffectiveFilter()
		got := map[string]bool{}
		for _, l := range eff.Leaves() {
			got[l.Field+":"+string(l.Op)] = true
		}
		for _, want := range []string{"status:not_in", "branch_only:eq", "program_asset:eq"} {
			if !got[want] {
				t.Errorf("%q: mandatory %s missing", src, want)
			}
		}
		// And they sit at the top level: ANDed, not under the user's tree.
		if len(eff.Root.All) < 1 {
			t.Errorf("%q: effective root is not an AND", src)
		}
		last := eff.Root.All[len(eff.Root.All)-1]
		if p.UserFilter().Root != nil && (last.All == nil || len(last.All) != 3) {
			t.Errorf("%q: mandatory group not last", src)
		}
	}
	p := mustBuild(t, "assets where type = domain", memberAll())
	got := map[string]bool{}
	for _, l := range p.EffectiveFilter().Leaves() {
		got[l.Field] = true
	}
	if !got["deleted"] || !got["program_only"] {
		t.Errorf("assets mandatory filters missing: %v", got)
	}
}

func TestMemberRule(t *testing.T) {
	if p := mustBuild(t, "findings", memberAll()); !p.MemberRule() || !p.Restricted() {
		t.Error("member: rule and scope must apply")
	}
	admin := Principal{TenantID: testTenant, UserID: testUser, Admin: true, Scope: &shared.DataScope{TenantID: testTenant, UserID: testUser, Unrestricted: true}}
	if p := mustBuild(t, "findings", admin); p.MemberRule() || p.Restricted() {
		t.Error("admin: neither applies")
	}
	if p := mustBuild(t, "assets", memberAll()); p.MemberRule() {
		t.Error("assets have no member rule")
	}
}

func TestRelativeTimes(t *testing.T) {
	cases := map[string]time.Duration{
		"-3h": 3 * time.Hour, "-14d": 14 * 24 * time.Hour, "-2w": 14 * 24 * time.Hour,
		"-1mo": 30 * 24 * time.Hour, "-1y": 365 * 24 * time.Hour,
	}
	for rel, d := range cases {
		p := mustBuild(t, "findings where created_at >= "+rel, memberAll())
		got := p.UserFilter().Root.Leaf.Values[0].(time.Time)
		if !got.Equal(testNow.Add(-d)) {
			t.Errorf("%s = %v, want %v", rel, got, testNow.Add(-d))
		}
	}
}

func TestDocumentV2(t *testing.T) {
	p := mustBuild(t, `findings where severity in (critical, high) and text ~ "log4j" | count by asset.type | top 5 by count`, memberAll())
	doc := p.Document()
	b, _ := json.Marshal(doc)
	want := `{"entity":"findings","filter":{"all":[{"field":"severity","op":"in","value":["critical","high"]}]},` +
		`"pipeline":[{"count":{"by":["asset.type"]}},{"top":{"by":"count","n":5}}],"q":"log4j","v":2}`
	if string(b) != want {
		t.Errorf("document =\n%s\nwant\n%s", b, want)
	}
	// The mandatory filters are not part of the stored document: they are
	// added again at every run.
	if strings.Contains(string(b), "branch_only") || strings.Contains(string(b), "program_asset") {
		t.Error("document carries server-side filters")
	}
}

// A version 1 FilterDocument (a saved view) converts to text and back to
// the same document.
func TestV1DocumentRoundTrip(t *testing.T) {
	docs := []string{
		`{"filter":{"field":"severity","op":"in","value":["critical","high"]},"v":1}`,
		`{"filter":{"all":[{"field":"state","op":"eq","value":"open"},{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.5}]},"q":"log4j","v":1}`,
		`{"filter":{"any":[{"field":"cve_id","op":"in","value":["CVE-2026-1","CVE-2026-2"]},{"not":{"field":"tool_name","op":"not_in","value":["a b","c"]}}]},"v":1}`,
		`{"filter":{"all":[{"field":"assigned_to","op":"is_null","value":true},{"field":"first_detected_at","op":"lt","value":"2026-01-02T03:04:05Z"},{"field":"related_to","op":"eq","value":"me"}]},"v":1}`,
		`{"filter":{"all":[{"field":"asset_criticality","op":"in","value":["critical"]},{"field":"network_port","op":"in","value":[22,443]}]},"v":1}`,
	}
	for _, d := range docs {
		spec, err := filterspec.ParseDocument([]byte(d), Findings.Registry, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if err != nil {
			t.Fatalf("ParseDocument(%s): %v", d, err)
		}
		text := Format(FromSpec(Findings, spec))
		p, err := build(t, text, memberAll())
		if err != nil {
			t.Errorf("text %q from %s: %v", text, d, err)
			continue
		}
		got, _ := p.UserFilter().DocumentJSON()
		if string(got) != d {
			t.Errorf("round trip via %q:\n got %s\nwant %s", text, got, d)
		}
	}
}

func TestDescribe(t *testing.T) {
	p := mustBuild(t, `findings where state = open and severity = critical and first_detected_at < -14d | count by asset.type | top 10 by count`, memberAll())
	want := "Count of findings where state is open and severity is critical and first_detected_at is before 14 days ago, grouped by asset.type, ordered by count descending, first 10"
	if got := Describe(p); got != want {
		t.Errorf("Describe =\n%q\nwant\n%q", got, want)
	}
}

func TestEntitiesDeclared(t *testing.T) {
	for _, e := range []*Entity{Findings, Assets} {
		for _, p := range append(append(e.Dimensions(), e.Measures()...), e.Times()...) {
			if _, ok := e.field(p, hasAll); !ok {
				t.Errorf("%s: path %s does not resolve", e.Name, p)
			}
		}
		for _, f := range e.Registry.Fields() {
			for _, bad := range []string{"tenant", "password", "secret", "token", "credential", "email", "phone"} {
				if strings.Contains(f.Name, bad) && !e.internal[f.Name] {
					t.Errorf("%s exposes %s", e.Name, f.Name)
				}
			}
		}
	}
}
