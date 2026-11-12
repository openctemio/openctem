package scan

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

var strictScans = filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: []string{"include_ad_hoc"}}

func scanActor(t *testing.T, tenant shared.ID) filterspec.Actor {
	t.Helper()
	a, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func compileScans(t *testing.T, q string, includeAdHoc bool) *filterspec.Where {
	t.Helper()
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := filterspec.ParseValues(vals, Fields, strictScans)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	w, err := filterspec.Compile(WithListVisibility(spec, includeAdHoc), ListFields, scanActor(t, shared.NewID()))
	if err != nil {
		t.Fatalf("compile %q: %v", q, err)
	}
	return w
}

// Every compiled scans filter starts with the tenant predicate and carries
// the visibility rules, whatever the request names.
func TestScansListCompile_TenantFirstAndVisibility(t *testing.T) {
	const archivedRule = "(NOT COALESCE((scans.archived_at IS NOT NULL), FALSE))"
	const adHocRule = "(NOT COALESCE((scans.ad_hoc), FALSE))"
	for _, c := range []struct {
		name, query  string
		includeAdHoc bool
		wantAdHoc    bool
	}{
		{"default hides quick scans", "", false, true},
		{"status filter keeps the rules", "status=active", false, true},
		{"include_ad_hoc lists them", "", true, false},
		{"origin=system lists managed scans, which are ad hoc", "origin=system", false, false},
		{"origin=user still hides quick scans", "origin=user", false, true},
		{"a different filter does not lift the rule", "q=nightly&origin=user", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := compileScans(t, c.query, c.includeAdHoc)
			if !strings.HasPrefix(w.SQL, "scans.tenant_id = $1") {
				t.Errorf("the tenant predicate is not first: %s", w.SQL)
			}
			if !strings.Contains(w.SQL, archivedRule) {
				t.Errorf("archived scans are not excluded: %s", w.SQL)
			}
			if got := strings.Contains(w.SQL, adHocRule); got != c.wantAdHoc {
				t.Errorf("ad hoc rule present = %v, want %v: %s", got, c.wantAdHoc, w.SQL)
			}
		})
	}
}

// origin=system only lifts the ad hoc rule at the top level of the AND: inside
// an OR or a NOT it asks for nothing.
func TestScansListVisibility_SystemOriginOnlyAtTopLevel(t *testing.T) {
	for name, doc := range map[string]string{
		"or":  `{"filter":{"any":[{"field":"origin","op":"eq","value":"system"},{"field":"status","op":"in","value":["active"]}]}}`,
		"not": `{"filter":{"not":{"field":"origin","op":"eq","value":"system"}}}`,
	} {
		spec, err := filterspec.ParseDocument([]byte(doc), Fields, strictScans)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w, err := filterspec.Compile(WithListVisibility(spec, false), ListFields, scanActor(t, shared.NewID()))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(w.SQL, "(NOT COALESCE((scans.ad_hoc), FALSE))") {
			t.Errorf("%s: origin=system lifted the ad hoc rule from inside a group: %s", name, w.SQL)
		}
	}
}

func TestWithListVisibility_DoesNotChangeTheSpec(t *testing.T) {
	spec, err := filterspec.ParseValues(url.Values{"status": {"active"}}, Fields, strictScans)
	if err != nil {
		t.Fatal(err)
	}
	root, before := spec.Root, len(spec.Leaves())
	_ = WithListVisibility(spec, false)
	if spec.Root != root || len(spec.Leaves()) != before {
		t.Errorf("the caller's spec was modified")
	}
}

// The old param names are aliases of the registry: the same filter, with the
// old names recorded so the handler can announce them.
func TestScansAliases_SameFilterAsCanonical(t *testing.T) {
	old, err := filterspec.ParseValues(url.Values{"search": {"nightly"}, "tags": {"prod,edge"}, "status": {"active"}}, Fields, strictScans)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := filterspec.ParseValues(url.Values{"q": {"nightly"}, "tag": {"prod,edge"}, "status": {"active"}}, Fields, strictScans)
	if err != nil {
		t.Fatal(err)
	}
	a, b := scanActor(t, shared.NewID()), scanActor(t, shared.NewID())
	wo, err := filterspec.Compile(old, ListFields, a)
	if err != nil {
		t.Fatal(err)
	}
	wc, err := filterspec.Compile(canon, ListFields, b)
	if err != nil {
		t.Fatal(err)
	}
	if wo.SQL != wc.SQL || wo.OrderBy != wc.OrderBy {
		t.Errorf("alias SQL differs:\n%s\n%s", wo.SQL, wc.SQL)
	}
	if len(old.AliasesUsed) != 2 || len(canon.AliasesUsed) != 0 {
		t.Errorf("aliases used: old %v canonical %v", old.AliasesUsed, canon.AliasesUsed)
	}
	for _, p := range []string{"search", "tags"} {
		found := false
		for _, u := range old.AliasesUsed {
			found = found || u.Old == p
		}
		if !found {
			t.Errorf("alias %s was not recorded", p)
		}
	}
}

// A request value is a bound parameter: replacing every literal leaves the
// SQL text unchanged, and quotes and semicolons stay in the argument.
func TestScansListCompile_ValuesAreBound(t *testing.T) {
	seeds := []string{`'; DROP TABLE scans; --`, `" OR 1=1 --`, `a%b_c\`, "x'); SELECT pg_sleep(10); --"}
	base := compileScans(t, "q=aaaa&tag=aaaa&name_contains=aaaa&scanner_name_contains=aaaa", false)
	for _, s := range seeds {
		q := url.Values{"q": {s}, "tag": {s}, "name_contains": {s}, "scanner_name_contains": {s}}.Encode()
		w := compileScans(t, q, false)
		if w.SQL != base.SQL || w.OrderBy != base.OrderBy {
			t.Errorf("SQL text changed with the value %q:\n%s\n%s", s, w.SQL, base.SQL)
		}
		if strings.Contains(w.SQL, "DROP") || strings.Contains(w.SQL, "pg_sleep") || strings.Contains(w.SQL, s) {
			t.Errorf("a value reached the SQL text: %s", w.SQL)
		}
	}
	// LIKE metacharacters of q are escaped in the bound pattern.
	w := compileScans(t, url.Values{"q": {"a%b_c"}}.Encode(), false)
	found := false
	for _, a := range w.Args {
		if s, ok := a.(string); ok && s == `%a\%b\_c%` {
			found = true
		}
	}
	if !found {
		t.Errorf("q was not bound as an escaped pattern: %v", w.Args)
	}
}

// A field the request may not name (the server's own rules) and a field that
// does not exist give the same error, and no error echoes the input value.
func TestScansListErrors_NoFieldDiscoveryNoValueEcho(t *testing.T) {
	const secret = "VALUE-ECHO-PROBE-9"
	errBody := func(q string) string {
		t.Helper()
		vals, _ := url.ParseQuery(q)
		_, err := filterspec.ParseValues(vals, Fields, strictScans)
		fe, ok := filterspec.AsError(err)
		if !ok {
			t.Fatalf("%q: not a filter error: %v", q, err)
		}
		b, _ := json.Marshal(fe.APIError())
		return string(b)
	}
	hidden, nonsense := errBody("archived="+secret), errBody("zzz_nothing="+secret)
	norm := func(s, name string) string { return strings.ReplaceAll(s, name, "X") }
	if norm(hidden, "archived") != norm(nonsense, "zzz_nothing") {
		t.Errorf("a server-only field and a missing one answer differently:\n%s\n%s", hidden, nonsense)
	}
	// Free text is never echoed by the engine; the typed fields' short echo is
	// switched off by the route (the handler tests).
	for _, doc := range []string{
		`{"filter":{"field":"archived","op":"eq","value":"` + secret + `"}}`,
		`{"filter":{"field":"nothing","op":"eq","value":"` + secret + `"}}`,
	} {
		_, err := filterspec.ParseDocument([]byte(doc), Fields, strictScans)
		fe, ok := filterspec.AsError(err)
		if !ok {
			t.Fatalf("%s: not a filter error", doc)
		}
		if b, _ := json.Marshal(fe.APIError()); strings.Contains(string(b), secret) {
			t.Errorf("%s echoes the value: %s", doc, b)
		}
	}
}

// The registry's server-only fields are not part of the public contract.
func TestScansPublicFields_ExcludeServerRules(t *testing.T) {
	for _, n := range []string{"archived", "ad_hoc"} {
		if _, ok := Fields.Field(n); ok {
			t.Errorf("%s is a public field", n)
		}
		if _, ok := ListFields.Field(n); !ok {
			t.Errorf("%s is missing from the list registry", n)
		}
	}
}

// Every template that reads a table other than scans pins the tenant.
func TestScansTemplatesPinTenant(t *testing.T) {
	for _, f := range ListFields.Fields() {
		var all []string
		for _, tpl := range f.Templates {
			all = append(all, tpl)
		}
		all = append(all, f.BoolTemplate, f.SQL)
		for _, tpl := range f.EnumTemplates {
			all = append(all, tpl)
		}
		for _, tpl := range all {
			if strings.Contains(strings.ToUpper(tpl), "SELECT") {
				t.Errorf("%s reads another table: %s", f.Name, tpl)
			}
		}
	}
	if ListFields.TenantSQL != "scans.tenant_id" || ListFields.Unscoped == "" {
		t.Errorf("tenant column or Unscoped reason lost")
	}
}
