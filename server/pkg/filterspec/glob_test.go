package filterspec

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeGlob(t *testing.T) {
	ok := map[string]string{
		"*.Example.COM ": "*.example.com",
		"api-*":          "api-*",
		"db?.corp":       "db?.corp",
		"a%b_c\\d*":      "a%b_c\\d*",
	}
	for in, want := range ok {
		got, err := NormalizeGlob(in)
		if err != nil || got != want {
			t.Errorf("NormalizeGlob(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "*", "**", "*a*", "ab*", "*.*.*.*.com", strings.Repeat("a", MaxGlobLen+1), "ab\x00c", "a?b?c"}
	for _, in := range bad {
		if _, err := NormalizeGlob(in); err == nil {
			t.Errorf("NormalizeGlob(%q) accepted", in)
		}
	}
}

func TestGlobToLikeEscapes(t *testing.T) {
	cases := map[string]string{
		"*.example.com": "%.example.com",
		"db?.corp":      "db_.corp",
		"100%_off\\x*":  `100\%\_off\\x%`,
	}
	for in, want := range cases {
		if got := GlobToLike(in); got != want {
			t.Errorf("GlobToLike(%q) = %q, want %q", in, got, want)
		}
	}
}

// globRegistry has a pattern field (Normalize + Expand) and two expensive
// fields.
func globRegistry(t *testing.T) *Registry {
	t.Helper()
	return MustRegistry(Registry{Name: "things", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"},
		Field{Name: "name", Type: TypeString, Ops: []Op{OpIn, OpNotIn}, SQL: "t.name", Expensive: true, MaxValues: 10,
			Normalize: NormalizeGlob, Expand: func(v string) []string { return []string{GlobToLike(v)} },
			Templates: map[Op]string{OpIn: "t.name ILIKE ANY({arg})", OpNotIn: "NOT (t.name ILIKE ANY({arg}))"}},
		Field{Name: "path", Type: TypeString, Ops: []Op{OpContains}, SQL: "t.path"},
		Field{Name: "note", Type: TypeString, Ops: []Op{OpContains}, SQL: "t.note"},
	)
}

func TestPatternFieldBindsEscapedLike(t *testing.T) {
	reg := globRegistry(t)
	spec, err := ParseValues(url.Values{"name": {"*.Ex_ample.com"}}, reg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Leaves()[0].Values[0]; got != "*.ex_ample.com" {
		t.Fatalf("parsed value %v, want the normalised glob", got)
	}
	w, err := Compile(spec, reg, SystemActor(tenantA, "test"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.SQL, "ex_ample") {
		t.Fatalf("value rendered into SQL: %s", w.SQL)
	}
	arr := w.Args[len(w.Args)-1]
	if got := fmt.Sprint(arr); !strings.Contains(got, `%.ex\_ample.com`) {
		t.Fatalf("bound %s, want the escaped LIKE pattern", got)
	}
	if _, err := ParseValues(url.Values{"name": {"*"}}, reg, Options{}); err == nil {
		t.Fatal("a bare wildcard was accepted")
	}
}

func TestExpensiveLeavesCapped(t *testing.T) {
	reg := globRegistry(t)
	two := url.Values{"name": {"api-*"}, "path_contains": {"src"}}
	spec, err := ParseValues(two, reg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(spec, reg, SystemActor(tenantA, "test")); err != nil {
		t.Fatalf("two expensive leaves refused: %v", err)
	}
	three := url.Values{"name": {"api-*"}, "path_contains": {"src"}, "note_contains": {"x"}}
	spec, err = ParseValues(three, reg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(spec, reg, SystemActor(tenantA, "test")); err == nil || !strings.Contains(err.Error(), "narrow the filter") {
		t.Fatalf("three expensive leaves: err = %v, want a refusal with a reason", err)
	}
}
