package filterspec

import (
	"net/url"
	"strings"
	"testing"
)

func lensRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry(Registry{Name: "x", TenantSQL: "findings.tenant_id", ScopeAssetSQL: "findings.asset_id", IDSQL: "findings.id"},
		Field{Name: "state", Type: TypeEnum, Enum: []string{"open", "fixed", "all"}, Ops: []Op{OpEq}, SQL: "findings.status",
			EnumTemplates: map[string]string{
				"open":  "findings.status IN ('new', 'confirmed')",
				"fixed": "findings.status IN ('resolved')",
				"all":   "TRUE",
			}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// A lens value compiles to its constant predicate and binds nothing, so a
// request value can never reach the SQL text and an index on the predicate
// can serve it.
func TestEnumTemplates_CompileToConstantPredicate(t *testing.T) {
	reg := lensRegistry(t)
	for v, want := range map[string]string{
		"open":  "(findings.status IN ('new', 'confirmed'))",
		"fixed": "(findings.status IN ('resolved'))",
		"all":   "(TRUE)",
	} {
		s, err := ParseValues(url.Values{"state": {v}}, reg, testOpts())
		if err != nil {
			t.Fatalf("state=%s: %v", v, err)
		}
		w, err := Compile(s, reg, memberActor(t))
		if err != nil {
			t.Fatalf("state=%s: %v", v, err)
		}
		if !strings.Contains(w.SQL, want) {
			t.Errorf("state=%s: %s, want %s", v, w.SQL, want)
		}
		if strings.Contains(w.SQL, "'"+v+"'") && v != "fixed" {
			t.Errorf("state=%s: the value itself reached the SQL: %s", v, w.SQL)
		}
		// The tenant and the two data-scope args only: the lens binds nothing.
		if len(w.Args) != 3 {
			t.Errorf("state=%s: %d args, want 3 (tenant + scope)", v, len(w.Args))
		}
		if !strings.HasPrefix(w.SQL, "findings.tenant_id = $1") {
			t.Errorf("state=%s: tenant predicate missing: %s", v, w.SQL)
		}
	}
	if _, err := ParseValues(url.Values{"state": {"closed"}}, reg, testOpts()); err == nil {
		t.Error("state=closed (not in the enum) must be rejected")
	}
	if _, err := ParseValues(url.Values{"state": {"open,fixed"}}, reg, testOpts()); err == nil {
		t.Error("state takes one value (eq), a list must be rejected")
	}
}

func TestEnumTemplates_DocumentAndRebase(t *testing.T) {
	reg := lensRegistry(t)
	s, err := ParseDocument([]byte(`{"filter":{"field":"state","op":"eq","value":"fixed"}}`), reg, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	f := reg.Rebase("findings", "f")
	w, err := Compile(s, f, adminActor(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.SQL, "(f.status IN ('resolved'))") {
		t.Errorf("rebased lens: %s", w.SQL)
	}
}

func TestEnumTemplates_Validation(t *testing.T) {
	base := Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"}
	cases := map[string]Field{
		"missing value": {Name: "state", Type: TypeEnum, Enum: []string{"open", "all"}, Ops: []Op{OpEq}, SQL: "t.status",
			EnumTemplates: map[string]string{"open": "TRUE"}},
		"unknown value": {Name: "state", Type: TypeEnum, Enum: []string{"open"}, Ops: []Op{OpEq}, SQL: "t.status",
			EnumTemplates: map[string]string{"open": "TRUE", "x": "TRUE"}},
		"binds a value": {Name: "state", Type: TypeEnum, Enum: []string{"open"}, Ops: []Op{OpEq}, SQL: "t.status",
			EnumTemplates: map[string]string{"open": "t.status = {arg}"}},
		"not an enum": {Name: "state", Type: TypeString, Ops: []Op{OpEq}, SQL: "t.status",
			EnumTemplates: map[string]string{"open": "TRUE"}},
		"other operators": {Name: "state", Type: TypeEnum, Enum: []string{"open"}, Ops: []Op{OpEq, OpIn}, SQL: "t.status",
			EnumTemplates: map[string]string{"open": "TRUE"}},
	}
	for name, f := range cases {
		if _, err := NewRegistry(base, f); err == nil {
			t.Errorf("%s: registry accepted an invalid EnumTemplates field", name)
		}
	}
}
