package filterspec

import (
	"strings"
	"testing"
)

// A search template's UpperToken binds q (trimmed by the parser) upper-cased, as is (no
// pattern), while ArgToken keeps the escaped %q% pattern, and TenantToken
// still renders the tenant placeholder.
func TestSearch_UpperToken(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "findings.tenant_id", ScopeAssetSQL: "findings.asset_id", IDSQL: "findings.id",
		Search: &Search{
			Template: "findings.title ILIKE {arg} OR findings.cve_id = {upper} OR findings.asset_id IN (SELECT a.id FROM assets a WHERE a.tenant_id = {tenant} AND a.name ILIKE {arg})",
			Pattern:  true, Fields: []string{"title", "cve_id", "asset_name"},
		}},
		Field{Name: "severity", Type: TypeString, Ops: []Op{OpIn}, SQL: "findings.severity"})
	w, err := Compile(&Spec{Q: "cve-2024_1%"}, reg, adminActor(t))
	if err != nil {
		t.Fatal(err)
	}
	var upper, pattern bool
	for _, a := range w.Args {
		switch a {
		case "CVE-2024_1%":
			upper = true
		case `%cve-2024\_1\%%`:
			pattern = true
		}
	}
	if !upper || !pattern {
		t.Fatalf("args %v: want the upper-cased exact value and the escaped pattern", w.Args)
	}
	if strings.Contains(w.SQL, UpperToken) || strings.Contains(w.SQL, ArgToken) || strings.Contains(w.SQL, TenantToken) {
		t.Fatalf("unrendered token: %s", w.SQL)
	}
	if !strings.Contains(w.SQL, "a.tenant_id = $1") {
		t.Fatalf("the asset arm is not pinned to the tenant: %s", w.SQL)
	}
	// Rebase rewrites the qualifiers and keeps the token working.
	rw, err := Compile(&Spec{Q: "x"}, reg.Rebase("findings", "f"), adminActor(t))
	if err != nil || strings.Contains(rw.SQL, "findings.") || strings.Contains(rw.SQL, UpperToken) {
		t.Fatalf("rebase: %v %s", err, rw.SQL)
	}
	if d := reg.Describe(nil); strings.Join(d.SearchFields, ",") != "title,cve_id,asset_name" || !d.Search {
		t.Fatalf("describe search fields: %+v", d.SearchFields)
	}
}
