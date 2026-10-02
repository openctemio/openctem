package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// declaredConsts returns every constant of the named type declared in
// value_objects.go, keyed by identifier.
//
// NewAuditLog rejects an event whose Action or ResourceType fails IsValid, and
// the audit service only logs that rejection — so a constant that is declared
// and used but missing from the IsValid switch drops every event that carries
// it, silently. That is how credential-access auditing (AUTHZ-07) recorded
// nothing: ResourceTypeCredential was declared and emitted, never accepted.
// Reading the declarations from source keeps this test from becoming one more
// hand-maintained list to forget.
func declaredConsts(t *testing.T, typeName string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "value_objects.go", nil, 0)
	if err != nil {
		t.Fatalf("parse value_objects.go: %v", err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != typeName {
				continue
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				out[name.Name] = v
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("found no %s constants — the parser no longer matches the file layout", typeName)
	}
	return out
}

func TestEveryDeclaredResourceTypeIsValid(t *testing.T) {
	for name, v := range declaredConsts(t, "ResourceType") {
		if !ResourceType(v).IsValid() {
			t.Errorf("%s (%q) is declared but ResourceType.IsValid rejects it: every audit event using it is dropped", name, v)
		}
	}
}

func TestEveryDeclaredActionIsValid(t *testing.T) {
	for name, v := range declaredConsts(t, "Action") {
		if !Action(v).IsValid() {
			t.Errorf("%s (%q) is declared but Action.IsValid rejects it: every audit event using it is dropped", name, v)
		}
	}
}
