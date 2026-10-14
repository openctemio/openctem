package notification

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Every notification type the package declares is one Create accepts: a
// type declared and used but not listed in IsValidType made every in-app
// notice of that type fail validation and be dropped (sensor grant and scope
// changes, CI security, member lifecycle, scan approvals, scan window
// overrides, attack surface digests).
func TestEveryDeclaredTypeIsValid(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "entity.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, sp := range g.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Type") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				n++
				if !IsValidType(v) {
					t.Errorf("%s (%q) is declared but IsValidType refuses it", name.Name, v)
				}
			}
		}
	}
	if n < 20 {
		t.Fatalf("found only %d notification types; the parser no longer sees the declarations", n)
	}
}
