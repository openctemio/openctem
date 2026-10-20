package controller

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// Every controller declares how its SQL stays inside the app role's
// statement_timeout (statement_profile.go). A new controller without an entry
// fails here, and so does an entry whose controller no longer exists.
func TestEveryControllerDeclaresItsStatementProfile(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Name.Name != "Reconcile" || len(fn.Recv.List) != 1 {
					continue
				}
				typ := fn.Recv.List[0].Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				if id, ok := typ.(*ast.Ident); ok {
					found[id.Name] = true
				}
			}
		}
	}
	if len(found) < 50 {
		t.Fatalf("found only %d controllers; the scan is broken", len(found))
	}
	var missing, stale []string
	for name := range found {
		switch sqlProfiles[name] {
		case SQLLight, SQLBatched, SQLLong:
		default:
			missing = append(missing, name)
		}
	}
	for name := range sqlProfiles {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("controllers without a SQL profile in statement_profile.go (light, batched or long): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("statement_profile.go entries without a controller: %v", stale)
	}
}
