package oidc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// ignoreTimesSetters are the only non-test files allowed to set IgnoreTimes.
// verify.go reads a token's iat without verifying it when IgnoreTimes is set
// (a reviewed security-review waiver whose premise is that only the CI trust
// configuration preview sets it, and the signature, issuer and audience are
// verified right after). A new setter needs the same review: add it here only
// after that review.
var ignoreTimesSetters = map[string]bool{
	"internal/app/cirun/preview.go": true, // the CI trust configuration preview
	"pkg/oidc/workload.go":          true, // passes WorkloadExpect.IgnoreTimes through
}

func TestIgnoreTimesSettersAreReviewed(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			var hit bool
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == "IgnoreTimes" {
					hit = true
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "IgnoreTimes" {
						hit = true
					}
				}
			}
			if hit {
				seen++
				if !ignoreTimesSetters[rel] {
					t.Errorf("%s sets IgnoreTimes: the JWT-UNVERIFIED waiver in verify.go assumes only the CI trust preview does; review it, then add the file to ignoreTimesSetters", fset.Position(n.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("found no IgnoreTimes setter at all: the walk is broken")
	}
}
