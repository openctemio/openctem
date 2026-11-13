package command

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandTypes_ListsEveryConstant parses this package and fails when a
// CommandType constant is missing from CommandTypes(): the tests that range
// over it (every claimed command type carries a signed job) would otherwise
// skip the new type.
func TestCommandTypes_ListsEveryConstant(t *testing.T) {
	listed := map[CommandType]bool{}
	for _, ct := range CommandTypes() {
		if listed[ct] {
			t.Fatalf("CommandTypes lists %q twice", ct)
		}
		listed[ct] = true
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "CommandType" {
				return true
			}
			for i, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				found++
				if ct := CommandType(strings.Trim(lit.Value, `"`)); !listed[ct] {
					t.Errorf("constant %s (%q) is missing from CommandTypes()", vs.Names[i].Name, ct)
				}
			}
			return true
		})
	}
	if found != len(listed) {
		t.Fatalf("found %d CommandType constants, CommandTypes() lists %d", found, len(listed))
	}
}
