package extension_test

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/extension"
)

var updateSurface = flag.Bool("update-api", false, "rewrite testdata/api.golden (refused for a removal without an APIVersion bump)")

const goldenPath = "testdata/api.golden"

// surface lists the package's exported API, one line per constant, type,
// struct field, interface method and function, with its type.
func surface(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	str := func(n any) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}
	var out []string
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() {
					out = append(out, "func "+d.Name.Name+" "+str(d.Type))
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for i, n := range s.Names {
							if n.IsExported() && d.Tok == token.CONST && i < len(s.Values) {
								out = append(out, "const "+n.Name+" = "+str(s.Values[i]))
							}
						}
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						switch tt := s.Type.(type) {
						case *ast.StructType:
							out = append(out, "type "+s.Name.Name+" struct")
							for _, fl := range tt.Fields.List {
								for _, n := range fl.Names {
									if n.IsExported() {
										out = append(out, fmt.Sprintf("field %s.%s %s", s.Name.Name, n.Name, str(fl.Type)))
									}
								}
							}
						case *ast.InterfaceType:
							out = append(out, "type "+s.Name.Name+" interface")
							for _, m := range tt.Methods.List {
								for _, n := range m.Names {
									out = append(out, fmt.Sprintf("method %s.%s %s", s.Name.Name, n.Name, str(m.Type)))
								}
							}
						default:
							alias := ""
							if s.Assign.IsValid() {
								alias = "= "
							}
							out = append(out, "type "+s.Name.Name+" "+alias+str(s.Type))
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestAPISurface keeps the public extension API honest: any change to the
// exported surface must be recorded in testdata/api.golden, where the
// maintainer reviews it (CODEOWNERS). APIVersion stays 1 until the core's
// 1.0 release: a removal or change of an existing line is a break, made only
// as expand, migrate the extensions, contract within one release train and
// listed under "Extension API" in the release notes. Run
// `go test ./pkg/extension -run TestAPISurface -update-api` to record a
// change.
func TestAPISurface(t *testing.T) {
	cur := surface(t)
	raw, err := os.ReadFile(goldenPath)
	if err != nil && !*updateSurface {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	goldenVersion := -1
	if len(lines) > 0 {
		_, _ = fmt.Sscanf(lines[0], "api_version %d", &goldenVersion)
		lines = lines[1:]
	}
	have := map[string]bool{}
	for _, l := range cur {
		have[l] = true
	}
	var removed []string
	golden := map[string]bool{}
	for _, l := range lines {
		golden[l] = true
		if !have[l] {
			removed = append(removed, l)
		}
	}
	var added []string
	for _, l := range cur {
		if !golden[l] {
			added = append(added, l)
		}
	}
	if *updateSurface {
		body := fmt.Sprintf("api_version %d\n%s\n", extension.APIVersion, strings.Join(cur, "\n"))
		if err := os.WriteFile(filepath.Clean(goldenPath), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if goldenVersion != extension.APIVersion {
		t.Fatalf("APIVersion is %d, testdata/api.golden records %d: rerun with -update-api", extension.APIVersion, goldenVersion)
	}
	if len(removed) > 0 {
		t.Errorf("removed or changed (a break for extensions: expand, migrate, contract; list it under \"Extension API\" in the release notes, then -update-api):\n  %s", strings.Join(removed, "\n  "))
	}
	if len(added) > 0 {
		t.Errorf("added to the API without a record (rerun with -update-api):\n  %s", strings.Join(added, "\n  "))
	}
}
