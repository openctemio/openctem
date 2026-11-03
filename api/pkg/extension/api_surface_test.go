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

	"github.com/openctemio/openctem/api/pkg/extension"
)

var updateSurface = flag.Bool("update-api", false, "rewrite testdata/api.golden (refused for a removal without an APIVersion bump)")

const goldenPath = "testdata/api.golden"

// surface lists the package's exported API, one line per constant, type,
// struct field, interface method and function, with its type.
func surface(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	str := func(n any) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}
	var out []string
	for _, f := range pkgs["extension"].Files {
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
// exported surface must be recorded in testdata/api.golden, and a removal
// or change of an existing line (a break for extensions) needs an
// APIVersion bump. Run `go test ./pkg/extension -run TestAPISurface
// -update-api` to record a change.
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
	breaking := len(removed) > 0 && goldenVersion == extension.APIVersion
	if *updateSurface {
		if breaking {
			t.Fatalf("removed or changed (breaks extensions; bump APIVersion first):\n  %s", strings.Join(removed, "\n  "))
		}
		body := fmt.Sprintf("api_version %d\n%s\n", extension.APIVersion, strings.Join(cur, "\n"))
		if err := os.WriteFile(filepath.Clean(goldenPath), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if goldenVersion != extension.APIVersion {
		t.Fatalf("APIVersion is %d, testdata/api.golden records %d: rerun with -update-api", extension.APIVersion, goldenVersion)
	}
	if breaking {
		t.Errorf("removed or changed since API %d (a break: bump APIVersion, then -update-api):\n  %s", goldenVersion, strings.Join(removed, "\n  "))
	}
	if len(added) > 0 {
		t.Errorf("added to the API without a record (rerun with -update-api):\n  %s", strings.Join(added, "\n  "))
	}
}
