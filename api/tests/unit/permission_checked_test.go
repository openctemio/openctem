package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Every permission in the catalog gates something. A permission that no
// route, handler or service checks still shows in the role editor, so an
// owner believes they can grant or withhold a capability that does not
// exist. This is the inverse of TestEveryRouteIsGatedOrAllowlisted: it fails
// when a permission string is never referenced outside the permission
// package (internal/ and cmd/), unless it is reserved below with a reason.

// reservedPermissions are in the catalog on purpose before anything checks
// them, each with its decision.
var reservedPermissions = map[string]string{
	"assets:export":                 "server-side asset export (owner decision R14; kept by migration 000772 for it)",
	"attack_surface:programs:read":  "RFC-065: the programs routes gate on it (next P0 pull request)",
	"attack_surface:programs:write": "RFC-065: the programs routes gate on it (next P0 pull request)",
}

const permissionImportPath = "github.com/openctemio/openctem/api/pkg/domain/permission"

// referencedPermissionConsts returns the permission constants referenced
// from the non-test Go files under dirs, through the file's import name for
// the permission package.
//
//nolint:gocognit // one AST walk
func referencedPermissionConsts(t *testing.T, dirs ...string) map[string]bool {
	t.Helper()
	used := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			name := ""
			for _, imp := range f.Imports {
				if p, _ := strconv.Unquote(imp.Path.Value); p == permissionImportPath {
					name = "permission"
					if imp.Name != nil {
						name = imp.Name.Name
					}
				}
			}
			if name == "" {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == name {
						used[sel.Sel.Name] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return used
}

func TestEveryPermissionIsCheckedSomewhere(t *testing.T) {
	root := repoRoot(t)
	values := permissionConstValues(t, root)
	used := referencedPermissionConsts(t, filepath.Join(root, "internal"), filepath.Join(root, "cmd"))

	checked := map[string]bool{}
	for name := range used {
		if v, ok := values[name]; ok {
			checked[v] = true
		}
	}
	if len(checked) < 50 {
		t.Fatalf("only %d permission strings referenced: the walker is broken, not the code", len(checked))
	}

	var dead []string
	for _, p := range permission.AllPermissions() {
		s := p.String()
		if checked[s] {
			if why, ok := reservedPermissions[s]; ok {
				t.Errorf("%s is checked now; drop it from reservedPermissions (%s)", s, why)
			}
			continue
		}
		if _, ok := reservedPermissions[s]; ok {
			continue
		}
		dead = append(dead, s)
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("permissions in the catalog that nothing checks (gate a route with them, "+
			"or remove them with a migration, or reserve them with a reason):\n  %s", strings.Join(dead, "\n  "))
	}

	// Every constant name of the package has a distinct value: a second name
	// for the same string hides which one the code means.
	byValue := map[string][]string{}
	for name, v := range values {
		byValue[v] = append(byValue[v], name)
	}
	for v, names := range byValue {
		if len(names) > 1 && strings.Contains(v, ":") {
			sort.Strings(names)
			t.Errorf("%q has more than one constant: %s", v, strings.Join(names, ", "))
		}
	}
}
