package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Every permission string the product refers to must exist in the registry
// (permission.AllPermissions, which the catalog sync test ties to the DB
// seed). A reference to a permission that does not exist can never be
// granted, so whatever it gates is silently hidden from — or denied to —
// every non-admin. The module map once named five such permissions and hid
// Attack Surface, CTEM Cycles, Business Services, Compensating Controls and
// Scan Scan workflows from every member.
//
// Three reference sites are checked:
//   - the module → permission map that drives the sidebar (bootstrap);
//   - every permission.X constant used by api Go code (routes, handlers,
//     services, middleware);
//   - the web Permission constants that the UI gates on.

func registryIDs() map[string]bool {
	out := make(map[string]bool)
	for _, p := range permission.AllPermissions() {
		out[p.String()] = true
	}
	return out
}

func TestPermissionReferences_ModuleMapNamesOnlyRegisteredPermissions(t *testing.T) {
	reg := registryIDs()
	var missing []string
	for mod, perm := range module.ModulePermissionMapping {
		if perm != "" && !reg[perm] {
			missing = append(missing, mod+" -> "+perm)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("ModulePermissionMapping names permissions that do not exist (no role can grant them):\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// The five modules the broken map hid are visible to the system roles that
// hold the permission their routes gate on, and stay hidden from a role
// without it.
func TestPermissionReferences_CTEMModulesVisibleToMembers(t *testing.T) {
	mods := []string{
		module.ModuleAttackSurface, module.ModuleCTEMCycles, module.ModuleBusinessServices,
		module.ModuleBusinessImpact, module.ModuleCompensatingControls, module.ModuleScanWorkflows,
	}
	for _, r := range []tenant.Role{tenant.RoleMember, tenant.RoleViewer} {
		got := module.FilterModuleIDsByPermissions(mods, permission.GetPermissionStringsForRole(r), false)
		if len(got) != len(mods) {
			t.Errorf("%s sees %v of %v", r, got, mods)
		}
	}
	if got := module.FilterModuleIDsByPermissions(mods, []string{"dashboard:read"}, false); len(got) != 0 {
		t.Errorf("a role without the gating permissions sees %v", got)
	}
}

// permissionConstValues parses pkg/domain/permission/*.go and returns the
// string value of every exported constant.
func permissionConstValues(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, "pkg", "domain", "permission")
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err == nil && name.IsExported() {
						out[name.Name] = v
					}
				}
			}
		}
	}
	if len(out) < 50 {
		t.Fatalf("parsed only %d permission constants — the parser is broken", len(out))
	}
	return out
}

var permissionSelector = regexp.MustCompile(`\bpermission\.([A-Z][A-Za-z0-9_]*)\b`)

func TestPermissionReferences_GoCodeUsesOnlyRegisteredPermissions(t *testing.T) {
	root := repoRoot(t)
	consts := permissionConstValues(t, root)
	reg := registryIDs()

	missing := map[string]string{}
	for _, sub := range []string{"internal", "pkg", "cmd"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.Contains(path, filepath.Join("pkg", "domain", "permission")) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range permissionSelector.FindAllStringSubmatch(string(data), -1) {
				v, isConst := consts[m[1]]
				if !isConst {
					continue // a function or type, e.g. permission.AllPermissions
				}
				if !reg[v] {
					rel, _ := filepath.Rel(root, path)
					missing["permission."+m[1]+" ("+v+")"] = rel
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	if len(missing) > 0 {
		var lines []string
		for k, v := range missing {
			lines = append(lines, k+" used in "+v)
		}
		sort.Strings(lines)
		t.Fatalf("Go code references permissions that are not in AllPermissions():\n  %s", strings.Join(lines, "\n  "))
	}
}

// webPermissionValue matches `Key: 'module:action'` entries in the web
// Permission object.
var webPermissionValue = regexp.MustCompile(`^\s*[A-Za-z0-9_]+:\s*'([a-z][a-z0-9_]*(?::[a-z0-9_]+)+)'`)

func TestPermissionReferences_WebConstantsAreRegistered(t *testing.T) {
	path := filepath.Join(repoRoot(t), "..", "web", "src", "lib", "permissions", "constants.ts")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("web constants not present (%v); this check runs in the monorepo checkout", err)
	}
	src := string(data)
	start := strings.Index(src, "export const Permission = {")
	if start < 0 {
		t.Fatal("web constants.ts has no `export const Permission = {` block — update this test")
	}
	end := strings.Index(src[start:], "\n} as const")
	if end < 0 {
		t.Fatal("web Permission block is not terminated by `} as const` — update this test")
	}
	reg := registryIDs()
	var missing []string
	n := 0
	for _, line := range strings.Split(src[start:start+end], "\n") {
		if m := webPermissionValue.FindStringSubmatch(line); m != nil {
			n++
			if !reg[m[1]] {
				missing = append(missing, strings.TrimSpace(line))
			}
		}
	}
	if n < 50 {
		t.Fatalf("parsed only %d web permission constants — the parser is broken", n)
	}
	if len(missing) > 0 {
		t.Fatalf("web Permission constants name permissions that do not exist in the api:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
