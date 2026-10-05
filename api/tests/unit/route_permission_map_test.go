package unit

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The web console decides whether to show a mutating control (Save, Delete,
// Add, Test) from web/src/config/api-route-permissions.json, which this test
// generates from the route source. Before, each button picked its own
// permission and about 15 disagreed with the API: controls were shown and then
// answered 403, or hidden although the API allowed the action (settings audit
// 23a B24).
//
// The test fails when the committed file differs from the route table; run
//
//	UPDATE_ROUTE_PERMISSIONS=1 go test ./tests/unit -run TestRoutePermissionMapIsCurrent
//
// to regenerate it. It is a UX map, not a security boundary: the API gates
// stay authoritative.

// routeGate is what a route requires, as the web console checks it.
type routeGate struct {
	// Permissions must all be held.
	Permissions []string `json:"permissions,omitempty"`
	// AnyOf groups: at least one permission of each group must be held.
	AnyOf [][]string `json:"any_of,omitempty"`
	// MinRole is the lowest tenant role allowed ("admin" or "owner").
	MinRole string `json:"min_role,omitempty"`
}

const routePermissionMapPath = "../web/src/config/api-route-permissions.json"

// roleGateFuncs maps a role gate constructor to the minimum role it admits.
var roleGateFuncs = map[string]string{
	"RequireTeamAdmin": "admin", "RequireAdmin": "admin",
	"RequireTeamOwner": "owner", "RequireOwner": "owner",
}

var roleRank = map[string]int{"viewer": 1, "member": 2, "admin": 3, "owner": 4}

func higherRole(a, b string) string {
	if roleRank[b] > roleRank[a] {
		return b
	}
	return a
}

// loadPermissionValues maps permission constant names to their wire values.
func loadPermissionValues(t *testing.T, root string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "pkg", "domain", "permission", "permission.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse permission.go: %v", err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Values) != len(vs.Names) {
			return true
		}
		for i, name := range vs.Names {
			if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[name.Name] = v
				}
			}
		}
		return true
	})
	if len(out) < 50 {
		t.Fatalf("read only %d permission constants", len(out))
	}
	return out
}

// gateOf reads the gates in one middleware expression.
func gateOf(e ast.Expr, perms map[string]string, g *routeGate) {
	ast.Inspect(e, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := ce.Fun.(type) {
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		case *ast.Ident:
			name = fn.Name
		}
		if role, ok := roleGateFuncs[name]; ok {
			g.MinRole = higherRole(g.MinRole, role)
			return false
		}
		var values []string
		for _, a := range ce.Args {
			if sel, ok := a.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "permission" {
					if v, ok := perms[sel.Sel.Name]; ok {
						values = append(values, v)
					}
				}
			}
		}
		if len(values) == 0 {
			return true
		}
		if name == "RequireAny" {
			g.AnyOf = append(g.AnyOf, values)
		} else {
			g.Permissions = append(g.Permissions, values...)
		}
		return false
	})
}

func mergeGate(dst *routeGate, src routeGate) {
	dst.Permissions = append(dst.Permissions, src.Permissions...)
	dst.AnyOf = append(dst.AnyOf, src.AnyOf...)
	dst.MinRole = higherRole(dst.MinRole, src.MinRole)
}

// buildRoutePermissionMap walks the route source like parseRoutes, keeping
// the gates themselves (inherited from groups and middleware-slice variables)
// for every mutating route.
//
//nolint:cyclop,gocognit // AST walk mirrors parseRoutes
func buildRoutePermissionMap(t *testing.T) map[string]routeGate {
	t.Helper()
	root := repoRoot(t)
	perms := loadPermissionValues(t, root)
	routesDir := filepath.Join(root, "internal", "infra", "http", "routes")
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		t.Fatalf("read routes dir: %v", err)
	}
	out := map[string]routeGate{}
	fset := token.NewFileSet()
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(routesDir, ent.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", ent.Name(), perr)
		}
		argsGate := func(args []ast.Expr, vars map[string]routeGate) routeGate {
			var g routeGate
			for _, a := range args {
				if id, ok := a.(*ast.Ident); ok {
					if vg, ok := vars[id.Name]; ok {
						mergeGate(&g, vg)
						continue
					}
				}
				gateOf(a, perms, &g)
			}
			return g
		}
		collectVars := func(block *ast.BlockStmt, parent map[string]routeGate) map[string]routeGate {
			vars := map[string]routeGate{}
			for k, v := range parent {
				vars[k] = v
			}
			ast.Inspect(block, func(m ast.Node) bool {
				as, ok := m.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range as.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || i >= len(as.Rhs) {
						continue
					}
					var g routeGate
					gateOf(as.Rhs[i], perms, &g)
					if len(g.Permissions)+len(g.AnyOf) > 0 || g.MinRole != "" {
						vars[id.Name] = g
					}
				}
				return true
			})
			return vars
		}
		var process func(block *ast.BlockStmt, prefix string, inherited routeGate, vars map[string]routeGate)
		process = func(block *ast.BlockStmt, prefix string, inherited routeGate, vars map[string]routeGate) {
			vs := collectVars(block, vars)
			ast.Inspect(block, func(m ast.Node) bool {
				ce, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || (recv.Name != "r" && recv.Name != "router") {
					return true
				}
				if sel.Sel.Name == "Group" && len(ce.Args) >= 2 {
					gp, ok := routePathArg(ce.Args[0])
					if !ok {
						return true
					}
					var body *ast.BlockStmt
					for _, a := range ce.Args[1:] {
						if fl, ok := a.(*ast.FuncLit); ok {
							body = fl.Body
							break
						}
					}
					g := inherited
					g.Permissions = append([]string(nil), inherited.Permissions...)
					g.AnyOf = append([][]string(nil), inherited.AnyOf...)
					mergeGate(&g, argsGate(ce.Args[2:], vs))
					if body != nil {
						process(body, prefix+gp, g, vs)
					}
					return false
				}
				switch sel.Sel.Name {
				case "POST", "PUT", "PATCH", "DELETE":
				default:
					return true
				}
				if len(ce.Args) == 0 {
					return true
				}
				p, ok := routePathArg(ce.Args[0])
				if !ok {
					return true
				}
				g := inherited
				g.Permissions = append([]string(nil), inherited.Permissions...)
				g.AnyOf = append([][]string(nil), inherited.AnyOf...)
				mergeGate(&g, argsGate(ce.Args[1:], vs))
				full := prefix + p
				if len(full) > 1 {
					full = strings.TrimSuffix(full, "/")
				}
				out[sel.Sel.Name+" "+full] = normalizeGate(g)
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
				process(fn.Body, "", routeGate{}, map[string]routeGate{})
			}
			return true
		})
	}
	return out
}

func normalizeGate(g routeGate) routeGate {
	seen := map[string]bool{}
	var ps []string
	for _, p := range g.Permissions {
		if !seen[p] {
			seen[p] = true
			ps = append(ps, p)
		}
	}
	sort.Strings(ps)
	g.Permissions = ps
	for i := range g.AnyOf {
		sort.Strings(g.AnyOf[i])
	}
	sort.Slice(g.AnyOf, func(i, j int) bool { return strings.Join(g.AnyOf[i], ",") < strings.Join(g.AnyOf[j], ",") })
	return g
}

func renderRoutePermissionMap(m map[string]routeGate) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		buf.Write(kb)
		buf.WriteString(": ")
		buf.Write(vb)
		if i < len(keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return buf.Bytes()
}

func TestRoutePermissionMapIsCurrent(t *testing.T) {
	m := buildRoutePermissionMap(t)
	if len(m) < 100 {
		t.Fatalf("only %d mutating routes parsed; the walker is broken", len(m))
	}
	// Spot checks that pin the walker's reading of the gates.
	want := map[string]routeGate{
		"PATCH /api/v1/tenants/{tenant}/settings/pentest": {Permissions: []string{"settings:write"}, MinRole: "admin"},
		"DELETE /api/v1/tenants/{tenant}":                 {Permissions: []string{"team:delete"}, MinRole: "owner"},
	}
	for k, w := range want {
		got, ok := m[k]
		if !ok {
			t.Errorf("route %s missing from the map", k)
			continue
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(w)
		if !bytes.Equal(gb, wb) {
			t.Errorf("route %s: gate %s, want %s", k, gb, wb)
		}
	}

	rendered := renderRoutePermissionMap(m)
	path := filepath.Join(repoRoot(t), routePermissionMapPath)
	if os.Getenv("UPDATE_ROUTE_PERMISSIONS") == "1" {
		if err := os.WriteFile(path, rendered, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with UPDATE_ROUTE_PERMISSIONS=1)", path, err)
	}
	if !bytes.Equal(current, rendered) {
		t.Fatalf("%s is stale: a route gate changed. Regenerate with UPDATE_ROUTE_PERMISSIONS=1 go test ./tests/unit -run TestRoutePermissionMapIsCurrent", routePermissionMapPath)
	}
}
