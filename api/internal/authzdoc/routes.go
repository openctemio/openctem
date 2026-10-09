// Package authzdoc reads the authorization model from the source (the route
// gates, the permission catalog, the built-in roles and the role templates)
// and renders it as the generated authorization reference: one JSON document
// for the web console and markdown pages for the documentation site.
//
// Nothing here is a security boundary. The gates themselves are enforced by
// the middleware; this package only describes them, from the same source the
// router is built from, so the description cannot drift from the code.
package authzdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Gate is what a route requires.
type Gate struct {
	// Permissions must all be held.
	Permissions []string `json:"permissions,omitempty"`
	// AnyOf groups: at least one permission of each group must be held.
	AnyOf [][]string `json:"any_of,omitempty"`
	// MinRole is the lowest team role admitted ("admin" or "owner").
	MinRole string `json:"min_role,omitempty"`
	// Modules must be enabled for the organization (RequireModule).
	Modules []string `json:"modules,omitempty"`
	// StepUp: the session must have signed in or stepped up recently.
	StepUp bool `json:"step_up,omitempty"`
	// Other names any other gate the route applies (campaign role, platform
	// administrator, permission-or-self, ...).
	Other []string `json:"other,omitempty"`
}

// Gated reports whether the gate checks who the caller is (a permission, a
// role or another named gate). A module or step-up check alone is not one.
func (g Gate) Gated() bool {
	return len(g.Permissions)+len(g.AnyOf)+len(g.Other) > 0 || g.MinRole != ""
}

// Route is one registered HTTP route with its gate.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// RawPath is the path as registered (a trailing slash kept), which the
	// data-surface registry matches on.
	RawPath string `json:"-"`
	// Register is the function that registers the route; it names the
	// feature the route belongs to.
	Register string `json:"register"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Gate
}

// Key is "METHOD /path".
func (r Route) Key() string { return r.Method + " " + r.Path }

// roleGateFuncs maps a team-role gate to the lowest role it admits.
var roleGateFuncs = map[string]string{
	"RequireTeamAdmin": "admin", "RequireAdmin": "admin",
	"RequireTeamOwner": "owner", "RequireOwner": "owner",
}

// permissionGateFuncs take permission constants as arguments.
var permissionGateFuncs = map[string]bool{
	"Require": true, "RequireAll": true, "RequireAny": true,
	"RequireTenantPermission": true, "RequirePermission": true,
}

// otherGateFuncs are gates that are neither a permission nor a team role.
var otherGateFuncs = map[string]string{
	"RequirePermissionOrSelf": "permission_or_self",
	"RequireCampaignRole":     "campaign_role",
	"RequirePlatformAdmin":    "platform_admin",
	"RequireRole":             "platform_admin_role",
	"RequireTeamRole":         "team_role",
	"RequireMinTeamRole":      "team_role",
	"RequireTenantRole":       "team_role",
	"RequireMinTenantRole":    "team_role",
}

var roleRank = map[string]int{"viewer": 1, "member": 2, "admin": 3, "owner": 4}

func higherRole(a, b string) string {
	if roleRank[b] > roleRank[a] {
		return b
	}
	return a
}

// loadStringConsts maps the string constants declared in the Go files of dir
// to their values.
func loadStringConsts(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
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
	}
	return out, nil
}

func routePathArg(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		p, err := strconv.Unquote(v.Value)
		return p, err == nil
	case *ast.SelectorExpr:
		if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "protov2" {
			p, ok := protov2.Paths[v.Sel.Name]
			return p, ok
		}
	}
	return "", false
}

func callName(ce *ast.CallExpr) string {
	switch fn := ce.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

func merge(dst *Gate, src Gate) {
	dst.Permissions = append(dst.Permissions, src.Permissions...)
	dst.AnyOf = append(dst.AnyOf, src.AnyOf...)
	dst.MinRole = higherRole(dst.MinRole, src.MinRole)
	dst.Modules = append(dst.Modules, src.Modules...)
	dst.StepUp = dst.StepUp || src.StepUp
	dst.Other = append(dst.Other, src.Other...)
}

func clone(g Gate) Gate {
	var c Gate
	merge(&c, g)
	return c
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalize(g Gate) Gate {
	g.Permissions = uniqSorted(g.Permissions)
	g.Modules = uniqSorted(g.Modules)
	g.Other = uniqSorted(g.Other)
	for i := range g.AnyOf {
		g.AnyOf[i] = uniqSorted(g.AnyOf[i])
	}
	sort.Slice(g.AnyOf, func(i, j int) bool { return strings.Join(g.AnyOf[i], ",") < strings.Join(g.AnyOf[j], ",") })
	if len(g.AnyOf) == 0 {
		g.AnyOf = nil
	}
	return g
}

type walker struct {
	perms   map[string]string // permission constant name -> value
	modules map[string]string // module constant name -> value
}

// permArgs returns the permission values named by a call's arguments
// (permission.X selectors).
func (w *walker) permArgs(ce *ast.CallExpr) []string {
	var values []string
	for _, a := range ce.Args {
		sel, ok := a.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "permission" {
			if val, ok := w.perms[sel.Sel.Name]; ok {
				values = append(values, val)
			}
		}
	}
	return values
}

// moduleArgs returns the module ids named by a RequireModule call.
func (w *walker) moduleArgs(ce *ast.CallExpr) []string {
	var values []string
	for _, a := range ce.Args {
		if sel, ok := a.(*ast.SelectorExpr); ok {
			if val, ok := w.modules[sel.Sel.Name]; ok {
				values = append(values, val)
			}
		}
	}
	return values
}

// callGate adds the gate of one call to g. It reports whether the call was a
// gate (so its arguments need no further walking).
func (w *walker) callGate(ce *ast.CallExpr, g *Gate) bool {
	name := callName(ce)
	if role, ok := roleGateFuncs[name]; ok {
		g.MinRole = higherRole(g.MinRole, role)
		return true
	}
	switch name {
	case "requireStepUp", "RequireRecentAuth":
		g.StepUp = true
		return true
	case "RequireModule":
		g.Modules = append(g.Modules, w.moduleArgs(ce)...)
		return true
	case "RequireAny":
		if vals := w.permArgs(ce); len(vals) > 0 {
			g.AnyOf = append(g.AnyOf, vals)
		}
		return true
	}
	other, isOther := otherGateFuncs[name]
	if isOther {
		g.Other = append(g.Other, other)
	}
	// Permission gates, RequirePermissionOrSelf (which names a permission
	// too), and local wrappers such as tenantPerm(permission.X): a call in a
	// middleware position that names permissions gates on them.
	vals := w.permArgs(ce)
	g.Permissions = append(g.Permissions, vals...)
	return isOther || permissionGateFuncs[name] || len(vals) > 0
}

// gateOf reads every gate in a middleware expression. vars holds the gates of
// middleware variables (and module-gate parameters) in scope.
func (w *walker) gateOf(e ast.Expr, vars map[string]Gate) Gate {
	var g Gate
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			if vg, ok := vars[v.Name]; ok {
				merge(&g, vg)
			}
		case *ast.CallExpr:
			return !w.callGate(v, &g)
		}
		return true
	})
	return g
}

func paramNames(fn *ast.FuncDecl) (names []string, variadic bool) {
	if fn.Type.Params == nil {
		return nil, false
	}
	for _, field := range fn.Type.Params.List {
		_, isEllipsis := field.Type.(*ast.Ellipsis)
		for _, n := range field.Names {
			names = append(names, n.Name)
			variadic = isEllipsis
		}
	}
	return names, variadic
}

// ParseRoutes reads every route registered under
// internal/infra/http/routes, with its full path (chi groups resolved) and
// the gates applied to it, including gates inherited from groups, middleware
// variables and module gates passed in as arguments. apiRoot is the api/
// directory.
//
//nolint:cyclop,gocognit // one AST walk
func ParseRoutes(apiRoot string) ([]Route, error) {
	perms, err := loadStringConsts(filepath.Join(apiRoot, "pkg", "domain", "permission"))
	if err != nil {
		return nil, fmt.Errorf("read permission constants: %w", err)
	}
	modules, err := loadStringConsts(filepath.Join(apiRoot, "pkg", "domain", "module"))
	if err != nil {
		return nil, fmt.Errorf("read module constants: %w", err)
	}
	w := &walker{perms: perms, modules: modules}

	routesDir := filepath.Join(apiRoot, "internal", "infra", "http", "routes")
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	type parsed struct {
		name string
		file *ast.File
	}
	files := make([]parsed, 0, len(entries))
	funcs := map[string]*ast.FuncDecl{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(routesDir, ent.Name()), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", ent.Name(), err)
		}
		files = append(files, parsed{ent.Name(), f})
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}

	// Gates passed as arguments to a registering function (the module gate
	// is applied this way): parameter name -> gate, per function.
	paramGates := map[string]map[string]Gate{}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := ce.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			callee, ok := funcs[id.Name]
			if !ok {
				return true
			}
			names, variadic := paramNames(callee)
			for i, a := range ce.Args {
				g := w.gateOf(a, nil)
				if len(g.Modules)+len(g.Permissions)+len(g.AnyOf)+len(g.Other) == 0 && g.MinRole == "" && !g.StepUp {
					continue
				}
				var pname string
				switch {
				case i < len(names):
					pname = names[i]
				case variadic && len(names) > 0:
					pname = names[len(names)-1]
				default:
					continue
				}
				if paramGates[id.Name] == nil {
					paramGates[id.Name] = map[string]Gate{}
				}
				pg := paramGates[id.Name][pname]
				merge(&pg, g)
				paramGates[id.Name][pname] = pg
			}
			return true
		})
	}

	var routes []Route
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			register := fn.Name.Name
			base := map[string]Gate{}
			for k, v := range paramGates[register] {
				base[k] = v
			}

			collectVars := func(block *ast.BlockStmt, parent map[string]Gate) map[string]Gate {
				vars := map[string]Gate{}
				for k, v := range parent {
					vars[k] = v
				}
				// Two passes so a variable built from another one resolves.
				for pass := 0; pass < 2; pass++ {
					ast.Inspect(block, func(m ast.Node) bool {
						if _, ok := m.(*ast.FuncLit); ok {
							return false
						}
						as, ok := m.(*ast.AssignStmt)
						if !ok {
							return true
						}
						for i, lhs := range as.Lhs {
							id, ok := lhs.(*ast.Ident)
							if !ok || i >= len(as.Rhs) {
								continue
							}
							g := w.gateOf(as.Rhs[i], vars)
							if len(g.Modules)+len(g.Permissions)+len(g.AnyOf)+len(g.Other) > 0 || g.MinRole != "" || g.StepUp {
								vars[id.Name] = g
							}
						}
						return true
					})
				}
				return vars
			}

			var process func(block *ast.BlockStmt, prefix string, inherited Gate, vars map[string]Gate)
			process = func(block *ast.BlockStmt, prefix string, inherited Gate, vars map[string]Gate) {
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
						g := clone(inherited)
						for _, a := range ce.Args[1:] {
							if fl, ok := a.(*ast.FuncLit); ok {
								if body == nil {
									body = fl.Body
								}
								continue
							}
							merge(&g, w.gateOf(a, vs))
						}
						if body != nil {
							process(body, prefix+gp, g, vs)
						}
						return false
					}
					switch sel.Sel.Name {
					case "GET", "POST", "PUT", "PATCH", "DELETE":
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
					g := clone(inherited)
					for _, a := range ce.Args[1:] {
						merge(&g, w.gateOf(a, vs))
					}
					full := prefix + p
					if len(full) > 1 {
						full = strings.TrimSuffix(full, "/")
					}
					routes = append(routes, Route{
						Method:   sel.Sel.Name,
						Path:     full,
						RawPath:  prefix + p,
						Register: register,
						File:     pf.name,
						Line:     fset.Position(ce.Pos()).Line,
						Gate:     normalize(g),
					})
					return true
				})
			}
			process(fn.Body, "", Gate{}, base)
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})
	if len(routes) < 100 {
		return nil, fmt.Errorf("parsed only %d routes: the route walker is broken", len(routes))
	}
	return routes, nil
}
