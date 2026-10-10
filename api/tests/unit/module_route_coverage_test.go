package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// Every route follows the module the registry (configs/modules.yaml) says it
// belongs to, in both directions (RFC-064 R2, R5):
//
//   - a route under a module's `routes` prefix is gated by RequireModule for
//     that module;
//   - a route gated by RequireModule for a non-core module is declared under
//     that module's `routes`;
//   - every declared prefix matches at least one route.
//
// The gate is read from the route source: a RequireModule(moduledom.X) call in
// the route's (or an enclosing group's) middleware, or the registering
// function's moduleGate parameter, resolved at the call site that passes
// RequireModule to it.

// registryConsts maps a Go constant name of the registry to its module id.
func registryConsts(t *testing.T, root string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "configs", "modules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var mods []struct {
		ID    string `yaml:"id"`
		Const string `yaml:"const"`
	}
	if err := yaml.Unmarshal(raw, &mods); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, m := range mods {
		out[m.Const] = m.ID
	}
	return out
}

// moduleCallSites maps "<function>|<gate parameter>" to the module gates its
// callers pass in that parameter: "const:ModuleX", or "fwd:<caller>|<param>"
// when a caller forwards one of its own gate parameters.
func moduleCallSites(t *testing.T, root string) map[string][]string {
	t.Helper()
	dir := filepath.Join(root, "internal", "infra", "http", "routes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string][]string{}
	params := map[string][]string{} // function -> parameter names, in order
	fset := token.NewFileSet()
	var files []*ast.File
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, ent.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				for _, fld := range fn.Type.Params.List {
					for _, n := range fld.Names {
						params[fn.Name.Name] = append(params[fn.Name.Name], n.Name)
					}
				}
			}
		}
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee, ok := ce.Fun.(*ast.Ident)
				if !ok || !strings.HasPrefix(callee.Name, "register") {
					return true
				}
				names := params[callee.Name]
				for i, a := range ce.Args {
					if i >= len(names) {
						break
					}
					key := callee.Name + "|" + names[i]
					switch mod := moduleGateOf(a, nil); {
					case strings.HasPrefix(mod, "const:"):
						sites[key] = append(sites[key], mod)
					case strings.HasPrefix(mod, "param:"):
						sites[key] = append(sites[key], "fwd:"+fn.Name.Name+"|"+strings.TrimPrefix(mod, "param:"))
					}
				}
				return true
			})
		}
	}
	return sites
}

// pathSegments splits a route path, writing every path parameter as {}.
func pathSegments(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range parts {
		if strings.HasPrefix(s, "{") {
			parts[i] = "{}"
		}
	}
	return parts
}

func prefixMatches(prefix, path string) bool {
	ps, rs := pathSegments(prefix), pathSegments(path)
	if len(ps) > len(rs) {
		return false
	}
	for i := range ps {
		if ps[i] != rs[i] {
			return false
		}
	}
	return true
}

// expectedModule is the module whose declared prefix matches the path
// longest ("" when none does: the route is core).
func expectedModule(path string) (string, string) {
	best, bestPrefix := "", ""
	for _, d := range moduledom.Registry {
		for _, p := range d.Routes {
			if prefixMatches(p, path) && len(pathSegments(p)) > len(pathSegments(bestPrefix)) {
				best, bestPrefix = d.ID, p
			}
		}
	}
	return best, bestPrefix
}

func TestEveryRouteFollowsTheModuleRegistry(t *testing.T) {
	root := repoRoot(t)
	consts := registryConsts(t, root)
	sites := moduleCallSites(t, root)

	// resolve turns a gate reference into module ids ("" = none).
	var resolve func(ref, fn string, depth int) []string
	resolve = func(ref, fn string, depth int) []string {
		switch {
		case ref == "":
			return []string{""}
		case strings.HasPrefix(ref, "const:"):
			id, ok := consts[strings.TrimPrefix(ref, "const:")]
			if !ok {
				t.Errorf("RequireModule(%s) names no registry module", strings.TrimPrefix(ref, "const:"))
			}
			return []string{id}
		case strings.HasPrefix(ref, "param:") && depth < 5:
			var out []string
			for _, s := range sites[fn+"|"+strings.TrimPrefix(ref, "param:")] {
				if strings.HasPrefix(s, "fwd:") {
					caller, param, _ := strings.Cut(strings.TrimPrefix(s, "fwd:"), "|")
					out = append(out, resolve("param:"+param, caller, depth+1)...)
				} else {
					out = append(out, resolve(s, "", depth+1)...)
				}
			}
			if len(out) == 0 {
				// A moduleGate parameter that no caller fills: the gate is nil
				// (fail-open), i.e. no module.
				return []string{""}
			}
			return out
		}
		return []string{""}
	}

	routes := parseRoutes(t)
	usedPrefix := map[string]bool{}
	var problems []string
	gated := 0
	for _, r := range routes {
		want, prefix := expectedModule(r.path)
		if prefix != "" {
			usedPrefix[prefix] = true
		}
		got := map[string]bool{}
		for _, id := range resolve(r.module, r.fn, 0) {
			if moduledom.IsCoreModule(id) {
				id = "" // a core gate always lets through
			}
			got[id] = true
		}
		if len(got) > 1 {
			problems = append(problems, r.method+" "+r.path+": "+r.fn+" is called with different module gates for it")
			continue
		}
		var actual string
		for id := range got {
			actual = id
		}
		if actual != "" {
			gated++
		}
		switch {
		case actual == want:
		case want == "":
			problems = append(problems, r.method+" "+r.path+" ("+r.pos+"): gated by "+actual+
				" but not declared: add the prefix to "+actual+".routes in configs/modules.yaml")
		case actual == "":
			problems = append(problems, r.method+" "+r.path+" ("+r.pos+"): declared under "+want+
				" ("+prefix+") but not gated: add RequireModule(...) for it, or move the prefix")
		default:
			problems = append(problems, r.method+" "+r.path+" ("+r.pos+"): declared under "+want+" but gated by "+actual)
		}
	}
	for _, d := range moduledom.Registry {
		for _, p := range d.Routes {
			if !usedPrefix[p] {
				problems = append(problems, d.ID+": declared route prefix "+p+" matches no route")
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("routes and the module registry disagree:\n  %s", strings.Join(problems, "\n  "))
	}
	if gated < 50 {
		t.Fatalf("only %d module-gated routes found: the gate reader is broken, not the code", gated)
	}
	t.Logf("%d of %d routes are module-gated", gated, len(routes))
}
