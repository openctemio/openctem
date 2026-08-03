// Package openapicontract checks that three descriptions of this server's HTTP
// surface agree: the // @Router annotations on the handlers, the committed
// OpenAPI spec, and the routes actually registered with the router.
//
// # WHY NOT A BYTE COMPARISON OF THE SPEC
//
// The obvious gate is "regenerate the spec and diff it". That was tried and
// does not hold: swag is not hermetic across environments. On a clean CI runner
// it emits `format: int64` for some map[string]int64 fields and not others,
// while the same swag version, the same Go toolchain (1.26.5) and a freshly
// downloaded module cache produce the format locally. The difference describes
// no disagreement about the API — both documents say the same thing about the
// same Go types — but a byte gate fails on it, cannot be satisfied by the
// developer who trips it, and would be weakened or deleted within a week.
//
// So gate the property the work was actually about. Every cross-repo bug that
// motivated this was structural:
//
//   - 30 documented paths had no handler and no route anywhere in the repo
//     (/admin/platform-agents, /plans, /tenants/{id}/subscription, ...), which
//     is how the UI came to call GET /api/v1/me/event-types against a server
//     that never had it, and to render OAuth buttons that 404'd.
//   - 40 real endpoints were undocumented, the whole /notifications API among
//     them, so no generated client could see them.
//
// Set comparison catches both exactly, and is stable across swag's formatting.
//
// THE THREE CHECKS
//
//	A. annotations == spec
//	   Every // @Router in internal/infra/http/handler must appear as a
//	   path+method in the committed spec, and vice versa. This is what makes
//	   the spec "generated": you cannot hand-add a path, and you cannot change
//	   an annotation without running `make swagger`.
//
//	B. spec ⊆ routes
//	   Every documented path+method must be registered on the router. This is
//	   the phantom-endpoint check.
//
//	C. routes ⊆ spec ∪ baseline
//	   Every registered route must be documented, or listed in
//	   api/openapi/undocumented-routes.txt. 439 routes are undocumented today;
//	   annotating them is a large separate effort, so the baseline freezes that
//	   debt instead of ignoring it. A NEW route must be documented or must be
//	   added to the baseline deliberately, in the same commit, where a reviewer
//	   sees it.
package openapicontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// BasePath is the swagger `@BasePath`. Annotations and spec paths are relative
// to it; registered routes carry it literally.
const BasePath = "/api/v1"

// Op is one HTTP operation, normalised for comparison: method upper-cased and
// path parameters reduced to {} so that {id} and {groupId} compare equal.
type Op struct {
	Method string
	Path   string
}

func (o Op) String() string { return o.Method + " " + o.Path }

var paramRe = regexp.MustCompile(`\{[^}]*\}`)

// NormalizePath reduces path parameters to a positional {} so that a rename of
// the parameter is not reported as a contract change.
func NormalizePath(p string) string { return paramRe.ReplaceAllString(p, "{}") }

func norm(method, path string) Op {
	return Op{Method: strings.ToUpper(method), Path: NormalizePath(path)}
}

// rootOnlyPaths are registered on the root router rather than under BasePath,
// deliberately: liveness and readiness probes must not require a version prefix
// or auth. Swagger 2.0 has no per-operation basePath, so the spec renders them
// as /api/v1/health and /api/v1/ready. This is the one place the spec cannot be
// literally true, and it is recorded here rather than papered over.
var rootOnlyPaths = map[string]bool{
	"/health": true,
	"/ready":  true,
}

// ---------------------------------------------------------------------------
// 1. @Router annotations
// ---------------------------------------------------------------------------

var routerRe = regexp.MustCompile(`^\s*//\s*@Router\s+(\S+)\s+\[([a-zA-Z]+)\]`)

// Annotations returns every // @Router operation declared under handlerDir.
func Annotations(handlerDir string) (map[Op]string, error) {
	found := map[Op]string{}
	err := filepath.Walk(handlerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // repo-local path from the caller
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			m := routerRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			op := norm(m[2], m[1])
			found[op] = fmt.Sprintf("%s:%d", path, i+1)
		}
		return nil
	})
	return found, err
}

// ---------------------------------------------------------------------------
// 2. The committed spec
// ---------------------------------------------------------------------------

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true,
	"head": true, "options": true,
}

// SpecOps returns every path+method declared in the committed OpenAPI document.
func SpecOps(specPath string) (map[Op]bool, error) {
	data, err := os.ReadFile(specPath) //nolint:gosec // repo-local path from the caller
	if err != nil {
		return nil, err
	}
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", specPath, err)
	}
	ops := map[Op]bool{}
	for p, methods := range doc.Paths {
		for m := range methods {
			if !httpMethods[strings.ToLower(m)] {
				continue // parameters, $ref, x-* extensions
			}
			ops[norm(m, p)] = true
		}
	}
	return ops, nil
}

// ---------------------------------------------------------------------------
// 3. Registered routes
// ---------------------------------------------------------------------------

var routeMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// Routes returns every route registered under routesDir, with its full path
// including the BasePath prefix the Group calls supply.
//
// Registration nests: router.Group("/api/v1/x", func(r Router) { r.GET("/y", h) })
// so the walk carries the accumulated prefix down into each Group's function
// literal. Parsing the AST rather than grepping matters here — a regex cannot
// tell which Group a method call belongs to.
func Routes(routesDir string) (map[Op]string, error) {
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	found := map[Op]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(routesDir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			collect(fset, fn.Body, "", found)
		}
	}
	return found, nil
}

func collect(fset *token.FileSet, n ast.Node, prefix string, out map[Op]string) {
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}

		switch {
		case sel.Sel.Name == "Group" && len(call.Args) >= 2:
			body, ok := call.Args[1].(*ast.FuncLit)
			if !ok {
				return true
			}
			collect(fset, body.Body, join(prefix, s), out)
			return false // the recursion above already covered this subtree
		case routeMethods[sel.Sel.Name]:
			full := join(prefix, s)
			out[norm(sel.Sel.Name, full)] = fset.Position(call.Pos()).String()
		}
		return true
	})
}

func join(prefix, path string) string {
	if path == "" || path == "/" {
		if prefix == "" {
			return "/"
		}
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + path
}

// ---------------------------------------------------------------------------
// 4. The undocumented-route baseline
// ---------------------------------------------------------------------------

// Baseline reads the frozen list of registered-but-undocumented routes.
// Blank lines and # comments are ignored.
func Baseline(path string) (map[Op]bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // repo-local path from the caller
	if err != nil {
		return nil, err
	}
	out := map[Op]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed baseline line %q: want 'METHOD /path'", line)
		}
		out[norm(parts[0], parts[1])] = true
	}
	return out, nil
}

// SpecToRoute maps a spec/annotation path onto the route path it should serve.
func SpecToRoute(specPath string) string {
	if rootOnlyPaths[specPath] {
		return specPath
	}
	return BasePath + specPath
}

// RouteToSpec maps a registered route path back onto its spec path, reporting
// false when the route lives outside BasePath and is not a known root-only one.
func RouteToSpec(routePath string) (string, bool) {
	if rootOnlyPaths[routePath] {
		return routePath, true
	}
	if !strings.HasPrefix(routePath, BasePath+"/") {
		return "", false
	}
	return strings.TrimPrefix(routePath, BasePath), true
}

// SortedOps returns ops in a stable order for reporting.
func SortedOps[V any](m map[Op]V) []Op {
	out := make([]Op, 0, len(m))
	for op := range m {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
