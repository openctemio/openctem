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
)

// Step-up follows the action, not the path (docs/architecture/step-up-reauth.md).
// A service action that needs a recent sign-in must need it on EVERY route
// that reaches it: a second route to the same action without requireStepUp()
// is a bypass (a stolen session uses the unprotected door). This test maps
// each action below to every handler that reaches it, directly or through an
// application-service method, then to every route that registers one of those
// handlers, and fails when such a route lacks step-up.

// stepUpServiceActions are the service methods that require step-up on every
// route that reaches them, each with the reason.
var stepUpServiceActions = map[string]string{
	"OffboardMember":          "strips a member's access and reassigns their work",
	"EraseMemberPersonalData": "irreversibly anonymises a person",
	"ResetMemberMFA":          "removes another member's second factor",
	"CreateSensor":            "mints a persistent sensor key",
	"RegenerateAPIKey":        "mints a persistent sensor key",
	"RevealSecret":            "returns a leaked credential in plaintext",
}

// machinePlanes authenticate a machine, or a principal that cannot
// re-authenticate interactively; the rule is about the user planes. The
// admin console has its own step-up on the console session.
var machinePlanes = []string{
	"/api/v1/admin", "/scim/v2", "/api/v1/scim", "/api/v2/sensor",
	"/api/v1/ci/runs", "/api/v1/webhooks", "/api/v1/mcp",
}

// methodCalls parses every non-test Go file under dir (recursively when
// recursive is set) and maps "Type.Method" to the names of the methods it
// calls, directly or through other methods of the same receiver.
//
//nolint:gocognit,cyclop // one AST walk plus a fixed-point closure
func methodCalls(t *testing.T, dir string, recursive bool) map[string]map[string]bool {
	t.Helper()
	direct := map[string]map[string]bool{} // Type.Method -> called names
	self := map[string]map[string]bool{}   // Type.Method -> same-receiver methods called
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
				continue
			}
			rt := fn.Recv.List[0].Type
			if st, ok := rt.(*ast.StarExpr); ok {
				rt = st.X
			}
			id, ok := rt.(*ast.Ident)
			if !ok {
				continue
			}
			recv := ""
			if len(fn.Recv.List[0].Names) > 0 {
				recv = fn.Recv.List[0].Names[0].Name
			}
			key := id.Name + "." + fn.Name.Name
			if direct[key] == nil {
				direct[key], self[key] = map[string]bool{}, map[string]bool{}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
					direct[key][sel.Sel.Name] = true
					if x, ok := sel.X.(*ast.Ident); ok && recv != "" && x.Name == recv {
						self[key][id.Name+"."+sel.Sel.Name] = true
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	// Close over same-receiver helpers until nothing changes.
	for changed := true; changed; {
		changed = false
		for key, own := range self {
			for callee := range own {
				for name := range direct[callee] {
					if !direct[key][name] {
						direct[key][name] = true
						changed = true
					}
				}
			}
		}
	}
	return direct
}

// handlerReach maps "Type.Method" of every handler method to the method names
// it reaches: what it calls, plus what any application-service method of a
// called name calls (a handler calling a service method that offboards
// reaches OffboardMember). Matching is by method name, so it over-approximates:
// a false match fails the test (the safe direction), never hides a route.
func handlerReach(t *testing.T) map[string]map[string]bool {
	t.Helper()
	root := repoRoot(t)
	handlers := methodCalls(t, filepath.Join(root, "internal", "infra", "http", "handler"), false)
	services := methodCalls(t, filepath.Join(root, "internal", "app"), true)
	byName := map[string]map[string]bool{} // service method name -> names it reaches
	for key, calls := range services {
		name := key[strings.LastIndex(key, ".")+1:]
		if byName[name] == nil {
			byName[name] = map[string]bool{}
		}
		for c := range calls {
			byName[name][c] = true
		}
	}
	for _, calls := range handlers {
		for c := range calls {
			for reached := range byName[c] {
				calls[reached] = true
			}
		}
	}
	return handlers
}

func TestStepUp_EveryRouteToAStepUpActionRequiresIt(t *testing.T) {
	reach := handlerReach(t)
	routes := parseRoutes(t)

	reaches := func(r routeRec, action string) bool {
		if r.handlerMethod == "" {
			return false
		}
		if r.handlerType != "" {
			return reach[r.handlerType+"."+r.handlerMethod][action]
		}
		// Receiver is a local variable: any handler type with that method.
		for key, calls := range reach {
			if strings.HasSuffix(key, "."+r.handlerMethod) && calls[action] {
				return true
			}
		}
		return false
	}

	used := map[string]bool{}
	var missing []string
	for _, r := range routes {
		machine := false
		for _, p := range machinePlanes {
			machine = machine || strings.HasPrefix(r.path, p)
		}
		if machine {
			continue
		}
		for action, why := range stepUpServiceActions {
			if !reaches(r, action) {
				continue
			}
			used[action] = true
			if !r.stepUp {
				missing = append(missing, r.method+" "+r.path+" ("+r.pos+") reaches "+action+" ("+why+") without requireStepUp()")
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("routes that reach a step-up action without step-up:\n  %s", strings.Join(missing, "\n  "))
	}
	for action := range stepUpServiceActions {
		if !used[action] {
			t.Errorf("%s: no route reaches it; the AST mapping is broken or the entry is stale", action)
		}
	}
}
