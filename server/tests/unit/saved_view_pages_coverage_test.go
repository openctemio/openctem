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
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/savedview"
)

// Every list page of the console offers saved views, so every page route of
// the web console and of the admin console is either a registered page key
// (pkg/domain/savedview/pages.go) or listed in savedview.PagesWithoutViews
// with its reason. A new list page that does neither fails here: register
// its key, or say why it has no views. Routes with a dynamic segment are
// detail and edit pages and are skipped.

var routeGroupRE = regexp.MustCompile(`\([^/)]*\)/?`)

// webPageRoutes lists the routes (page.tsx files) under an app directory.
func webPageRoutes(t *testing.T, appDir, prefix string) []string {
	t.Helper()
	var routes []string
	err := filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "page.tsx" {
			return nil
		}
		rel, err := filepath.Rel(appDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		route := "/" + strings.Trim(routeGroupRE.ReplaceAllString(filepath.ToSlash(rel)+"/", ""), "/")
		if rel == "." {
			route = "/"
		}
		if strings.Contains(route, "[") {
			return nil
		}
		routes = append(routes, prefix+route)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", appDir, err)
	}
	return routes
}

func TestSavedViewPages_EveryListRouteHasAKeyOrAnExclusion(t *testing.T) {
	web := filepath.Join(repoRoot(t), "..", "web")
	if _, err := os.Stat(filepath.Join(web, "src", "app")); err != nil {
		t.Skipf("the web console is not in this checkout: %v", err)
	}
	routes := webPageRoutes(t, filepath.Join(web, "src", "app", "(dashboard)"), "")
	routes = append(routes, webPageRoutes(t, filepath.Join(web, "console", "src", "app", "(console)"), "console:")...)
	if len(routes) < 150 {
		t.Fatalf("found %d page routes; the walker lost the route tree", len(routes))
	}

	registered := map[string]bool{}
	for _, p := range savedview.Pages() {
		registered[p.Route] = true
	}
	exists := map[string]bool{}
	var unclassified []string
	for _, route := range routes {
		exists[route] = true
		_, excluded := savedview.PagesWithoutViews[route]
		if !registered[route] && !excluded {
			unclassified = append(unclassified, route)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("%d page route(s) have neither a saved-view page key nor a documented exclusion.\n"+
			"A list page: add it to the registry in pkg/domain/savedview/pages.go (route and the permission that reads the list)\n"+
			"and to the table in docs/architecture/saved-views.md. Any other page: add it to PagesWithoutViews with its reason.\n  %s",
			len(unclassified), strings.Join(unclassified, "\n  "))
	}

	// The registry and the exclusions name only routes that exist.
	var stale []string
	for route := range registered {
		if !exists[route] {
			stale = append(stale, route+" (registered page)")
		}
	}
	for route := range savedview.PagesWithoutViews {
		if !exists[route] {
			stale = append(stale, route+" (exclusion)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("these routes are no longer in the web route tree; a renamed list keeps its key (set Key and Route apart), "+
			"a removed page leaves the lists:\n  %s", strings.Join(stale, "\n  "))
	}
}

// The page keys are part of the API: the architecture doc lists every one
// with its permission.
func TestSavedViewPages_DocumentedInTheArchitectureDoc(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "architecture", "saved-views.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, p := range savedview.Pages() {
		row := "| `" + p.Key + "` | `" + p.Route + "` | `" + p.Permission.String() + "` |"
		if !strings.Contains(doc, row) {
			t.Errorf("docs/architecture/saved-views.md lacks the row %q", row)
		}
	}
	// No row of a key that is not registered.
	start, end := strings.Index(doc, "### Page keys"), strings.Index(doc, "### Pages without views")
	if start < 0 || end < start {
		t.Fatal("docs/architecture/saved-views.md lacks the Page keys section")
	}
	if n, want := strings.Count(doc[start:end], "\n| `"), len(savedview.Pages()); n != want {
		t.Errorf("the doc table has %d rows, the registry %d pages", n, want)
	}
}

// The /api/v1/views routes are gated by "any read permission of a list that
// has views", written out in routes/saved_views.go for the route gate tools.
// It must be exactly the set the page registry names: a page whose permission
// is missing there could not use its views, and a permission no page names
// would let a caller through the route for nothing.
func TestSavedViewRouteGateIsTheRegistry(t *testing.T) {
	root := repoRoot(t)
	perms := loadPermissionValues(t, root)
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "internal", "infra", "http", "routes", "saved_views.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	gate := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "registerSavedViewRoutes" {
			return true
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "RequireAny" {
				return true
			}
			for _, arg := range call.Args {
				sel, ok := arg.(*ast.SelectorExpr)
				if !ok {
					t.Errorf("the saved views route gate has an argument that is not a permission constant")
					continue
				}
				value, known := perms[sel.Sel.Name]
				if !known {
					t.Errorf("permission.%s is not a permission constant", sel.Sel.Name)
				}
				gate[value] = true
			}
			return false
		})
		return false
	})
	want := map[string]bool{}
	for _, p := range savedview.ReadPermissions() {
		want[p.String()] = true
		if !gate[p.String()] {
			t.Errorf("%s reads a list that has views but is not in the /api/v1/views route gate (routes/saved_views.go)", p)
		}
	}
	for p := range gate {
		if !want[p] {
			t.Errorf("%s is in the /api/v1/views route gate but no registered page names it", p)
		}
	}
	if len(gate) == 0 {
		t.Fatal("no route gate found in registerSavedViewRoutes")
	}
}
