package openapicontract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/api/tools/lint/openapicontract"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find go.mod above %s", wd)
	return ""
}

func paths(t *testing.T) (handlerDir, routesDir, spec, baseline string) {
	root := repoRoot(t)
	return filepath.Join(root, "internal", "infra", "http", "handler"),
		filepath.Join(root, "internal", "infra", "http", "routes"),
		filepath.Join(root, "api", "openapi", "swagger.yaml"),
		filepath.Join(root, "api", "openapi", "undocumented-routes.txt")
}

// TestSpecMatchesAnnotations is what makes the spec a generated artifact rather
// than a hand-maintained document. It fails if a path was hand-added to
// swagger.yaml, and if a handler's @Router changed without `make swagger`.
//
// This replaces a byte-for-byte diff of the regenerated spec. That was tried
// and does not hold: swag emits `format: int64` for some map[string]int64
// fields on a developer machine and not on a clean CI runner, with the same
// swag version, the same Go 1.26.5 and a freshly downloaded module cache. The
// two documents say the same thing about the same Go types, so a byte gate
// fails on a non-disagreement that the developer who trips it cannot fix.
func TestSpecMatchesAnnotations(t *testing.T) {
	handlerDir, _, spec, _ := paths(t)

	ann, err := openapicontract.Annotations(handlerDir)
	if err != nil {
		t.Fatalf("reading @Router annotations: %v", err)
	}
	if len(ann) == 0 {
		t.Fatal("found no @Router annotations — the scan is broken, not the code")
	}

	specOps, err := openapicontract.SpecOps(spec)
	if err != nil {
		t.Fatalf("reading spec: %v", err)
	}
	if len(specOps) == 0 {
		t.Fatal("spec declares no operations — the parse is broken, not the code")
	}

	var missing []string
	for _, op := range openapicontract.SortedOps(ann) {
		if !specOps[op] {
			missing = append(missing, op.String()+"  (annotated at "+ann[op]+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d operation(s) are annotated but absent from the committed spec.\n"+
			"The spec is generated: run `make swagger` and commit the result.\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	var extra []string
	for _, op := range openapicontract.SortedOps(specOps) {
		if _, ok := ann[op]; !ok {
			extra = append(extra, op.String())
		}
	}
	if len(extra) > 0 {
		t.Errorf("%d operation(s) are in the committed spec with no @Router annotation.\n"+
			"swagger.yaml is a GENERATED file — never hand-edit it. A path here that\n"+
			"no handler declares is exactly how the UI came to call\n"+
			"GET /api/v1/me/event-types against a server that never had it.\n"+
			"Run `make swagger` and commit the result.\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
}

// TestEveryDocumentedPathIsRouted is the phantom-endpoint check. 30 paths in
// the pre-generation spec had no handler and no route anywhere in the
// repository — /admin/platform-agents, /plans, /tenants/{id}/subscription and
// friends, left over from a closed-source era. A client written against those
// gets a 404.
func TestEveryDocumentedPathIsRouted(t *testing.T) {
	_, routesDir, spec, _ := paths(t)

	specOps, err := openapicontract.SpecOps(spec)
	if err != nil {
		t.Fatalf("reading spec: %v", err)
	}
	routes, err := openapicontract.Routes(routesDir)
	if err != nil {
		t.Fatalf("reading routes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("found no registered routes — the AST walk is broken, not the code")
	}

	var phantom []string
	for _, op := range openapicontract.SortedOps(specOps) {
		want := openapicontract.Op{
			Method: op.Method,
			Path:   openapicontract.NormalizePath(openapicontract.SpecToRoute(op.Path)),
		}
		if _, ok := routes[want]; !ok {
			phantom = append(phantom, op.String()+"  (would need "+want.String()+")")
		}
	}
	if len(phantom) > 0 {
		t.Errorf("%d documented operation(s) have no registered route — a client\n"+
			"calling them gets a 404. Either register the route, or correct the\n"+
			"handler's @Router to the path it is really served on and rerun\n"+
			"`make swagger`.\n  %s",
			len(phantom), strings.Join(phantom, "\n  "))
	}
}

// TestEveryRouteIsDocumentedOrBaselined freezes the documentation debt. 439
// registered routes carry no annotation today; annotating them is a separate
// effort. What must not happen again is a NEW endpoint shipping undocumented —
// that is how the entire /notifications API, GET /auth/providers and
// GET /scans/coverage stayed invisible to every generated client.
//
// Adding a route without an annotation therefore fails here, and the only way
// past is to add it to api/openapi/undocumented-routes.txt in the same commit,
// where a reviewer sees the choice.
func TestEveryRouteIsDocumentedOrBaselined(t *testing.T) {
	_, routesDir, spec, baselinePath := paths(t)

	specOps, err := openapicontract.SpecOps(spec)
	if err != nil {
		t.Fatalf("reading spec: %v", err)
	}
	routes, err := openapicontract.Routes(routesDir)
	if err != nil {
		t.Fatalf("reading routes: %v", err)
	}
	baseline, err := openapicontract.Baseline(baselinePath)
	if err != nil {
		t.Fatalf("reading baseline: %v", err)
	}

	var undocumented []string
	for _, op := range openapicontract.SortedOps(routes) {
		specPath, ok := openapicontract.RouteToSpec(op.Path)
		if !ok {
			// Outside /api/v1 and not a known probe: not part of the documented
			// surface at all (websocket upgrades, static handlers).
			continue
		}
		specOp := openapicontract.Op{Method: op.Method, Path: openapicontract.NormalizePath(specPath)}
		if specOps[specOp] || baseline[op] {
			continue
		}
		undocumented = append(undocumented, op.String()+"  (registered at "+routes[op]+")")
	}
	if len(undocumented) > 0 {
		t.Errorf("%d registered route(s) are neither documented nor baselined:\n  %s\n\n"+
			"Add a // @Router annotation to the handler and run `make swagger`, or —\n"+
			"if documenting it now is genuinely out of scope — add the line to\n"+
			"api/openapi/undocumented-routes.txt so the choice is visible in review.",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}

	// A baseline entry that no longer names a real route is stale: the route was
	// removed or documented, and leaving it behind lets a future route slip in
	// under a name that was already forgiven.
	var stale []string
	for _, op := range openapicontract.SortedOps(baseline) {
		if _, ok := routes[op]; !ok {
			stale = append(stale, op.String())
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d baseline entr(ies) no longer match a registered route — remove\n"+
			"them from api/openapi/undocumented-routes.txt:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}
