package openapicontract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/tools/lint/openapicontract"
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
// swagger.yaml, and if swag skipped a handler's @Router.
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
		t.Fatalf("reading spec: %v (the spec is generated, not committed: run `make swagger` in api/ or `make generate` at the repository root)", err)
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
		t.Errorf("%d operation(s) are annotated but absent from the generated spec.\n"+
			"swag did not read them: regenerate (`make swagger`) and check its log.\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	var extra []string
	for _, op := range openapicontract.SortedOps(specOps) {
		if _, ok := ann[op]; !ok {
			extra = append(extra, op.String())
		}
	}
	if len(extra) > 0 {
		t.Errorf("%d operation(s) are in the spec with no @Router annotation.\n"+
			"swagger.yaml is a GENERATED file — never hand-edit it. A path here that\n"+
			"no handler declares is exactly how the UI came to call\n"+
			"GET /api/v1/me/event-types against a server that never had it.\n"+
			"Regenerate it with `make swagger`.\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
}

// TestEveryDocumentedPathIsRouted is the phantom-endpoint check. 30 paths in
// the pre-generation spec had no handler and no route anywhere in the
// repository — /admin/platform-sensors, /plans, /tenants/{id}/subscription and
// friends, left over from a closed-source era. A client written against those
// gets a 404.
func TestEveryDocumentedPathIsRouted(t *testing.T) {
	_, routesDir, spec, _ := paths(t)

	specOps, err := openapicontract.SpecOps(spec)
	if err != nil {
		t.Fatalf("reading spec: %v (the spec is generated, not committed: run `make swagger` in api/ or `make generate` at the repository root)", err)
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
			"handler's @Router to the path it is really served on.\n  %s",
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
		t.Fatalf("reading spec: %v (the spec is generated, not committed: run `make swagger` in api/ or `make generate` at the repository root)", err)
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

// TestSensorProtocolV2Documented keeps the hand-maintained OpenAPI 3.1
// document of sensor protocol v2 (RFC-026) and the registered /api/v2/sensor
// routes in step, both ways. The generated swagger.yaml cannot hold them: it
// is Swagger 2.0 with basePath /api/v1.
func TestSensorProtocolV2Documented(t *testing.T) {
	_, routesDir, _, _ := paths(t)
	specPath := filepath.Join(repoRoot(t), "api", "openapi", "sensor-protocol-v2.yaml")

	spec, err := openapicontract.SpecOps(specPath)
	if err != nil {
		t.Fatalf("reading %s: %v", specPath, err)
	}
	routes, err := openapicontract.Routes(routesDir)
	if err != nil {
		t.Fatalf("reading routes: %v", err)
	}
	registered := map[openapicontract.Op]bool{}
	for op := range routes {
		if strings.HasPrefix(op.Path, "/api/v2/sensor/") {
			registered[op] = true
		}
	}
	if len(registered) == 0 {
		t.Fatal("no /api/v2/sensor route found; the route walk no longer resolves protov2.PathPrefix")
	}
	for op := range registered {
		if !spec[op] {
			t.Errorf("registered but not in sensor-protocol-v2.yaml: %s", op)
		}
	}
	for op := range spec {
		if !registered[op] {
			t.Errorf("in sensor-protocol-v2.yaml but not registered: %s", op)
		}
	}
}

// The probes live on the root router. They used to be annotated and mapped
// back to /health by a special case, so the spec advertised GET /api/v1/health
// and GET /api/v1/ready, both of which 404, while this gate passed. With the
// special case gone, an annotated /health maps to /api/v1/health and fails the
// "no registered route" check, as it should.
func TestRootProbesAreNotPartOfTheDocumentedSurface(t *testing.T) {
	for _, p := range []string{"/health", "/ready"} {
		if got := openapicontract.SpecToRoute(p); got != "/api/v1"+p {
			t.Errorf("SpecToRoute(%q) = %q; an annotation is always served under %s", p, got, openapicontract.BasePath)
		}
		if _, ok := openapicontract.RouteToSpec(p); ok {
			t.Errorf("RouteToSpec(%q) reports a documented path; root probes are outside the API spec", p)
		}
	}
}

// TestSpecParamNamesMatchRoutes is check D (RFC-041 §7). Checks A–C compare
// operations with every path parameter reduced to {}, so a spec that says
// /repositories/{repository_id} for a route registered as
// /repositories/{repositoryId} passes them — and every generated client then
// carries the spec's name, not the server's. This compares the names.
//
// Today's mismatches are frozen in api/openapi/param-name-drift.txt, which
// only shrinks: a new mismatch fails, and so does a line that no longer
// matches one.
func TestSpecParamNamesMatchRoutes(t *testing.T) {
	_, routesDir, spec, _ := paths(t)
	driftPath := filepath.Join(filepath.Dir(spec), "param-name-drift.txt")

	specRaw, err := openapicontract.SpecRawPaths(spec)
	if err != nil {
		t.Fatalf("reading spec: %v (the spec is generated, not committed: run `make swagger` in api/ or `make generate` at the repository root)", err)
	}
	routeRaw, err := openapicontract.RawRoutes(routesDir)
	if err != nil {
		t.Fatalf("reading routes: %v", err)
	}
	baseline, err := openapicontract.Baseline(driftPath)
	if err != nil {
		t.Fatalf("reading baseline: %v", err)
	}

	mismatched := map[openapicontract.Op]bool{}
	var fresh []string
	for _, op := range openapicontract.SortedOps(specRaw) {
		route, ok := routeRaw[op]
		if !ok {
			continue // TestEveryDocumentedPathIsRouted reports it
		}
		if strings.Join(openapicontract.ParamNames(route), ",") == strings.Join(openapicontract.ParamNames(specRaw[op]), ",") {
			continue
		}
		mismatched[op] = true
		if !baseline[op] {
			fresh = append(fresh, op.Method+" "+route+"  (spec: "+specRaw[op]+")")
		}
	}
	if len(fresh) > 0 {
		t.Errorf("%d documented operation(s) name their path parameters differently in the spec\n"+
			"and in the router. Make the handler's @Router use the route's names:\n  %s", len(fresh), strings.Join(fresh, "\n  "))
	}
	var stale []string
	for _, op := range openapicontract.SortedOps(baseline) {
		if !mismatched[op] {
			stale = append(stale, op.String())
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d line(s) in api/openapi/param-name-drift.txt no longer match a mismatch; delete them:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// TestWriteRouteManifest writes api/openapi/routes.txt, every registered API
// operation with its path parameters written {}. The web's endpoint check
// (web/src/lib/api/__tests__/endpoints-target-routes.test.ts) reads it.
//
// The file is generated, never committed: `make contract` in api/ (and the
// Web CI contract job) writes it from the router before the web tests run. A committed copy went stale every time two pull
// requests that add routes were in flight together, and each one then failed
// in the merge queue until it was regenerated.
//
// Write it locally with:
//
//	UPDATE_ROUTE_MANIFEST=1 go test ./tools/lint/openapicontract/ -run RouteManifest
func TestWriteRouteManifest(t *testing.T) {
	if os.Getenv("UPDATE_ROUTE_MANIFEST") != "1" {
		t.Skip("set UPDATE_ROUTE_MANIFEST=1 to write api/openapi/routes.txt")
	}
	_, routesDir, spec, _ := paths(t)
	manifest := filepath.Join(filepath.Dir(spec), "routes.txt")

	routes, err := openapicontract.Routes(routesDir)
	if err != nil {
		t.Fatalf("reading routes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("the router registers no routes; refusing to write an empty manifest")
	}
	var b strings.Builder
	b.WriteString("# GENERATED by tools/lint/openapicontract (TestWriteRouteManifest). Not committed.\n")
	b.WriteString("# Every registered API operation; path parameters are written {}.\n")
	for _, op := range openapicontract.SortedOps(routes) {
		b.WriteString(op.String() + "\n")
	}
	if err := os.WriteFile(manifest, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
