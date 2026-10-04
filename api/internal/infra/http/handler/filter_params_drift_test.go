package handler

// Query-param drift check for the list query contract (RFC-048 §3.10): the
// swag @Param blocks are generated from the field registries, and the
// committed OpenAPI spec documents exactly the params the parser accepts
// for each registry-backed operation. A failure names the fix.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// filterOperations are the operations that parse their query with a
// registry, with the params they read outside it.
var filterOperations = []struct {
	path, method, registry string
	extra                  []string
}{
	{"/findings", "get", "findings", []string{"q", "sort", "page", "per_page"}},
	{"/findings/stats", "get", "findings", []string{"q"}},
	{"/findings/groups", "get", "findings", []string{"q", "sort", "page", "per_page", "group_by"}},
	{"/findings/export", "get", "findings", []string{"q", "format"}},
	{"/findings/related-cves/{cveId}", "get", "findings", []string{"q"}},
}

func TestFilterParamBlocksAreGenerated(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // test reads its own package
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), filterspec.ParamMarker) {
			continue
		}
		out, blocks, err := filterspec.RewriteParamBlocks(string(b), FilterRegistries())
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if out != string(b) {
			t.Errorf("%s: generated @Param block is stale; run `go run ./tools/gen/filterparams` then `make swagger` from api/", f)
		}
		for _, bl := range blocks {
			found[bl] = true
		}
	}
	for _, op := range filterOperations {
		key := op.registry + " " + strings.ToUpper(op.method) + " " + op.path
		if !found[key] {
			t.Errorf("no generated @Param block %q", key)
		}
	}
}

func TestOpenAPIDocumentsFilterParams(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "openapi", "swagger.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	regs := FilterRegistries()
	for _, op := range filterOperations {
		reg := regs[op.registry]
		want := map[string]bool{}
		for _, p := range reg.SwagParams() {
			want[p.Name] = true
		}
		for _, e := range op.extra {
			want[e] = true
		}
		got := map[string]bool{}
		for _, p := range spec.Paths[op.path][op.method].Parameters {
			if p.In == "query" {
				got[p.Name] = true
			}
		}
		var missing, extra []string
		for n := range want {
			if !got[n] {
				missing = append(missing, n)
			}
		}
		for n := range got {
			if !want[n] {
				extra = append(extra, n)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("%s %s: spec query params differ from the parser (missing %v, not accepted %v); run `make swagger` from api/",
				strings.ToUpper(op.method), op.path, missing, extra)
		}
	}
}
