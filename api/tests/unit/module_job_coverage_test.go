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

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// jobInfrastructure are controller constructors that are not jobs of a
// module: the runner itself and generic building blocks.
var jobInfrastructure = map[string]string{
	"Manager":                "the controller runner",
	"PrometheusMetrics":      "controller metrics",
	"PurgeController":        "generic table purge, configured per retention policy",
	"ControlChangePublisher": "publishes control changes for other jobs; schedules nothing",
}

// Every background controller the server builds is owned by exactly one
// module of the registry (configs/modules.yaml, `jobs`), so a job of a
// module that can be switched off is a decision, not an accident (RFC-064 R2).
func TestEveryJobBelongsToAModule(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "cmd", "server")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	built := map[string]string{}
	fset := token.NewFileSet()
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, ent.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "New") {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "controller" {
				built[strings.TrimPrefix(sel.Sel.Name, "New")] = ent.Name() + ":" + itoa(fset.Position(ce.Pos()).Line)
			}
			return true
		})
	}
	if len(built) < 30 {
		t.Fatalf("found only %d controllers: the reader is broken, not the code", len(built))
	}

	owner := map[string]string{}
	for _, d := range moduledom.Registry {
		for _, j := range d.Jobs {
			owner[j] = d.ID
		}
	}
	var problems []string
	for name, pos := range built {
		if _, ok := jobInfrastructure[name]; ok {
			continue
		}
		if _, ok := owner[name]; !ok {
			problems = append(problems, name+" ("+pos+"): add it to the `jobs` of its module in configs/modules.yaml")
		}
	}
	for name, id := range owner {
		if _, ok := built[name]; !ok {
			problems = append(problems, id+" lists job "+name+", which the server does not build")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("background jobs and the module registry disagree:\n  %s", strings.Join(problems, "\n  "))
	}
}
