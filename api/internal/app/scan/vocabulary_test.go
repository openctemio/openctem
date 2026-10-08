package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// "Pipeline" names the customer CI pipeline only (docs glossary). A refusal,
// run message or audit message of the scan packages says scan workflow, scan
// or scan run. A string naming the CI pipeline, and error codes kept for API
// compatibility (PIPELINE_*), are the exceptions.
func TestScanMessagesDoNotSayPipeline(t *testing.T) {
	dirs := []string{
		".",
		"../scanrun",
		"../../../pkg/domain/scan",
		"../../../pkg/domain/scanrun",
		"../../../pkg/domain/scanworkflow",
	}
	code := regexp.MustCompile(`^PIPELINE_[A-Z_]+$`)
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s := strings.Trim(lit.Value, "\"`")
				lower := strings.ReplaceAll(strings.ToLower(s), "ci pipeline", "")
				if strings.Contains(lower, "pipeline") && !code.MatchString(s) {
					t.Errorf("%s: string %s says pipeline; use scan workflow, scan or scan run", fset.Position(lit.Pos()), lit.Value)
				}
				return true
			})
		}
	}
}
