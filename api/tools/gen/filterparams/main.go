// Command filterparams regenerates the swag @Param blocks of the list
// query contract (docs/rfcs/RFC-048-list-query-contract.md) from the field
// registries, in every handler file that has a "// filterspec-params:"
// block. Run it from api/ after changing a registry, then `make swagger`.
//
//	go run ./tools/gen/filterparams
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func main() {
	files, err := filepath.Glob("internal/infra/http/handler/*.go")
	if err != nil || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "filterparams: run from api/ (no handler files found)")
		os.Exit(2)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // developer tool over the repo's own files
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !strings.Contains(string(b), filterspec.ParamMarker) {
			continue
		}
		out, blocks, err := filterspec.RewriteParamBlocks(string(b), handler.FilterRegistries())
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f, err)
			os.Exit(1)
		}
		if out != string(b) {
			if err := os.WriteFile(f, []byte(out), 0o644); err != nil { //nolint:gosec // source file mode
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("%s: regenerated %s\n", f, strings.Join(blocks, "; "))
		}
	}
}
