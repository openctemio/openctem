// Command routepermcheck runs the route-permission analyzer as a
// single-checker binary. Example:
//
//	go run ./tools/lint/routeperm/cmd ./internal/infra/http/routes/...
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/openctemio/api/tools/lint/routeperm"
)

func main() {
	singlechecker.Main(routeperm.Analyzer)
}
