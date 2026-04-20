// Command getbyidtenant runs the F-310 tenant-scope analyzer as a
// single-checker binary. Example invocation:
//
//	go run ./tools/lint/getbyid/cmd ./internal/infra/postgres/...
//
// It exits non-zero when any flagged GetByID / UpdateByID / DeleteByID
// lacks a tenantID parameter, making it usable in CI.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/openctemio/api/tools/lint/getbyid"
)

func main() {
	singlechecker.Main(getbyid.Analyzer)
}
