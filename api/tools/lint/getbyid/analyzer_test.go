package getbyid_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/openctemio/api/tools/lint/getbyid"
)

// F-310: analysistest-driven test for the tenant-scope analyzer.
//
// We ship two tiny packages under testdata:
//   - "flagged" contains a GetByID(ctx, id) that must produce a
//     diagnostic
//   - "safe" contains variants that MUST NOT produce a diagnostic
//     (tenant param, rename, opt-out directive)
//
// analysistest reads `// want "..."` comments next to the expected
// diagnostic and compares.

func TestAnalyzer_FindsUnscoped(t *testing.T) {
	wd, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, wd, getbyid.Analyzer, "flagged")
}

func TestAnalyzer_IgnoresSafeVariants(t *testing.T) {
	wd, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, wd, getbyid.Analyzer, "safe")
}
