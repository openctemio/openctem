package routeperm_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/openctemio/api/tools/lint/routeperm"
)

// analysistest drives two fixture packages.
//  - "flagged" has POST/PUT/etc without middleware.Require → must flag.
//  - "safe" covers every acceptable pattern (Require present, opt-out
//    comment, non-write method).

func TestAnalyzer_FindsUnprotected(t *testing.T) {
	wd, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, wd, routeperm.Analyzer, "flagged")
}

func TestAnalyzer_AcceptsSafeVariants(t *testing.T) {
	wd, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, wd, routeperm.Analyzer, "safe")
}
