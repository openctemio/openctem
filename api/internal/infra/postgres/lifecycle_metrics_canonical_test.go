package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Metrics stay canonical (docs/rfcs/RFC-110-tenant-lifecycles.md, T3): the
// dashboards, program and cycle metrics, SLA and risk snapshots read the
// canonical status and closure reason only, never an organization's
// sub-status, so a lifecycle scheme can never change what a metric means.
func TestMetricQueriesNeverReadSubStatus(t *testing.T) {
	patterns := []string{
		"dashboard_*.go", "ctem_cycle_metrics*.go", "finding_sla*.go", "risk_*.go", "*metrics*.go",
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		files, err := filepath.Glob(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || seen[f] {
				continue
			}
			seen[f] = true
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), "sub_status") {
				t.Errorf("%s reads sub_status: metrics must read the canonical status and closure reason only", f)
			}
		}
	}
	if len(seen) < 3 {
		t.Fatalf("matched only %d metric files; the patterns no longer find the metric repositories", len(seen))
	}
}
