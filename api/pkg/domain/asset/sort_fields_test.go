package asset

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Criticality and exposure are text columns: sorting them by spelling put
// "low" above "medium" and "isolated" above "public". They sort by rank.
func TestAllowedSortFields_RankedLevels(t *testing.T) {
	got := pagination.NewSortOption(AllowedSortFields()).Parse("-criticality,exposure").SQLWithTieBreaker("a.id")
	if !strings.HasPrefix(got, CriticalityRankSQL+" DESC, "+ExposureRankSQL+" ASC") {
		t.Fatalf("ORDER BY = %q, want the rank expressions", got)
	}
	for _, level := range []string{"'critical' THEN 4", "'high' THEN 3", "'medium' THEN 2", "'low' THEN 1"} {
		if !strings.Contains(CriticalityRankSQL, level) {
			t.Errorf("criticality rank misses %s", level)
		}
	}
	for _, level := range []string{"'public' THEN 4", "'restricted' THEN 3", "'private' THEN 2", "'isolated' THEN 1"} {
		if !strings.Contains(ExposureRankSQL, level) {
			t.Errorf("exposure rank misses %s", level)
		}
	}
}

// A key outside the allow-list never reaches the ORDER BY.
func TestAllowedSortFields_RejectsUnknownKeys(t *testing.T) {
	got := pagination.NewSortOption(AllowedSortFields()).Parse("criticality;drop table assets,-name").SQL()
	if strings.Contains(got, "drop") || !strings.HasPrefix(got, "name DESC") {
		t.Fatalf("ORDER BY = %q", got)
	}
}
