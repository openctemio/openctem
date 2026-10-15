package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The asset finding counts and risk score count exactly the active finding
// statuses: an accepted, false-positive, duplicate or resolved finding, or an
// unpublished pentest draft, must carry no risk.
func TestRiskBearingFindingStatusClauseMatchesActiveStatuses(t *testing.T) {
	want := make([]string, 0)
	for _, s := range vulnerability.ActiveFindingStatuses() {
		want = append(want, "'"+string(s)+"'")
	}
	got := strings.TrimSuffix(strings.TrimPrefix(riskBearingFindingStatusClause, "f.status IN ("), ")")
	if got != strings.Join(want, ",") {
		t.Fatalf("riskBearingFindingStatusClause = %s, want IN (%s)", riskBearingFindingStatusClause, strings.Join(want, ","))
	}
}
