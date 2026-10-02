package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// FindingFilter.CVEIDs and FindingTypes must reach the list/count WHERE clause.
// They used to be dropped here, so a remediation campaign scoped to cve_ids
// counted (and on "resolve" closed) findings of every CVE in the tenant.
func TestBuildWhereClause_CVEAndFindingTypeFilters(t *testing.T) {
	r := &FindingRepository{}

	f := vulnerability.NewFindingFilter().
		WithCVEIDs([]string{"CVE-2021-44228"}).
		WithFindingTypes(vulnerability.FindingTypeSecret)

	where, args := r.buildWhereClause(f)

	for _, frag := range []string{"cve_id = ANY($", "finding_type = ANY($"} {
		if !strings.Contains(where, frag) {
			t.Errorf("WHERE missing %q\nfull: %s", frag, where)
		}
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d: %#v", len(args), args)
	}
}

func TestBuildWhereClause_NoCVEOrTypeClauseWhenUnset(t *testing.T) {
	r := &FindingRepository{}
	where, _ := r.buildWhereClause(vulnerability.NewFindingFilter())
	for _, frag := range []string{"cve_id", "finding_type"} {
		if strings.Contains(where, frag) {
			t.Errorf("unset filter leaked clause %q: %s", frag, where)
		}
	}
}
