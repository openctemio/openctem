package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// RFC-017 P1: the findings list must be filterable by the CTEM prioritization
// signals the classifier already computes. buildWhereClause is pure (no DB), so
// we assert the generated SQL fragments + args directly.
func TestBuildWhereClause_CTEMPriorityFilters(t *testing.T) {
	r := &FindingRepository{}

	f := vulnerability.NewFindingFilter().
		WithPriorityClasses("P0", "P1").
		WithIsInKEV(true).
		WithEPSSMin(0.5).
		WithIsReachable(true)

	where, args := r.buildWhereClause(f)

	for _, frag := range []string{
		"priority_class IN (",
		"is_in_kev = $",
		"is_reachable = $",
		"epss_score >= $",
	} {
		if !strings.Contains(where, frag) {
			t.Errorf("WHERE missing %q\nfull: %s", frag, where)
		}
	}

	// 2 priority classes + kev + reachable + epss = 5 bound args.
	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d: %#v", len(args), args)
	}
	if args[0] != "P0" || args[1] != "P1" {
		t.Errorf("priority class args = %v, want [P0 P1 ...]", args[:2])
	}
}

// A filter with none of the CTEM fields set must not emit any of their clauses
// (no accidental always-on predicate).
func TestBuildWhereClause_NoCTEMFiltersWhenUnset(t *testing.T) {
	r := &FindingRepository{}
	where, _ := r.buildWhereClause(vulnerability.NewFindingFilter())
	for _, frag := range []string{"priority_class", "is_in_kev", "is_reachable", "epss_score"} {
		if strings.Contains(where, frag) {
			t.Errorf("unset filter leaked clause %q: %s", frag, where)
		}
	}
}
