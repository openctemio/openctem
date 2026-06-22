package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// An empty scan id must short-circuit the auto-resolve methods BEFORE any SQL
// runs — otherwise the "not seen in this scan" staleness predicate matches
// every existing finding/occurrence and silently resolves a tenant's whole
// set. The repository is constructed with a zero DB on purpose: if the guard
// is removed these calls would dereference the nil *sql.DB and panic, so the
// test also proves no query is attempted.
func TestAutoResolveStale_EmptyScanID_NoOp(t *testing.T) {
	r := NewFindingRepository(&DB{})
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	ids, err := r.AutoResolveStale(ctx, tenantID, assetID, "trivy", "", nil)
	if err != nil {
		t.Fatalf("expected no error for empty scan id, got %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings resolved for empty scan id, got %d", len(ids))
	}
}

func TestAutoResolveStaleBranchOccurrences_EmptyScanID_NoOp(t *testing.T) {
	r := NewFindingRepository(&DB{})
	ctx := context.Background()
	tenantID := shared.NewID()
	branchID := shared.NewID()

	n, err := r.AutoResolveStaleBranchOccurrences(ctx, tenantID, branchID, "trivy", "")
	if err != nil {
		t.Fatalf("expected no error for empty scan id, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 occurrences resolved for empty scan id, got %d", n)
	}
}
