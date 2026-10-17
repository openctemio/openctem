package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

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
