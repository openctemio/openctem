package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ListByActor is inherently tenant-scoped; a zero tenant must fail closed BEFORE
// the query runs (db is nil here) rather than fall through to an unscoped read
// of the actor's activity across every tenant. This locks in the S1 fix so a
// future caller cannot reintroduce the cross-tenant read.
func TestAuditRepository_ListByActor_RequiresTenant(t *testing.T) {
	r := &AuditRepository{} // db nil on purpose: the guard must return first

	_, err := r.ListByActor(context.Background(), shared.ID{}, shared.NewID(), pagination.New(1, 20))
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected fail-closed validation error for zero tenant, got %v", err)
	}
}
