package scope

import (
	"context"
	"errors"
	"testing"

	scopedom "github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// fakeExclusionRepo overrides only ListActive; the embedded interface panics if
// any other method is unexpectedly called.
type fakeExclusionRepo struct {
	scopedom.ExclusionRepository
	active []*scopedom.Exclusion
	err    error
}

func (f *fakeExclusionRepo) ListActive(_ context.Context, _ shared.ID) ([]*scopedom.Exclusion, error) {
	return f.active, f.err
}

func newExclusion(t *testing.T, tenantID shared.ID, pattern string) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, pattern, "test exclusion", nil, "tester")
	if err != nil {
		t.Fatalf("NewExclusion: %v", err)
	}
	return e
}

func newFilterService(repo scopedom.ExclusionRepository) *Service {
	return NewService(nil, repo, nil, nil, logger.NewNop())
}

// TestFilterExcludedTargets_RemovesMatches proves an asset matching an active
// exclusion is reported as excluded, while a non-matching asset is retained.
func TestFilterExcludedTargets_RemovesMatches(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{
		active: []*scopedom.Exclusion{newExclusion(t, tenantID, "excluded.example.com")},
	})

	keepID := shared.NewID()
	dropID := shared.NewID()
	candidates := []ExclusionCandidate{
		{ID: keepID, Values: []string{"kept.example.com"}},
		{ID: dropID, Values: []string{"excluded.example.com"}},
	}

	excluded := svc.FilterExcludedTargets(context.Background(), tenantID.String(), candidates)

	if !excluded[dropID] {
		t.Fatal("asset matching an exclusion must be excluded")
	}
	if excluded[keepID] {
		t.Fatal("asset not matching any exclusion must be retained")
	}
	if len(excluded) != 1 {
		t.Fatalf("exactly one asset should be excluded, got %d", len(excluded))
	}
}

// TestFilterExcludedTargets_NoExclusionsRetainsAll proves that with no active
// exclusions every candidate is retained.
func TestFilterExcludedTargets_NoExclusionsRetainsAll(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: nil})

	candidates := []ExclusionCandidate{
		{ID: shared.NewID(), Values: []string{"a.example.com"}},
		{ID: shared.NewID(), Values: []string{"b.example.com"}},
	}
	excluded := svc.FilterExcludedTargets(context.Background(), tenantID.String(), candidates)
	if len(excluded) != 0 {
		t.Fatalf("no exclusions should exclude nothing, got %d", len(excluded))
	}
}

// TestFilterExcludedTargets_ErrorFailsOpen proves an exclusion-lookup error
// excludes nothing (fail-open) so a scope failure never blocks a scan.
func TestFilterExcludedTargets_ErrorFailsOpen(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{err: errors.New("db down")})

	candidates := []ExclusionCandidate{
		{ID: shared.NewID(), Values: []string{"excluded.example.com"}},
	}
	excluded := svc.FilterExcludedTargets(context.Background(), tenantID.String(), candidates)
	if len(excluded) != 0 {
		t.Fatalf("a scope lookup error must fail open (exclude nothing), got %d", len(excluded))
	}
}
