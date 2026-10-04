package retest

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeExclusions is the fail-closed scope-exclusion lookup the scan path uses
// (*scope.Service.ExcludedTargets).
type ScopeExclusions interface {
	ExcludedTargets(ctx context.Context, tenantID string, candidates []scope.ExclusionCandidate) (map[shared.ID]bool, error)
}

// ScopeExclusionGate refuses a retest of an asset that matches an active scope
// exclusion. A lookup error refuses too: retesting something the tenant
// excluded is worse than not retesting it.
type ScopeExclusionGate struct {
	Scope ScopeExclusions
}

// AllowActiveCheck implements TargetGate.
func (g ScopeExclusionGate) AllowActiveCheck(ctx context.Context, tenantID shared.ID, a *asset.Asset) (bool, string, error) {
	if g.Scope == nil {
		return true, "", nil
	}
	excluded, err := g.Scope.ExcludedTargets(ctx, tenantID.String(), []scope.ExclusionCandidate{{ID: a.ID(), Values: []string{a.Name()}}})
	if err != nil {
		return false, "", fmt.Errorf("scope exclusion check: %w", err)
	}
	if excluded[a.ID()] {
		return false, "the asset matches a scope exclusion", nil
	}
	return true, "", nil
}
