package unit

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The scan trigger puts its targets through the one target gate, which fails
// closed without its checks. Tests that do not exercise them wire these:
// no exclusion, no ownership refusal, an actor who may scan everything.

type noExclusions struct{}

func (noExclusions) ExcludedTargets(context.Context, string, []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	return map[shared.ID]bool{}, nil
}

type allOwned struct{}

func (allOwned) ActiveCheckBlocked(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return map[string]attribution.State{}, nil
}

func (allOwned) BlockedTargets(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return map[string]attribution.State{}, nil
}

func (allOwned) TierExceeded(context.Context, shared.ID, []string, scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	return map[string]*scopedom.RuleRef{}, nil
}

type actOnAll struct{}

func (actOnAll) Check(context.Context, actscope.Input) (*actscope.Decision, error) {
	return &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}, nil
}

// allowAllTargetChecks goes first in a test's options, so an option the test
// passes for one of these checks replaces it.
func allowAllTargetChecks(opts ...scanservice.ServiceOption) []scanservice.ServiceOption {
	return append([]scanservice.ServiceOption{
		scanservice.WithScopeExclusionFilter(noExclusions{}),
		scanservice.WithAttributionGate(allOwned{}),
		scanservice.WithActScope(actOnAll{}),
	}, opts...)
}

func (allOwned) UncoveredTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}
