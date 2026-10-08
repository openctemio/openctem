package scan

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Test hooks for the external scan_test package, whose DB tests import
// infra/postgres (which imports this package, so they cannot be internal).

// NewGroupResolverForTest builds a Service that only resolves scan targets:
// the given exclusions (nil: none), no ownership refusal, an actor who may
// scan everything.
func NewGroupResolverForTest(groups assetgroup.Repository, exclusions ScopeExclusionFilter) *Service {
	return allowAllChecks(&Service{assetGroupRepo: groups, scopeExclusions: exclusions, logger: logger.NewNop()})
}

// ResolvedForTest is what resolveScanTargets and recordResolvedTargets give.
type ResolvedForTest struct {
	Targets       []string
	ExcludedNames []string
	Archived      int
	RunContext    map[string]any
}

// ResolveScanTargetsForTest runs resolveScanTargets and records the result
// in a run context the way a trigger does.
func (s *Service) ResolveScanTargetsForTest(ctx context.Context, sc *scan.Scan) (*ResolvedForTest, error) {
	r, err := s.resolveScanTargets(ctx, sc)
	if err != nil {
		return nil, err
	}
	out := &ResolvedForTest{Targets: r.Targets, ExcludedNames: r.ExcludedNames, Archived: r.Archived, RunContext: map[string]any{}}
	if len(r.Targets) > 0 || r.Incompatible > 0 {
		if err := recordResolvedTargets(sc, r, out.RunContext); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// WithToolRepoForTest sets the tool repository the scanner type gate reads.
func (s *Service) WithToolRepoForTest(repo tool.Repository) *Service {
	s.toolRepo = repo
	return s
}
