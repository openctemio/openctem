// Package coverage drives the asset coverage ledger
// (docs/rfcs/RFC-093-asset-coverage.md): it keeps the ledger in line with the
// registry's coverage policy, plans due pairs into work through the scope
// gate, settles them from their runs, and detects coverage gaps.
package coverage

import (
	"context"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Service runs the coverage loop.
type Service struct {
	repo   covdom.Repository
	rules  []covdom.Rule
	now    func() time.Time
	logger *logger.Logger
}

// NewService creates the service with the registry's policy.
func NewService(repo covdom.Repository, log *logger.Logger) *Service {
	return &Service{repo: repo, rules: covdom.Rules(), now: time.Now, logger: log.With("component", "asset-coverage")}
}

// Run reconciles every tenant that has assets. One tenant's failure does
// not stop the others. It returns how many ledger rows it added or changed.
func (s *Service) Run(ctx context.Context) (int, error) {
	tenants, err := s.repo.TenantsWithAssets(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, err := s.RunTenant(ctx, t)
		total += n
		if err != nil {
			s.logger.Warn("coverage of a tenant failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return total, nil
}

// RunTenant reconciles one tenant.
func (s *Service) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	added, changed, err := s.repo.Reconcile(ctx, tenantID, s.rules)
	return added + changed, err
}
