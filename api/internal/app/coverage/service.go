// Package coverage drives the asset coverage ledger
// (docs/rfcs/RFC-093-asset-coverage.md): it keeps the ledger in line with the
// registry's coverage policy, plans due pairs into work through the scope
// gate, settles them from their runs, and detects coverage gaps.
package coverage

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Service runs the coverage loop.
type Service struct {
	repo         covdom.Repository
	rules        []covdom.Rule
	planner      covdom.Planner
	starter      RunStarter
	readiness    ReadinessChecker
	tenantSwitch TenantSwitch
	cfg          Config
	alerts       *alerting
	operator     *operatorAlerts
	now          func() time.Time
	logger       *logger.Logger
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
	if s.alerts != nil {
		s.alerts.gaps = map[string]int{}
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
	if s.alerts != nil {
		// Fleet-wide aggregates for the operator: no tenant label (D4).
		metrics.AssetCoverageGapPairs.Reset()
		for c, n := range s.alerts.gaps {
			metrics.AssetCoverageGapPairs.WithLabelValues(c).Set(float64(n))
		}
	}
	s.operatorPass(ctx)
	return total, nil
}

// RunTenant runs one pass for one tenant: reconcile the ledger with the
// policy, settle finished runs, then (when planning is wired and the tenant
// has automatic coverage on) start the due pairs.
func (s *Service) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	added, changed, err := s.repo.Reconcile(ctx, tenantID, s.rules)
	n := added + changed
	if err != nil || s.planner == nil {
		return n, err
	}
	settled, parked, err := s.settle(ctx, tenantID)
	n += settled
	if err != nil {
		return n, fmt.Errorf("settle: %w", err)
	}
	if parked > 0 {
		// Names found without an address are parked: reconcile again so
		// their active pairs turn not applicable before this pass plans.
		added, changed, err := s.repo.Reconcile(ctx, tenantID, s.rules)
		n += added + changed
		if err != nil {
			return n, err
		}
	}
	if s.tenantSwitch != nil {
		on, err := s.tenantSwitch.CoverageEnabled(ctx, tenantID)
		if err != nil {
			// Fail closed: without the tenant's switch nothing is started.
			return n, fmt.Errorf("read coverage setting: %w", err)
		}
		if !on {
			return n, nil
		}
	}
	planned, err := s.plan(ctx, tenantID)
	n += planned
	if err != nil {
		return n, err
	}
	if _, err := s.detect(ctx, tenantID); err != nil {
		return n, fmt.Errorf("detect coverage gaps: %w", err)
	}
	return n, nil
}
