package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app/scancoverage"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// CoverageScheduler is the live controller for RFC-007 license-aware rolling
// scan coverage. Each tick it walks every tenant's coverage-enabled Tenable
// integration, sizes a batch against the engine's license headroom, dispatches
// it to a runner, and advances the rotation cursor.
//
// The pure rotation logic lives in internal/app/scancoverage (planner +
// scheduler); this controller is the composition root that binds it to real
// repositories. It implements scancoverage.CoverageSource itself (the
// integration-listing half) and delegates the candidate/cursor half to the
// coverage repository.
//
// SCOPE: today the controller only drives UNLIMITED engines (Nessus Pro).
// Capped engines (Tenable.sc) are skipped with a log line until active-IP
// accounting + reclaim-ACK ship (Phase 3.5) — dispatching them without that
// accounting could exceed the license, which we refuse to risk.
type CoverageScheduler struct {
	integrations integrationLister
	coverage     coverageRepo
	dispatcher   scancoverage.BatchDispatcher
	config       *CoverageSchedulerConfig
	logger       *logger.Logger
}

// integrationLister is the slice of the integration repository the controller
// needs (kept narrow for testability).
type integrationLister interface {
	List(ctx context.Context, filter integration.Filter) (integration.ListResult, error)
}

// coverageRepo is the candidate + cursor half of scancoverage.CoverageSource /
// CursorStore, satisfied by *postgres.ScanCoverageRepository.
type coverageRepo interface {
	ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]scancoverage.Candidate, error)
	ActiveIPs(ctx context.Context, tenantID shared.ID) (int, error)
	MarkDispatched(ctx context.Context, rec scancoverage.DispatchRecord) error
}

// CoverageSchedulerConfig configures the CoverageScheduler.
type CoverageSchedulerConfig struct {
	// Interval is how often a rotation pass runs. Default: 5 minutes.
	Interval time.Duration
	// CandidateLimit caps candidates loaded per tenant per cycle. Default: 5000.
	CandidateLimit int
	// IntegrationPageSize is the page size when listing integrations. Default: 100.
	IntegrationPageSize int
	Logger              *logger.Logger
}

// NewCoverageScheduler builds a CoverageScheduler.
func NewCoverageScheduler(
	integrations integrationLister,
	coverage coverageRepo,
	dispatcher scancoverage.BatchDispatcher,
	config *CoverageSchedulerConfig,
) *CoverageScheduler {
	if config == nil {
		config = &CoverageSchedulerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 5 * time.Minute
	}
	if config.CandidateLimit == 0 {
		config.CandidateLimit = 5000
	}
	if config.IntegrationPageSize == 0 {
		config.IntegrationPageSize = 100
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &CoverageScheduler{
		integrations: integrations,
		coverage:     coverage,
		dispatcher:   dispatcher,
		config:       config,
		logger:       config.Logger,
	}
}

func (c *CoverageScheduler) Name() string            { return "coverage-scheduler" }
func (c *CoverageScheduler) Interval() time.Duration { return c.config.Interval }

// Reconcile runs one rotation pass over all tenants' coverage configs.
func (c *CoverageScheduler) Reconcile(ctx context.Context) (int, error) {
	if c.dispatcher == nil || c.coverage == nil || c.integrations == nil {
		return 0, nil
	}
	s := scancoverage.NewScheduler(c, c.dispatcher, c, &scancoverage.SchedulerConfig{
		CandidateLimit: c.config.CandidateLimit,
		Logger:         c.logger,
	})
	return s.RunOnce(ctx)
}

// =============================================================================
// scancoverage.CoverageSource implementation
// =============================================================================

// ListActiveCoverage returns every tenant's coverage-enabled, unlimited-engine
// Tenable integration as a CoverageConfig. Capped engines are skipped (see the
// type doc). It pages through integrations cross-tenant.
func (c *CoverageScheduler) ListActiveCoverage(ctx context.Context) ([]scancoverage.CoverageConfig, error) {
	provider := integration.ProviderTenable
	status := integration.StatusConnected

	var configs []scancoverage.CoverageConfig
	page := 1
	for {
		res, err := c.integrations.List(ctx, integration.Filter{
			Provider: &provider,
			Status:   &status,
			Page:     page,
			PerPage:  c.config.IntegrationPageSize,
		})
		if err != nil {
			return nil, err
		}
		for _, intg := range res.Data {
			cfg, ok := c.toCoverageConfig(intg)
			if ok {
				configs = append(configs, cfg)
			}
		}
		if len(res.Data) < c.config.IntegrationPageSize || int64(page*c.config.IntegrationPageSize) >= res.Total {
			break
		}
		page++
	}
	return configs, nil
}

// toCoverageConfig maps one integration to a CoverageConfig, returning ok=false
// when it should not be auto-rotated (config invalid, coverage disabled, or a
// capped engine that is not yet supported).
func (c *CoverageScheduler) toCoverageConfig(intg *integration.Integration) (scancoverage.CoverageConfig, bool) {
	tc, err := scancoverage.ParseTenableConfig(intg.Config())
	if err != nil {
		c.logger.Warn("skipping tenable integration: invalid config",
			"integration_id", intg.ID().String(),
			"tenant_id", intg.TenantID().String(),
			"error", err)
		return scancoverage.CoverageConfig{}, false
	}
	if !tc.CoverageEnabled {
		return scancoverage.CoverageConfig{}, false
	}
	if tc.Engine != scancoverage.EngineNessusPro {
		c.logger.Info("skipping coverage: capped engine not yet supported",
			"integration_id", intg.ID().String(),
			"tenant_id", intg.TenantID().String(),
			"engine", string(tc.Engine))
		return scancoverage.CoverageConfig{}, false
	}

	cfg := scancoverage.CoverageConfig{
		TenantID:     intg.TenantID(),
		Engine:       string(tc.Engine),
		Policy:       tc.LicensePolicy(),
		DefaultBatch: tc.EffectiveBatchSize(),
		TemplateUUID: tc.TemplateUUID,
	}
	if tc.AgentID != "" {
		if id, err := shared.IDFromString(tc.AgentID); err == nil {
			cfg.AgentID = &id
		} else {
			c.logger.Warn("ignoring invalid pinned agent_id on tenable integration",
				"integration_id", intg.ID().String(),
				"agent_id", tc.AgentID)
		}
	}
	return cfg, true
}

// ListCandidates delegates to the coverage repository.
func (c *CoverageScheduler) ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]scancoverage.Candidate, error) {
	return c.coverage.ListCandidates(ctx, tenantID, limit)
}

// ActiveIPs delegates to the coverage repository.
func (c *CoverageScheduler) ActiveIPs(ctx context.Context, tenantID shared.ID) (int, error) {
	return c.coverage.ActiveIPs(ctx, tenantID)
}

// =============================================================================
// scancoverage.CursorStore implementation (delegated)
// =============================================================================

// MarkDispatched delegates to the coverage repository.
func (c *CoverageScheduler) MarkDispatched(ctx context.Context, rec scancoverage.DispatchRecord) error {
	return c.coverage.MarkDispatched(ctx, rec)
}

// Compile-time checks: the controller satisfies the scheduler's ports.
var (
	_ Controller                  = (*CoverageScheduler)(nil)
	_ scancoverage.CoverageSource = (*CoverageScheduler)(nil)
	_ scancoverage.CursorStore    = (*CoverageScheduler)(nil)
)
