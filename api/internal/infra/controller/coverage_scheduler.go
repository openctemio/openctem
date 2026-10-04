package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
// Since RFC-047 the engine is the Tenable.sc sensor connector: a batch is a
// connector_scan launched through the connector's sensor, sized against
// Tenable.sc's own licensed and active IPs, and the next batch waits for the
// previous one to finish and be ingested. Nessus Pro integrations have no
// runner and are not driven.
type CoverageScheduler struct {
	integrations integrationLister
	coverage     coverageRepo
	dispatcher   scancoverage.BatchDispatcher
	config       *CoverageSchedulerConfig
	logger       *logger.Logger
	// active is the active-IP count per tenant read in the current pass.
	active map[shared.ID]int
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
	ClaimBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) ([]string, error)
	ReleaseBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) error
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
	// Gate checks every batch before dispatch (private-range policy, scope
	// exclusions, scan zones). Without it nothing is dispatched.
	Gate scancoverage.TargetGate
	// Connector says whether a connector integration may take a batch and
	// sizes it (tenablesc.Service). Without it nothing is dispatched.
	Connector CoverageConnector
	Logger    *logger.Logger
}

// CoverageConnector is the connector side of coverage (tenablesc.Service).
type CoverageConnector interface {
	CoverageStatus(ctx context.Context, intg *integration.Integration) (tenablesc.CoverageStatus, error)
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
		Gate:           c.config.Gate,
		Logger:         c.logger,
	})
	return s.RunOnce(ctx)
}

// =============================================================================
// scancoverage.CoverageSource implementation
// =============================================================================

// ListActiveCoverage returns, for every tenant, its coverage-enabled
// Tenable.sc sensor connector that may take a batch now (RFC-047 §9): the
// license numbers are Tenable.sc's own, and an integration whose previous
// batch is still running or being ingested is skipped. One connector per
// tenant; others are logged and skipped. It pages through integrations
// cross-tenant; each is then acted on under its own tenant.
func (c *CoverageScheduler) ListActiveCoverage(ctx context.Context) ([]scancoverage.CoverageConfig, error) {
	if c.config.Connector == nil {
		return nil, nil
	}
	provider := integration.ProviderTenable
	status := integration.StatusConnected
	c.active = map[shared.ID]int{}

	var configs []scancoverage.CoverageConfig
	for page := 1; ; page++ {
		res, err := c.integrations.List(ctx, integration.Filter{
			Provider: &provider, Status: &status, Page: page, PerPage: c.config.IntegrationPageSize,
			SortBy: "created_at", SortOrder: "asc",
		})
		if err != nil {
			return nil, err
		}
		for _, intg := range res.Data {
			if !tenablesc.IsConnector(intg) {
				continue
			}
			st, err := c.config.Connector.CoverageStatus(ctx, intg)
			if err != nil {
				c.logger.Warn("coverage status of a Tenable.sc connector failed",
					"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String(), "error", err)
				continue
			}
			if !st.Ready {
				c.logger.Debug("coverage not dispatched for connector",
					"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String(), "reason", st.Reason)
				continue
			}
			if _, dup := c.active[intg.TenantID()]; dup {
				c.logger.Warn("more than one coverage-enabled Tenable.sc connector in a tenant; only the first is used",
					"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String())
				continue
			}
			c.active[intg.TenantID()] = st.ActiveIPs
			id := intg.ID()
			configs = append(configs, scancoverage.CoverageConfig{
				TenantID:      intg.TenantID(),
				IntegrationID: &id,
				Engine:        string(scancoverage.EngineTenableSC),
				Policy:        st.Policy,
				DefaultBatch:  st.DefaultBatch,
			})
		}
		if len(res.Data) < c.config.IntegrationPageSize || int64(page*c.config.IntegrationPageSize) >= res.Total {
			break
		}
	}
	return configs, nil
}

// ListCandidates delegates to the coverage repository.
func (c *CoverageScheduler) ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]scancoverage.Candidate, error) {
	return c.coverage.ListCandidates(ctx, tenantID, limit)
}

// ActiveIPs is Tenable.sc's active-IP count for the tenant's connector, as
// read by ListActiveCoverage in the same pass (after the previous batch was
// settled).
func (c *CoverageScheduler) ActiveIPs(_ context.Context, tenantID shared.ID) (int, error) {
	return c.active[tenantID], nil
}

// =============================================================================
// scancoverage.CursorStore implementation (delegated)
// =============================================================================

// ClaimBatch delegates to the coverage repository.
func (c *CoverageScheduler) ClaimBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) ([]string, error) {
	return c.coverage.ClaimBatch(ctx, tenantID, batch, at)
}

// ReleaseBatch delegates to the coverage repository.
func (c *CoverageScheduler) ReleaseBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) error {
	return c.coverage.ReleaseBatch(ctx, tenantID, batch, at)
}

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
