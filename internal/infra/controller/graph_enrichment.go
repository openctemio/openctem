package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// GraphEnrichmentControllerConfig configures the periodic asset-graph
// enrichment pass.
type GraphEnrichmentControllerConfig struct {
	// Interval is how often to run. Default: 1h. Enrichment is derived from
	// slow-moving inventory data, so a sub-hourly cadence would only add DB
	// churn without changing outcomes. The pass is idempotent (edges use
	// ON CONFLICT DO NOTHING), so re-running is cheap and safe.
	Interval time.Duration

	// Logger for structured output. Defaults to NewNop when nil.
	Logger *logger.Logger
}

// graphEnricher is the app-layer surface the controller drives per tenant.
// Implemented by *asset.RelationshipSuggestionService.
type graphEnricher interface {
	EnrichGraph(ctx context.Context, tenantID string) (asset.EnrichGraphResult, error)
}

// GraphEnrichmentController periodically infers high-confidence asset-graph
// edges (Exposes host→service, RunsOn application→host) from data scanners
// already ingest, so the attack-path / exposure-chain / reachability engines
// have edges beyond DNS to traverse over historical data.
//
// A background controller (rather than the ingest hot path) is used because
// enrichment reasons over the WHOLE tenant graph — it must also enrich assets
// ingested before this feature existed, and it must not slow ingest. The pass
// is idempotent and each tenant is handled serially; a failure on one tenant
// never halts the others.
type GraphEnrichmentController struct {
	enricher   graphEnricher
	tenantRepo tenant.Repository
	config     *GraphEnrichmentControllerConfig
	logger     *logger.Logger
}

// NewGraphEnrichmentController constructs the controller.
func NewGraphEnrichmentController(
	enricher graphEnricher,
	tenantRepo tenant.Repository,
	config *GraphEnrichmentControllerConfig,
) *GraphEnrichmentController {
	if config == nil {
		config = &GraphEnrichmentControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &GraphEnrichmentController{
		enricher:   enricher,
		tenantRepo: tenantRepo,
		config:     config,
		logger:     config.Logger.With("controller", "graph-enrichment"),
	}
}

// Name implements controller.Controller.
func (c *GraphEnrichmentController) Name() string { return "graph-enrichment" }

// Interval implements controller.Controller.
func (c *GraphEnrichmentController) Interval() time.Duration { return c.config.Interval }

// Reconcile enriches the asset graph for every active tenant. Returns the
// total number of edges auto-created across all tenants. Per-tenant errors are
// logged and skipped; only an unrecoverable tenant-list failure is returned so
// the runner retries next tick.
func (c *GraphEnrichmentController) Reconcile(ctx context.Context) (int, error) {
	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	totalEdges := 0
	for _, tenantID := range tenantIDs {
		res, err := c.enrichTenant(ctx, tenantID)
		if err != nil {
			c.logger.Warn("graph enrichment failed; continuing with next tenant",
				"tenant_id", tenantID.String(), "error", err)
			continue
		}
		totalEdges += res.EdgesCreated
	}
	return totalEdges, nil
}

// enrichTenant runs a single tenant's enrichment pass.
func (c *GraphEnrichmentController) enrichTenant(ctx context.Context, tenantID shared.ID) (asset.EnrichGraphResult, error) {
	return c.enricher.EnrichGraph(ctx, tenantID.String())
}
