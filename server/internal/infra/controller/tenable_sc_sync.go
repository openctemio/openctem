package controller

// The Tenable.sc connector schedule (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md
// §10): settles finished connector_sync commands and queues the next sync of
// every connector integration that is due.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TenableSCIntegrationLister lists integrations across tenants (the scheduler
// acts on each under its own tenant). Satisfied by the integration repository.
type TenableSCIntegrationLister interface {
	List(ctx context.Context, filter integration.Filter) (integration.ListResult, error)
}

// TenableSCSyncer is the connector service's scheduled step for one
// integration (tenablesc.Service.ScheduledSync).
type TenableSCSyncer interface {
	ScheduledSync(ctx context.Context, intg *integration.Integration) (bool, error)
}

// TenableSCSyncController runs the connector schedule.
type TenableSCSyncController struct {
	integrations TenableSCIntegrationLister
	syncer       TenableSCSyncer
	interval     time.Duration
	pageSize     int
	logger       *logger.Logger
}

// NewTenableSCSyncController creates the controller (every 2 minutes, so a
// finished sync is reflected quickly; queuing is gated by each integration's
// own interval).
func NewTenableSCSyncController(integrations TenableSCIntegrationLister, syncer TenableSCSyncer, log *logger.Logger) *TenableSCSyncController {
	return &TenableSCSyncController{
		integrations: integrations,
		syncer:       syncer,
		interval:     2 * time.Minute,
		pageSize:     100,
		logger:       log.With("controller", "tenable-sc-sync"),
	}
}

// Name implements Controller.
func (c *TenableSCSyncController) Name() string { return "tenable-sc-sync" }

// Interval implements Controller.
func (c *TenableSCSyncController) Interval() time.Duration { return c.interval }

// Reconcile walks the Tenable integrations; the syncer ignores those that are
// not Tenable.sc sensor connectors. A failure on one integration is logged
// and does not stop the others. Returns the number of syncs queued.
func (c *TenableSCSyncController) Reconcile(ctx context.Context) (int, error) {
	provider := integration.ProviderTenable
	queued := 0
	var firstErr error
	for page := 1; ; page++ {
		res, err := c.integrations.List(ctx, integration.Filter{
			Provider:  &provider,
			Page:      page,
			PerPage:   c.pageSize,
			SortBy:    "created_at",
			SortOrder: "asc",
		})
		if err != nil {
			return queued, err
		}
		for _, intg := range res.Data {
			if ctx.Err() != nil {
				return queued, ctx.Err()
			}
			ok, err := c.syncer.ScheduledSync(ctx, intg)
			if err != nil {
				c.logger.Warn("tenable.sc scheduled sync step failed",
					"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String(), "error", err)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if ok {
				queued++
			}
		}
		if len(res.Data) < c.pageSize || int64(page*c.pageSize) >= res.Total {
			break
		}
	}
	return queued, firstErr
}
