package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// IntegrationSyncStore is the narrow store the scheduler needs: find due
// integrations and persist their sync tracking. Satisfied by
// *postgres.IntegrationRepository.
type IntegrationSyncStore interface {
	ListDueForSync(ctx context.Context, provider integration.Provider, now time.Time, limit int) ([]*integration.Integration, error)
	Update(ctx context.Context, i *integration.Integration) error
}

// TenantSyncer runs a DefectDojo pull for one tenant. Returns error only (not
// the result) so the controller need not import app/defectdojo — cmd/server
// adapts *defectdojo.SyncService into this. Avoids a controller→app cycle.
type TenantSyncer interface {
	SyncTenant(ctx context.Context, tenantID shared.ID) error
}

// DefectDojoSyncController periodically pulls connected DefectDojo integrations
// that are due (RFC-013 Phase 2c), making the co-existence sync hands-off. Each
// integration syncs under its own tenant; success/failure advances next_sync_at
// so a failing one retries next interval instead of hammering.
type DefectDojoSyncController struct {
	store    IntegrationSyncStore
	syncer   TenantSyncer
	interval time.Duration
	batch    int
	logger   *logger.Logger
}

// NewDefectDojoSyncController wires the controller. Default cadence 5m, batch 20.
func NewDefectDojoSyncController(store IntegrationSyncStore, syncer TenantSyncer, log *logger.Logger) *DefectDojoSyncController {
	return &DefectDojoSyncController{
		store:    store,
		syncer:   syncer,
		interval: 5 * time.Minute,
		batch:    20,
		logger:   log.With("controller", "defectdojo-sync-scheduler"),
	}
}

// Name implements Controller.
func (c *DefectDojoSyncController) Name() string { return "defectdojo-sync-scheduler" }

// Interval implements Controller.
func (c *DefectDojoSyncController) Interval() time.Duration { return c.interval }

// Reconcile pulls each due DefectDojo integration under its own tenant and
// advances its sync tracking. Returns the number synced.
func (c *DefectDojoSyncController) Reconcile(ctx context.Context) (int, error) {
	due, err := c.store.ListDueForSync(ctx, integration.ProviderDefectDojo, time.Now(), c.batch)
	if err != nil {
		return 0, err
	}
	if len(due) == 0 {
		return 0, nil
	}

	synced := 0
	var firstErr error
	for _, intg := range due {
		if ctx.Err() != nil {
			return synced, ctx.Err()
		}
		if serr := c.syncer.SyncTenant(ctx, intg.TenantID()); serr != nil {
			intg.RecordSyncFailure(serr.Error())
			c.logger.Warn("scheduled defectdojo sync failed",
				"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String(), "error", serr)
			if firstErr == nil {
				firstErr = serr
			}
		} else {
			intg.RecordSyncSuccess()
			synced++
		}
		// Persist next_sync_at/last_sync_at/sync_error regardless of outcome so a
		// failing integration reschedules instead of being retried every tick.
		if uerr := c.store.Update(ctx, intg); uerr != nil {
			c.logger.Warn("failed to persist integration sync tracking",
				"integration_id", intg.ID().String(), "error", uerr)
		}
	}
	return synced, firstErr
}
