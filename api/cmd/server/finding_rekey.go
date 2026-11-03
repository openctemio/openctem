package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/refingerprintcmd"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// runFindingRekeyOnStart re-keys stored findings to the current identity
// version (docs/architecture/deduplication.md, "Recipe versions and the
// re-key"). Every tenant that changed gets one audit entry, as with the
// refingerprint command.
func runFindingRekeyOnStart(ctx context.Context, db *postgres.DB, log *logger.Logger) {
	store := postgres.NewFindingRekeyRepository(db)
	svc := refingerprint.NewService(store)
	auditWriter := postgres.NewAuditRepository(db)
	runID := toolaudit.NewRunID()
	ran, err := store.WithRekeyLock(ctx, func(ctx context.Context) error {
		return svc.RunAll(ctx, store, func(rep *refingerprint.Report) {
			if rep.Rekeyed > 0 || rep.Merged > 0 {
				log.Info("findings re-keyed to the current identity version",
					"tenant_id", rep.TenantID, "rekeyed", rep.Rekeyed, "merged", rep.Merged,
					"kept", rep.SkippedTotal(), "completed", rep.Completed)
			}
			if err := refingerprintcmd.AuditRun(ctx, auditWriter, runID, rep); err != nil {
				log.Error("finding re-key audit entry failed", "tenant_id", rep.TenantID, "error", err)
			}
		})
	})
	if err != nil {
		log.Error("finding re-key on start failed", "error", err)
		return
	}
	if !ran {
		log.Debug("finding re-key on start: another replica holds the lock")
	}
}
