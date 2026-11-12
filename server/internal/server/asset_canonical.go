package server

import (
	"context"

	"github.com/openctemio/openctem/server/internal/app/assetcanon"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/tools/assetcanoncmd"
	"github.com/openctemio/openctem/server/internal/tools/toolaudit"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// runAssetCanonicalOnStart moves stored asset names to their CTIS 2.0
// canonical form (internal/app/assetcanon, docs/operations/ctis-2-upgrade.md):
// a rename, or a merge into the asset that already holds the name. Every
// tenant that changed gets one audit entry. Counts only in the log.
func runAssetCanonicalOnStart(ctx context.Context, db *postgres.DB, log *logger.Logger) {
	svc := assetcanon.NewService(postgres.NewAssetCanonicalRepository(db))
	auditWriter := postgres.NewAuditRepository(db)
	runID := toolaudit.NewRunID()
	err := svc.RunAll(ctx, true, func(rep assetcanon.Report) {
		if rep.Changed() || rep.Conflicts > 0 {
			log.Info("asset names moved to the CTIS 2.0 canonical form",
				"tenant_id", rep.TenantID, "renamed", rep.Renamed, "merged", rep.Merged,
				"conflicts", rep.Conflicts, "raced", rep.Raced)
		}
		if err := assetcanoncmd.AuditRun(ctx, auditWriter, runID, "server", rep); err != nil {
			log.Error("asset canonical audit entry failed", "tenant_id", rep.TenantID, "error", err)
		}
	})
	if err != nil {
		log.Error("asset canonical migration on start failed", "error", err)
	}
}
