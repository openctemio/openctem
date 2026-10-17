package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/instancezone"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// wireInstanceScanZones builds the instance scan zone service
// (docs/rfcs/RFC-100-shared-sensors.md §6.1) and wires it into the scan
// trigger (zone lookup) and the job signer client (the zone in a shared
// job's signed statement). It returns the console handler.
func wireInstanceScanZones(svc *Services, repos *Repositories, db *postgres.DB, stepUp handler.StepUpVerifier, log *logger.Logger) *handler.AdminInstanceScanZoneHandler {
	if db == nil || repos == nil {
		return nil
	}
	var ledger instancezone.ZoneLedger
	if svc.JobSigner != nil {
		ledger = svc.JobSigner
	}
	var policy instancezone.InternalZonesPolicy
	if svc.ScanPolicy != nil {
		policy = svc.ScanPolicy
	}
	zones := instancezone.NewService(postgres.NewInstanceScanZoneRepository(db), ledger, policy, repos.AdminAuditLog, log)
	if svc.Scan != nil {
		svc.Scan.SetInstanceZones(zones)
	}
	if svc.Command != nil && repos.Command != nil {
		svc.Command.SetInstanceZoneSource(commandZoneSource{commands: repos.Command, zones: zones})
	}
	return handler.NewAdminInstanceScanZoneHandler(zones, stepUp, log)
}

// commandZoneSource reads the instance scan zone of a shared job for its
// signed statement.
type commandZoneSource struct {
	commands *postgres.CommandRepository
	zones    *instancezone.Service
}

func (c commandZoneSource) StatementZoneFor(ctx context.Context, tenantID, commandID shared.ID) (*jobsign.StatementZone, error) {
	zid, err := c.commands.InstanceScanZoneID(ctx, tenantID, commandID)
	if err != nil || zid == nil {
		return nil, err
	}
	return c.zones.StatementZone(ctx, *zid)
}
