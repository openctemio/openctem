package ingest

// "The tenant scanned it" attribution evidence (RFC-036 §6.4 rule
// tenant_scanned, owner decision O8): assets reported for a command the
// tenant's own sensor ran are stamped with which sensor, which command (and
// so which scan run), which tool, which report and when.
//
// Only a command-bound report counts (RFC-040 §5.3): a scan the tenant
// dispatched to its sensor. Unsolicited reports (collectors, CI) and
// server-side ingests (CT promotion, uploads, imports) are not "the tenant
// scanned it", so they never fire the rule. Within a bound report only the
// assets the report may change are stamped: those it created and the
// existing ones its command's targets cover. A sensor cannot raise the
// attribution of an asset outside what it was asked to scan.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanProvenance is where a tenant scan's sighting came from.
type ScanProvenance struct {
	SensorID   shared.ID
	CommandID  *shared.ID
	StepRunID  *shared.ID
	Tool       string
	ReportID   string
	ObservedAt time.Time
}

// ScanAttributionStamper records tenant_scanned evidence on assets and
// re-evaluates their attribution. Tenant-scoped; asset ids of another tenant
// write nothing.
type ScanAttributionStamper interface {
	StampScanned(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, prov ScanProvenance) error
}

// SetScanAttributionStamper wires tenant_scanned evidence. Nil-safe: unwired,
// scan results carry no attribution evidence (prior behavior).
func (s *Service) SetScanAttributionStamper(st ScanAttributionStamper) {
	s.scanAttribution = st
}

// stampScanAttribution is best-effort: a failure is logged and never fails
// the ingest, because the assets and findings are already stored.
func (s *Service) stampScanAttribution(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding, scope *alterScope, toolName, reportID string, assetMap map[string]shared.ID) {
	ids := scanStampTargets(binding, scope, assetMap)
	if s.scanAttribution == nil || len(ids) == 0 {
		return
	}
	prov := ScanProvenance{
		SensorID:   agt.ID,
		CommandID:  binding.CommandID,
		StepRunID:  binding.StepRunID,
		Tool:       toolName,
		ReportID:   reportID,
		ObservedAt: time.Now().UTC(),
	}
	if err := s.scanAttribution.StampScanned(ctx, tenantID, ids, prov); err != nil {
		s.logger.Warn("ingest: tenant-scan attribution evidence not recorded",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "assets", len(ids),
			"error", logger.SanitizeError(err))
	}
}

// scanStampTargets returns the persisted asset ids a report may stamp: none
// unless the report is bound to a command, then only the assets the report
// created or whose command target covers them.
func scanStampTargets(binding Binding, scope *alterScope, assetMap map[string]shared.ID) []shared.ID {
	if binding.Kind != BindingCommand || scope == nil {
		return nil
	}
	seen := map[shared.ID]bool{}
	out := make([]shared.ID, 0, len(assetMap))
	for _, id := range assetMap {
		if id.IsZero() || seen[id] || !scope.allowed[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
