package ingest

// Attribution of what a sensor report wrote (RFC-036 §6.4; owner decision
// O8 as narrowed by research/22 E7; RFC-040: sensor output is untrusted).
//
// A report bound to a command the tenant's own sensor ran:
//   - an asset that is one of the command's targets (what the tenant typed)
//     gets tenant_scanned evidence ("the tenant scanned it");
//   - an asset the scan found while scanning something else (a subfinder
//     child, a resolved address, a root domain named in a result) gets
//     tenant_scan_discovered evidence, which never confirms a name by itself:
//     a new internet-facing name waits for review unless it is under a
//     verified domain.
//
// An unsolicited sensor report (collectors, CI) carries no evidence; a new
// internet-facing asset it creates is a candidate. Server-side ingests (CT
// promotion, uploads, imports) do not come here. A sensor report never
// confirms an asset on its own, and never touches a person's decision.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanProvenance is where a sensor's sighting came from.
type ScanProvenance struct {
	SensorID   shared.ID
	CommandID  *shared.ID
	StepRunID  *shared.ID
	Tool       string
	ReportID   string
	ObservedAt time.Time
	// Unsolicited: the report named no command assigned to the sensor.
	Unsolicited bool
}

// ScannedAsset is one persisted asset a sensor report created or changed.
type ScannedAsset struct {
	ID   shared.ID
	Name string
	Type asset.TypeRef
	// Created: this report created the asset.
	Created bool
	// Typed: the asset is one of the bound command's targets itself, not a
	// name found under one.
	Typed bool
}

// ScanAttributionStamper records attribution evidence and records for what
// a sensor report wrote. Tenant-scoped; asset ids of another tenant write
// nothing.
type ScanAttributionStamper interface {
	StampScanned(ctx context.Context, tenantID shared.ID, assets []ScannedAsset, prov ScanProvenance) error
}

// SetScanAttributionStamper wires sensor-report attribution. Nil-safe:
// unwired, sensor results carry no attribution.
func (s *Service) SetScanAttributionStamper(st ScanAttributionStamper) {
	s.scanAttribution = st
}

// stampScanAttribution is best-effort: a failure is logged and never fails
// the ingest, because the assets and findings are already stored.
func (s *Service) stampScanAttribution(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding, scope *alterScope, toolName, reportID string, assetMap map[string]shared.ID) {
	if s.scanAttribution == nil || agt == nil {
		return
	}
	assets := scanStampTargets(binding, scope, assetMap)
	if len(assets) == 0 {
		return
	}
	prov := ScanProvenance{
		SensorID:    agt.ID,
		CommandID:   binding.CommandID,
		StepRunID:   binding.StepRunID,
		Tool:        toolName,
		ReportID:    reportID,
		ObservedAt:  time.Now().UTC(),
		Unsolicited: binding.Kind == BindingUnsolicited,
	}
	if err := s.scanAttribution.StampScanned(ctx, tenantID, assets, prov); err != nil {
		s.logger.Warn("ingest: sensor-report attribution not recorded",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "assets", len(assets),
			"error", logger.SanitizeError(err))
	}
}

// scanStampTargets returns the persisted assets a sensor report may
// attribute: for a bound report, those it created and the existing ones its
// command covers; for an unsolicited one, only those it created. Trusted
// ingests attribute nothing here.
func scanStampTargets(binding Binding, scope *alterScope, assetMap map[string]shared.ID) []ScannedAsset {
	if scope == nil || (binding.Kind != BindingCommand && binding.Kind != BindingUnsolicited) {
		return nil
	}
	ids := map[shared.ID]bool{}
	for id, seen := range scope.seen {
		if seen.created {
			ids[id] = true
		}
	}
	if binding.Kind == BindingCommand {
		for _, id := range assetMap {
			if !id.IsZero() && scope.allowed[id] {
				ids[id] = true
			}
		}
	}
	out := make([]ScannedAsset, 0, len(ids))
	for id := range ids {
		seen, known := scope.seen[id]
		a := ScannedAsset{ID: id, Created: seen.created}
		if known {
			a.Name, a.Type = seen.name, seen.typ
			a.Typed = binding.Kind == BindingCommand && scope.typedTarget(seen.name)
		}
		out = append(out, a)
	}
	return out
}
