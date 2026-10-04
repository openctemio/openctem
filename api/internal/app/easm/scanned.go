package easm

// tenant_scanned attribution evidence (RFC-036 §6.4, owner decision O8):
// assets a tenant's own scan reported get evidence naming the sensor, the
// command, the scan run, the tool and the report, and their attribution is
// re-evaluated (automation only raises it and never overrides a person).
//
// Which assets qualify is decided by ingest (command-bound reports, assets
// the report may change); this side only records. Every write is
// tenant-scoped in the store: an asset id of another tenant writes nothing.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanEvidenceStore is the storage the stamper needs.
type ScanEvidenceStore interface {
	// UpsertEvidenceBulk records one evidence row per asset (same rule,
	// technique, source, weight and datum) in one statement.
	UpsertEvidenceBulk(ctx context.Context, tenantID shared.ID, assetIDs []string, ev attribution.Evidence) error
	FiredRules(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string][]attribution.Rule, error)
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
	SaveAutomatic(ctx context.Context, tenantID shared.ID, assetID string, d attribution.Decision) error
	// ScanRunOf returns the pipeline run and scan of a step run in the
	// tenant ("" when unknown).
	ScanRunOf(ctx context.Context, tenantID, stepRunID shared.ID) (runID, scanID string, err error)
}

// ScanStamper implements ingest.ScanAttributionStamper.
type ScanStamper struct {
	store ScanEvidenceStore
}

var _ ingest.ScanAttributionStamper = (*ScanStamper)(nil)

// NewScanStamper creates the stamper.
func NewScanStamper(store ScanEvidenceStore) *ScanStamper {
	return &ScanStamper{store: store}
}

// TechniqueSensorScan is the technique of a tenant-scan sighting whose tool
// is unknown.
const TechniqueSensorScan = "sensor_scan"

// StampScanned records the evidence and raises the attribution of assets
// that already have an automatic record. An asset with no record is a
// legacy or scan-created asset and is confirmed by construction: it gets the
// evidence only.
func (s *ScanStamper) StampScanned(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, prov ingest.ScanProvenance) error {
	if len(assetIDs) == 0 || prov.SensorID.IsZero() {
		return nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	observed := map[string]any{
		"sensor_id":   prov.SensorID.String(),
		"observed_at": prov.ObservedAt.UTC().Format(time.RFC3339),
	}
	if prov.CommandID != nil {
		observed["command_id"] = prov.CommandID.String()
	}
	if prov.Tool != "" {
		observed["tool"] = prov.Tool
	}
	if prov.ReportID != "" {
		observed["report_id"] = truncate(prov.ReportID, 200)
	}
	if prov.StepRunID != nil {
		observed["step_run_id"] = prov.StepRunID.String()
		runID, scanID, err := s.store.ScanRunOf(ctx, tenantID, *prov.StepRunID)
		if err != nil {
			return fmt.Errorf("resolve scan run: %w", err)
		}
		if runID != "" {
			observed["pipeline_run_id"] = runID
		}
		if scanID != "" {
			observed["scan_id"] = scanID
		}
	}
	technique := TechniqueSensorScan
	if prov.Tool != "" {
		technique = truncate(prov.Tool, 100)
	}
	w, _, err := attribution.Weight(attribution.RuleTenantScanned)
	if err != nil {
		return err
	}
	ev := attribution.Evidence{
		Rule:      attribution.RuleTenantScanned,
		Technique: technique,
		// One row per (asset, sensor): a re-scan refreshes the datum and
		// last_observed_at instead of piling up rows.
		Source:   "sensor:" + prov.SensorID.String(),
		Weight:   w,
		Observed: observed,
	}
	if err := s.store.UpsertEvidenceBulk(ctx, tenantID, ids, ev); err != nil {
		return err
	}

	records, err := s.store.Records(ctx, tenantID, ids)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	recorded := make([]string, 0, len(records))
	for id := range records {
		recorded = append(recorded, id)
	}
	fired, err := s.store.FiredRules(ctx, tenantID, recorded)
	if err != nil {
		return err
	}
	for _, id := range recorded {
		rec := records[id]
		if rec.HumanDecided {
			continue
		}
		dec, err := attribution.Evaluate(fired[id])
		if err != nil {
			return err
		}
		if err := s.store.SaveAutomatic(ctx, tenantID, id, attribution.Merge(&rec, dec)); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
