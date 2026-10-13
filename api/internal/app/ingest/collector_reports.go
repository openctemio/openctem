package ingest

// Complete reports from trusted collectors (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §12, docs/architecture/sensor-result-binding.md).
//
// A collector report names no command, so it is unsolicited: it may create
// assets but never change an existing one. That keeps a re-collected
// inventory from refreshing anything that changed. The exception is narrow:
//
//   - The source is a collector of the tenant that an administrator trusted
//     (trustedCollector), reporting one collector instance: the sensor, the
//     tool (collector type) and metadata.source_ref (the instance) together
//     are the collector source.
//   - Every report of a trusted collector records which assets the source
//     reported (collector_assets) and whether it created them.
//   - A COMPLETE report (coverage_type "full") of the source may change the
//     existing assets that source created, unless a person decided on them
//     (a manual attribute lock or a manual status override). Assets another
//     source created, or a person decided on, are only marked seen.
//   - When a complete report is committed, the assets the source created and
//     no longer lists are marked not seen (status stale, never deleted),
//     unless any source saw them after the report's time, the report lost
//     assets on the way, or the share would blind the inventory
//     (BlindingGuard). A partial or incremental report never marks anything.

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxCollectorSourceRef bounds the collector instance name a report gives.
const maxCollectorSourceRef = 255

// CollectorSource is one collector instance of a sensor.
type CollectorSource struct {
	TenantID  shared.ID
	SensorID  shared.ID
	Tool      string
	SourceRef string
}

// CollectorSighting is one asset a collector source reported.
type CollectorSighting struct {
	AssetID shared.ID
	// Created: this report created the asset.
	Created bool
}

// UnseenResult is what marking a source's unlisted assets did.
type UnseenResult struct {
	// Owned is how many listed assets the source created; Unseen how many
	// of them the report no longer lists (and nobody saw since).
	Owned, Unseen int
	// Held: Unseen was too large a share of Owned (BlindingGuard); nothing
	// was marked.
	Held bool
	// Demoted are the assets that went from active to stale.
	Demoted []shared.ID
}

// CollectorAssetStore keeps which assets each collector source reported.
// Every method is scoped to the source's tenant.
type CollectorAssetStore interface {
	// OwnedAssets returns the ids among ids the source created and no person
	// decided on (no manual attribute lock, no manual status override).
	OwnedAssets(ctx context.Context, src CollectorSource, ids []shared.ID) (map[shared.ID]bool, error)
	// RecordSightings records that the source reported these assets at
	// observedAt (never moving last_seen backwards) and clears their
	// missing mark.
	RecordSightings(ctx context.Context, src CollectorSource, observedAt time.Time, sightings []CollectorSighting) error
	// MarkUnseen marks the assets the source created that are not in
	// listed, that it last reported before observedAt and that no source saw
	// at or after observedAt, as missing, and demotes the active ones to
	// stale (never a manual status override, never deleted). guard decides
	// whether the share is too large: then nothing changes and Held is set.
	MarkUnseen(ctx context.Context, src CollectorSource, observedAt time.Time, listed []shared.ID, guard BlindingGuard) (UnseenResult, error)
}

// SetCollectorAssets wires the collector source store. Unwired, collector
// reports keep the unsolicited limits and nothing is marked not seen.
func (s *Service) SetCollectorAssets(store CollectorAssetStore) { s.collectorAssets = store }

// completeCoverage reports whether a report says it covers everything its
// source has: coverage_type "full". Partial, incremental and unset are not
// complete.
func completeCoverage(md ctis.ReportMetadata) bool {
	return strings.EqualFold(strings.TrimSpace(md.CoverageType), "full")
}

// collectorSourceOf is the collector source of a report from a trusted
// collector, or nil: the report must name its tool.
func collectorSourceOf(tenantID, sensorID shared.ID, tool *ctis.Tool, md ctis.ReportMetadata) *CollectorSource {
	if tool == nil || strings.TrimSpace(tool.Name) == "" {
		return nil
	}
	ref := strings.TrimSpace(md.SourceRef)
	if len(ref) > maxCollectorSourceRef {
		ref = ref[:maxCollectorSourceRef]
	}
	return &CollectorSource{TenantID: tenantID, SensorID: sensorID, Tool: strings.ToLower(strings.TrimSpace(tool.Name)), SourceRef: ref}
}

// collectorScope is a trusted collector's authority inside one ingest.
type collectorScope struct {
	src *CollectorSource
	// complete: the report is complete, so the source may change the
	// existing assets it owns.
	complete bool
	// owned caches OwnedAssets answers; lookup asks the store on a miss.
	owned  map[shared.ID]bool
	lookup func(ids []shared.ID) map[shared.ID]bool
}

// owns reports whether the source owns the existing asset id (complete
// reports only). A store error is "no" (fail closed).
func (c *collectorScope) owns(id shared.ID) bool {
	if c == nil || !c.complete || id.IsZero() {
		return false
	}
	if v, ok := c.owned[id]; ok {
		return v
	}
	c.prime([]shared.ID{id})
	return c.owned[id]
}

// prime looks up the ownership of ids not cached yet, in one call.
func (c *collectorScope) prime(ids []shared.ID) {
	if c == nil || !c.complete || c.lookup == nil {
		return
	}
	var missing []shared.ID
	for _, id := range ids {
		if _, ok := c.owned[id]; !ok && !id.IsZero() {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return
	}
	found := c.lookup(missing)
	for _, id := range missing {
		c.owned[id] = found[id]
	}
}

// collectorScopeFor builds the authority of a report from a trusted
// collector (trusted: the caller checked trustedCollector for this report's
// unsolicited binding), or nil for any other report.
func (s *Service) collectorScopeFor(ctx context.Context, trusted bool, sensorID, tenantID shared.ID, report *ctis.Report) *collectorScope {
	if s.collectorAssets == nil || !trusted || report == nil {
		return nil
	}
	src := collectorSourceOf(tenantID, sensorID, report.Tool, report.Metadata)
	if src == nil {
		return nil
	}
	store := s.collectorAssets
	c := &collectorScope{src: src, complete: completeCoverage(report.Metadata), owned: map[shared.ID]bool{}}
	c.lookup = func(ids []shared.ID) map[shared.ID]bool {
		out, err := store.OwnedAssets(ctx, *src, ids)
		if err != nil {
			s.logger.Warn("collector source: ownership lookup failed", "sensor_id", src.SensorID.String(), "error", logger.SanitizeError(err))
			return nil
		}
		return out
	}
	return c
}

// recordCollectorSightings records the assets a trusted collector's report
// stored. Best effort: a failure is logged.
func (s *Service) recordCollectorSightings(ctx context.Context, c *collectorScope, scope *alterScope,
	observedAt time.Time, assetMap map[string]shared.ID,
) {
	if c == nil || len(assetMap) == 0 {
		return
	}
	seen := map[shared.ID]bool{}
	sightings := make([]CollectorSighting, 0, len(assetMap))
	for _, id := range assetMap {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		created := false
		if scope != nil {
			created = scope.seen[id].created
		}
		sightings = append(sightings, CollectorSighting{AssetID: id, Created: created})
	}
	if err := s.collectorAssets.RecordSightings(ctx, *c.src, observedAt, sightings); err != nil {
		s.logger.Warn("collector source: sightings not recorded", "sensor_id", c.src.SensorID.String(),
			"tool", sanitizeIngestLogField(c.src.Tool), "error", logger.SanitizeError(err))
	}
}

// reportLostAssets reports whether any segment of a report refused,
// quarantined or failed an asset: its source's listing is then incomplete.
func reportLostAssets(rep *ingestreport.Report) bool {
	if rep == nil || len(rep.Outcomes) < rep.SegmentsReceived {
		return true
	}
	for _, o := range rep.Outcomes {
		if o.RejectedAssets > 0 || o.QuarantinedAssets > 0 {
			return true
		}
	}
	return false
}

// sweepCollectorReport marks not seen, after a complete report of a trusted
// collector was committed, the assets its source created that the report no
// longer lists. Best effort: a failure is logged and never fails the report.
func (s *Service) sweepCollectorReport(ctx context.Context, rep *ingestreport.Report, header V2Header, guard BlindingGuard) {
	if s.collectorAssets == nil || rep == nil || rep.CommandID != nil || !completeCoverage(header.Metadata) {
		return
	}
	// An empty report never says everything is gone.
	if len(rep.TouchedAssetIDs) == 0 || reportLostAssets(rep) {
		s.logger.Info("collector sweep skipped: the report is empty or lost assets",
			"report_ref", rep.ID.String(), "touched", len(rep.TouchedAssetIDs))
		return
	}
	tenantID := rep.TenantID
	agt := &sensor.Sensor{ID: rep.SensorID, TenantID: &tenantID, Type: sensor.SensorType(rep.SensorType)}
	if !s.trustedCollector(ctx, agt, tenantID) {
		return
	}
	src := collectorSourceOf(tenantID, rep.SensorID, header.Tool, header.Metadata)
	if src == nil {
		return
	}
	now := time.Now()
	observedAt := reportObservedAt(&ctis.Report{Metadata: header.Metadata}, now)
	res, err := s.collectorAssets.MarkUnseen(ctx, *src, observedAt, rep.TouchedAssetIDs, guard)
	if err != nil {
		s.logger.Warn("collector sweep failed", "report_ref", rep.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	if res.Held {
		s.logger.Warn("collector sweep held: the report no longer lists too many of its assets",
			"report_ref", rep.ID.String(), "tool", sanitizeIngestLogField(src.Tool), "owned", res.Owned, "unseen", res.Unseen)
		return
	}
	s.recordCollectorDisappeared(ctx, tenantID, src.Tool, res.Demoted)
	if res.Unseen > 0 {
		s.logger.Info("collector sweep: assets no longer listed", "report_ref", rep.ID.String(),
			"tool", sanitizeIngestLogField(src.Tool), "unseen", res.Unseen, "demoted", len(res.Demoted))
	}
}

// recordCollectorDisappeared writes one disappeared state-history row per
// asset a complete collector report demoted to stale. Best effort.
func (s *Service) recordCollectorDisappeared(ctx context.Context, tenantID shared.ID, tool string, ids []shared.ID) {
	if len(ids) == 0 || s.assetProcessor == nil || s.assetProcessor.stateHistory == nil {
		return
	}
	changes := make([]*asset.AssetStateChange, 0, len(ids))
	for _, id := range ids {
		ch := asset.RecordFieldChange(tenantID, id, asset.StateChangeDisappeared,
			"status", string(asset.StatusActive), string(asset.StatusStale), asset.ChangeSourceIntegration, nil)
		ch.SetReason("not in the latest complete report of collector " + sanitizeIngestLogField(tool))
		changes = append(changes, ch)
	}
	if err := s.assetProcessor.stateHistory.CreateBatch(ctx, changes); err != nil {
		s.logger.Warn("collector sweep: state history not recorded", "count", len(changes), "error", logger.SanitizeError(err))
	}
}
