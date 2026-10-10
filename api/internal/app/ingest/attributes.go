package ingest

// Attribute reconciliation (RFC-069): what a report says about an asset's
// criticality, owner, exposure and data classification is recorded as this
// source's observation, and the asset shows the value of the most trusted,
// most recent source (internal/app/asset/attribute_sources.go). The source
// kind comes from how the report arrived, never from the report: every
// sensor report is a scan, whatever it claims.

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AttributeReconciler records observations and applies what they decide.
type AttributeReconciler interface {
	ReconcileAttributes(ctx context.Context, tenantID shared.ID, obs []asset.AttributeObservation) error
}

// SetAttributeReconciler wires attribute reconciliation. Unwired, reports
// record no source and existing assets keep their tracked values.
func (s *Service) SetAttributeReconciler(r AttributeReconciler) {
	s.attributes = r
	// The same reconciler decides set attributes (IP addresses,
	// technologies, open ports) when it can; ingest then leaves those sets
	// of existing assets to it.
	s.sets, _ = r.(SetReconciler)
	s.assetProcessor.trackSets = s.sets != nil
}

// maxAttributeObservationsPerReport bounds what one report may record.
const maxAttributeObservationsPerReport = 20000

// reportSource is the kind and name a report's observations carry. Only a
// server-side ingest (an upload, an importer, an integration) may say what
// it is; every sensor and CI report is a scan.
func reportSource(b Binding, opts Options, report *ctis.Report) (asset.SourceKind, string) {
	name := ""
	if report != nil && report.Tool != nil {
		name = report.Tool.Name
	}
	if b.Kind == BindingTrusted {
		switch opts.SourceKind {
		case asset.SourceKindIntegration, asset.SourceKindImport, asset.SourceKindFeed:
			if opts.SourceName != "" {
				name = opts.SourceName
			}
			return opts.SourceKind, name
		}
	}
	return asset.SourceKindScan, name
}

// clampReportTimestamp keeps a sensor's clock from deciding which data wins:
// a report bound to a command cannot have observed anything before the
// command was handed to the sensor, nor after it arrived (now). The report
// timestamp is clamped into that window once, so every consumer
// (attribute reconciliation, last_seen, the property merge, port closing)
// uses the same observation time.
func clampReportTimestamp(report *ctis.Report, b Binding, now time.Time) {
	if report == nil {
		return
	}
	ts := report.Metadata.Timestamp
	if ts.IsZero() || ts.After(now) {
		ts = now
	}
	if !b.DispatchedAt.IsZero() && ts.Before(b.DispatchedAt) && !b.DispatchedAt.After(now) {
		ts = b.DispatchedAt
	}
	report.Metadata.Timestamp = ts
}

// reportObservedAt is when the report's source saw what it reports: its
// timestamp, never later than now.
func reportObservedAt(report *ctis.Report, now time.Time) time.Time {
	if report == nil || report.Metadata.Timestamp.IsZero() || report.Metadata.Timestamp.After(now) {
		return now
	}
	return report.Metadata.Timestamp
}

// untrustedAttributes are the tracked attributes the policy does not let
// source (kind and name) decide.
func untrustedAttributes(p asset.ReconciliationPolicy, kind asset.SourceKind, name string) map[asset.TrackedAttribute]bool {
	out := map[asset.TrackedAttribute]bool{}
	for _, attr := range asset.AllTrackedAttributes() {
		if !p.Trusts(attr, kind, name) {
			out[attr] = true
		}
	}
	return out
}

// attributeClaims are the tracked values a report asset states. A claim the
// asset does not make is absent: not reporting is not "empty".
func (p *AssetProcessor) attributeClaims(a *ctis.Asset) map[asset.TrackedAttribute]string {
	out := map[asset.TrackedAttribute]string{}
	if c := strings.TrimSpace(string(a.Criticality)); c != "" {
		out[asset.AttrCriticality] = c
	}
	if o := p.extractOwnerRef(a); o != "" {
		out[asset.AttrOwnerRef] = o
	}
	if a.IsInternetAccessible {
		out[asset.AttrExposure] = asset.ExposurePublic.String()
	} else if e, ok := a.Properties["exposure"].(string); ok && strings.TrimSpace(e) != "" {
		out[asset.AttrExposure] = e
	}
	if a.Compliance != nil && strings.TrimSpace(a.Compliance.DataClassification) != "" {
		out[asset.AttrDataClassification] = a.Compliance.DataClassification
	}
	return out
}

// recordAttributes records the tracked values the report states about the
// assets it may change, and applies what they decide. Best-effort: a
// failure is logged and never fails the report.
// attributeSource is who a report's observations come from.
type attributeSource struct {
	kind asset.SourceKind
	name string
	run  string // scan task, CI run or import
}

func (s *Service) recordAttributes(ctx context.Context, tenantID shared.ID, scope *alterScope,
	src attributeSource, observedAt time.Time,
	report *ctis.Report, assetMap map[string]shared.ID,
) {
	if s.attributes == nil || report == nil || len(assetMap) == 0 {
		return
	}
	var obs []asset.AttributeObservation
	for i := range report.Assets {
		a := &report.Assets[i]
		id, ok := assetMap[a.ID]
		if !ok || id.IsZero() || !scope.allowedAsset(id) {
			continue
		}
		confidence := a.Confidence
		if confidence <= 0 || confidence > 100 {
			confidence = 100
		}
		for attr, raw := range s.assetProcessor.attributeClaims(a) {
			v, err := asset.NormalizeAttributeValue(attr, raw)
			if err != nil {
				continue
			}
			obs = append(obs, asset.AttributeObservation{
				AssetID: id, Attribute: attr, Kind: src.kind, Name: src.name, Value: v,
				ObservedAt: observedAt, Confidence: confidence, SourceRun: src.run,
			})
		}
		if len(obs) >= maxAttributeObservationsPerReport {
			break
		}
	}
	if len(obs) == 0 {
		return
	}
	if err := s.attributes.ReconcileAttributes(ctx, tenantID, obs); err != nil {
		s.logger.Warn("asset attributes not reconciled", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}
