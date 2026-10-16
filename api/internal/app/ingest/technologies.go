package ingest

// Asset technologies (docs/rfcs/RFC-112-asset-technologies.md): every
// technology a report says an asset was fingerprinted with is recorded with
// its category, version, the tool's confidence and when it was seen.
// Best-effort: a failure is logged and never fails the report.

import (
	"context"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetTechnologyRepository wires the asset technology store. Unwired,
// reports keep working and record no technologies.
func (s *Service) SetTechnologyRepository(repo assettech.Repository) {
	s.techs = repo
}

// recordTechnologies records the technologies of the report's assets this
// report was allowed to write. With set reconciliation wired, only the
// technologies the asset now shows are recorded: a source the asset does
// not trust for software adds nothing.
func (s *Service) recordTechnologies(ctx context.Context, tenantID shared.ID, scope *alterScope,
	src attributeSource, observedAt time.Time, report *ctis.Report, assetMap map[string]shared.ID,
) {
	if s.techs == nil || report == nil || len(assetMap) == 0 {
		return
	}
	source := src.name
	if report.Tool != nil && report.Tool.Name != "" {
		source = report.Tool.Name
	}
	if observedAt.IsZero() || observedAt.After(time.Now()) {
		observedAt = time.Now()
	}
	var techs []assettech.Technology
	ids := make([]shared.ID, 0, len(report.Assets))
	for i := range report.Assets {
		a := &report.Assets[i]
		id, ok := assetMap[a.ID]
		if !ok || id.IsZero() || !scope.allowedAsset(id) {
			continue
		}
		obs := technologyObservations(id, a, source, observedAt)
		if len(obs) == 0 {
			continue
		}
		if room := assettech.MaxPerReport - len(techs); len(obs) > room {
			obs = obs[:room]
		}
		techs = append(techs, obs...)
		ids = append(ids, id)
		if len(techs) >= assettech.MaxPerReport {
			break
		}
	}
	if len(techs) == 0 {
		return
	}
	if s.sets != nil {
		shown, err := s.techs.ShownKeys(ctx, tenantID, ids)
		if err != nil {
			s.logger.Warn("asset technologies not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			return
		}
		kept := techs[:0]
		for _, t := range techs {
			if shown[t.AssetID][t.Key] {
				kept = append(kept, t)
			}
		}
		techs = kept
	}
	if err := s.techs.Upsert(ctx, tenantID, techs); err != nil {
		s.logger.Warn("asset technologies not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// technologyObservations reads the technologies a CTIS asset states: the
// typed list (with the tool's categories and confidence) and the loose
// properties.technologies strings ("Name:version"), at most
// assettech.MaxPerAsset, each sanitized and classified.
func technologyObservations(id shared.ID, a *ctis.Asset, source string, seen time.Time) []assettech.Technology {
	out := make([]assettech.Technology, 0, len(a.Technologies))
	add := func(t assettech.Technology, ok bool) bool {
		if ok {
			out = append(out, t)
		}
		return len(out) < assettech.MaxPerAsset
	}
	for _, t := range a.Technologies {
		if !add(assettech.Observation(id, t.Name, t.Version, t.Categories, t.Confidence, source, seen)) {
			return out
		}
	}
	for _, key := range []string{"technologies", "technology"} {
		for _, el := range stringList(a.Properties[key]) {
			name, version := assettech.Split(el)
			if !add(assettech.Observation(id, name, version, nil, 0, source, seen)) {
				return out
			}
		}
	}
	return out
}
