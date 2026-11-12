package ingest

import (
	"context"

	"github.com/openctemio/ctis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/server/internal/app/taggov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tag"
)

// ingestAssetTagsDropped counts the tags an import dropped before they
// reached an asset, by reason (too_long, hidden_chars, markup,
// formula_prefix, reserved, protected, over_cap, empty).
var ingestAssetTagsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "openctem", Subsystem: "ingest", Name: "asset_tags_dropped_total",
	Help: "Asset tags an import (sensor report, connector, importer) dropped, by reason",
}, []string{"reason"})

// importTags is the one gate every ingested asset tag passes: the shared
// validator (length, characters, reserved namespaces), the per-import cap,
// and the allow check. It returns what may be stored; the rest is counted.
func (p *AssetProcessor) importTags(raw []string, assetRef string, allow func(string) (tag.Reason, bool)) []string {
	kept, dropped := tag.FilterImport(raw, allow)
	for reason, n := range dropped {
		ingestAssetTagsDropped.WithLabelValues(string(reason)).Add(float64(n))
	}
	if len(dropped) > 0 && p.logger != nil {
		p.logger.Warn("asset tags dropped by import",
			"asset_id", assetRef, "received", len(raw), "kept", len(kept))
	}
	return kept
}

// TagGovernor answers the governing tags of a tenant (*taggov.Governor).
type TagGovernor interface {
	For(ctx context.Context, tenantID shared.ID) (taggov.Set, error)
}

// SetTagGovernor wires the check that keeps imports from setting a tag an
// access rule, approval rule, scan window or assignment rule reads.
// Without it imports still pass the shared validator.
func (p *AssetProcessor) SetTagGovernor(g TagGovernor) { p.tagGovernor = g }

// dropGoverningTags removes, from every asset of the report, the tags the
// tenant's rules read. Governing tags are changed by people holding the
// permission to change the rule (the asset API); an import that could set
// one could widen a team's access or escape an approval. When the governing
// set cannot be read the report's tags are dropped (fail closed).
func (p *AssetProcessor) dropGoverningTags(ctx context.Context, tenantID shared.ID, report *ctis.Report) {
	if p.tagGovernor == nil || report == nil {
		return
	}
	hasTags := false
	for i := range report.Assets {
		if len(report.Assets[i].Tags) > 0 {
			hasTags = true
			break
		}
	}
	if !hasTags {
		return
	}
	set, err := p.tagGovernor.For(ctx, tenantID)
	if err != nil && p.logger != nil {
		p.logger.Warn("governing tags unavailable; dropping report tags", "tenant_id", tenantID.String(), "error", err)
	}
	allow := taggov.ImportAllow(set, err)
	for i := range report.Assets {
		a := &report.Assets[i]
		if len(a.Tags) == 0 {
			continue
		}
		a.Tags = p.importTags(a.Tags, a.ID, allow)
	}
}
