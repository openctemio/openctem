package ingest

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/api/pkg/domain/tag"
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
