package ingest

// Web page monitoring (docs/rfcs/RFC-138-web-page-monitoring.md): a report
// asset's reserved `web_content` property (fetches of watched URLs) is handed,
// with the stored asset it resolved to, to the page monitor. The property
// itself is never stored on the asset (asset.IsReservedPropertyKey).

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WebContentRecorder takes the fetches of one report.
type WebContentRecorder interface {
	RecordReport(ctx context.Context, tenantID shared.ID, tool string, items []pagemon.Item) (taken, skipped int)
}

// SetWebContentRecorder enables page monitoring ingest (nil = fetches dropped).
func (p *AssetProcessor) SetWebContentRecorder(r WebContentRecorder) { p.webContent = r }

// recordWebContent passes the fetches of the report's assets this report may
// change (RFC-040 §5.3) to the page monitor. Best effort.
func (p *AssetProcessor) recordWebContent(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	existingMap map[string]*asset.Asset, mayChange func(shared.ID) bool,
) {
	if p.webContent == nil {
		return
	}
	items := make([]pagemon.Item, 0, len(report.Assets))
	for i := range report.Assets {
		a := &report.Assets[i]
		raw, ok := a.Properties[asset.PropKeyWebContent]
		if !ok {
			continue
		}
		name := getAssetName(a)
		if name == "" {
			continue
		}
		rt := resolveCTISAssetType(a)
		stored, ok := existingMap[asset.NormalizeName(name, rt.normType, rt.normSubType)]
		if !ok || stored == nil || !mayChange(stored.ID()) {
			continue
		}
		items = append(items, pagemon.Item{AssetID: stored.ID(), Raw: raw})
	}
	if len(items) == 0 {
		return
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	taken, skipped := p.webContent.RecordReport(ctx, tenantID, tool, items)
	if skipped > 0 {
		p.logger.Info("page monitoring: fetches skipped", "tenant_id", tenantID.String(), "taken", taken, "skipped", skipped)
	}
}
