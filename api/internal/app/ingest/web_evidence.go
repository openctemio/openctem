package ingest

// Web evidence (docs/rfcs/RFC-081-web-evidence-screenshots.md): a report
// asset's reserved `web_evidence` property is handed, with the stored asset
// it resolved to, to the web evidence recorder. The property itself is never
// stored on the asset (asset.IsReservedPropertyKey).

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
)

// WebEvidenceRecorder stores the captures of one report.
type WebEvidenceRecorder interface {
	RecordReport(ctx context.Context, tenantID shared.ID, tool string, items []webevidence.Item) (stored, skipped int)
}

// SetWebEvidenceRecorder enables web evidence (nil = captures dropped).
func (p *AssetProcessor) SetWebEvidenceRecorder(r WebEvidenceRecorder) { p.webEvidence = r }

// recordWebEvidence passes the captures of the report's assets this report
// may change (RFC-040 §5.3) to the recorder. Best effort.
func (p *AssetProcessor) recordWebEvidence(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	existingMap map[string]*asset.Asset, mayChange func(shared.ID) bool,
) {
	if p.webEvidence == nil {
		return
	}
	items := make([]webevidence.Item, 0, len(report.Assets))
	for i := range report.Assets {
		a := &report.Assets[i]
		raw, ok := a.Properties[asset.PropKeyWebEvidence]
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
		items = append(items, webevidence.Item{AssetID: stored.ID(), Raw: raw})
	}
	if len(items) == 0 {
		return
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	stored, skipped := p.webEvidence.RecordReport(ctx, tenantID, tool, items)
	if skipped > 0 {
		p.logger.Info("web evidence: captures skipped", "tenant_id", tenantID.String(), "stored", stored, "skipped", skipped)
	}
}
