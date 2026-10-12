package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type fakeWebRecorder struct {
	items []webevidence.Item
	tool  string
}

func (f *fakeWebRecorder) RecordReport(_ context.Context, _ shared.ID, tool string, items []webevidence.Item) (int, int) {
	f.tool, f.items = tool, items
	return len(items), 0
}

// Captures reach the recorder only for stored assets the report may
// change, and the reserved property never lands on the asset.
func TestRecordWebEvidence(t *testing.T) {
	rec := &fakeWebRecorder{}
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	p.SetWebEvidenceRecorder(rec)

	mine, _ := asset.NewAsset("app.example.com", asset.AssetTypeSubdomain, asset.CriticalityMedium)
	locked, _ := asset.NewAsset("other.example.com", asset.AssetTypeSubdomain, asset.CriticalityMedium)
	capture := []any{map[string]any{"url": "https://app.example.com/"}}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "screenshot"}, Assets: []ctis.Asset{
		{ID: "a1", Type: "subdomain", Value: "app.example.com", Properties: ctis.Properties{"web_evidence": capture}},
		{ID: "a2", Type: "subdomain", Value: "other.example.com", Properties: ctis.Properties{"web_evidence": capture}},
		{ID: "a3", Type: "subdomain", Value: "unknown.example.com", Properties: ctis.Properties{"web_evidence": capture}},
		{ID: "a4", Type: "subdomain", Value: "plain.example.com"},
	}}
	existing := map[string]*asset.Asset{"app.example.com": mine, "other.example.com": locked}
	p.recordWebEvidence(context.Background(), shared.NewID(), report, existing, func(id shared.ID) bool { return id == mine.ID() })
	if len(rec.items) != 1 || rec.items[0].AssetID != mine.ID() || rec.tool != "screenshot" {
		t.Fatalf("items: %+v tool %q", rec.items, rec.tool)
	}

	props := p.buildPropertiesFromCTIS(&report.Assets[0])
	if _, ok := props["web_evidence"]; ok {
		t.Fatal("web_evidence stored on the asset")
	}
}
