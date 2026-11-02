package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type fakeContentRecorder struct {
	items []pagemon.Item
	tool  string
}

func (f *fakeContentRecorder) RecordReport(_ context.Context, _ shared.ID, tool string, items []pagemon.Item) (int, int) {
	f.tool, f.items = tool, items
	return len(items), 0
}

// Fetches reach the page monitor only for stored assets the report may
// change, and the reserved property never lands on the asset.
func TestRecordWebContent(t *testing.T) {
	rec := &fakeContentRecorder{}
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	p.SetWebContentRecorder(rec)

	mine, _ := asset.NewAsset("app.example.com", asset.AssetTypeSubdomain, asset.CriticalityMedium)
	locked, _ := asset.NewAsset("other.example.com", asset.AssetTypeSubdomain, asset.CriticalityMedium)
	fetch := []any{map[string]any{"url": "https://app.example.com/", "body": "<html>"}}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "httpx"}, Assets: []ctis.Asset{
		{ID: "a1", Type: "subdomain", Value: "app.example.com", Properties: ctis.Properties{"web_content": fetch}},
		{ID: "a2", Type: "subdomain", Value: "other.example.com", Properties: ctis.Properties{"web_content": fetch}},
		{ID: "a3", Type: "subdomain", Value: "unknown.example.com", Properties: ctis.Properties{"web_content": fetch}},
	}}
	existing := map[string]*asset.Asset{"app.example.com": mine, "other.example.com": locked}
	p.recordWebContent(context.Background(), shared.NewID(), report, existing, func(id shared.ID) bool { return id == mine.ID() })
	if len(rec.items) != 1 || rec.items[0].AssetID != mine.ID() || rec.tool != "httpx" {
		t.Fatalf("items: %+v tool %q", rec.items, rec.tool)
	}
	if props := p.buildPropertiesFromCTIS(&report.Assets[0]); props["web_content"] != nil {
		t.Fatal("web_content stored on the asset")
	}
}
