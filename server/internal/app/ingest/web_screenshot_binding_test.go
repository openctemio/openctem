package ingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"io"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	webevidenceapp "github.com/openctemio/openctem/server/internal/app/webevidence"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/webevidence"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// In-memory stores for the real web evidence service.
type memEvidenceRepo struct{ recs []webevidence.Record }

func (m *memEvidenceRepo) Insert(_ context.Context, r webevidence.Record) error {
	r.ID = shared.NewID().String()
	m.recs = append(m.recs, r)
	return nil
}
func (m *memEvidenceRepo) List(context.Context, shared.ID, shared.ID) ([]webevidence.Record, error) {
	return m.recs, nil
}
func (m *memEvidenceRepo) Get(context.Context, shared.ID, shared.ID, string) (*webevidence.Record, error) {
	return nil, shared.ErrNotFound
}
func (m *memEvidenceRepo) ExpireScreenshots(context.Context, time.Time, int) ([]webevidence.BlobRef, error) {
	return nil, nil
}
func (m *memEvidenceRepo) TakeOrphans(context.Context, int) ([]webevidence.BlobRef, error) {
	return nil, nil
}
func (m *memEvidenceRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) { return 0, nil }

type memBlobs struct{ n int }

func (m *memBlobs) StoreBlob(_ context.Context, tenantID, name, _ string, _ []byte) (string, string, error) {
	m.n++
	return tenantID + "/" + name, "local", nil
}
func (m *memBlobs) OpenBlob(context.Context, string, string, string) (io.ReadCloser, error) {
	return nil, shared.ErrNotFound
}
func (m *memBlobs) DeleteBlob(context.Context, string, string, string) error { return nil }

type switchSettings map[string]bool

func (s switchSettings) GetEASMSettings(_ context.Context, id string) (*tenant.EASMSettings, error) {
	return &tenant.EASMSettings{WebScreenshotsEnabled: s[id]}, nil
}

// A report bound to capture.screenshot (tool webshot, a web_origin asset
// with the same canonical value as the stored http_service) records the
// capture and its picture on that service when the organization has
// screenshots on, and only the text when it has them off. A report asset
// that names a service the tenant does not have (another tenant's service is
// never in the tenant's lookup), or one the report may not change, records
// nothing.
func TestWebshotReportBindsToStoredHTTPService(t *testing.T) {
	ctx := context.Background()
	on, off := shared.NewID(), shared.NewID()
	repo, blobs := &memEvidenceRepo{}, &memBlobs{}
	svc := webevidenceapp.NewService(repo, blobs, switchSettings{on.String(): true}, nil)
	p := &AssetProcessor{logger: logger.NewNop()}
	p.SetWebEvidenceRecorder(svc)

	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 6)))
	capture := []any{map[string]any{
		"url": "https://app.example.com/", "status_code": float64(200), "title": "App",
		"screenshot": map[string]any{"data": base64.StdEncoding.EncodeToString(buf.Bytes())},
	}}
	report := func(value string) *ctis.Report {
		return &ctis.Report{Tool: &ctis.Tool{Name: "webshot"}, Assets: []ctis.Asset{
			{ID: "o1", Type: ctis.AssetTypeWebOrigin, Value: value, Properties: ctis.Properties{"web_evidence": capture}},
		}}
	}
	stored, err := asset.NewAsset("https://app.example.com", asset.AssetTypeService, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	stored.SetSubType("http")
	existing := map[string]*asset.Asset{asset.NormalizeName("https://app.example.com", asset.AssetTypeService, "http"): stored}
	all := func(shared.ID) bool { return true }

	// Switch on: text and picture.
	p.recordWebEvidence(ctx, on, report("https://app.example.com"), existing, all)
	if len(repo.recs) != 1 || repo.recs[0].AssetID != stored.ID().String() || repo.recs[0].TenantID != on.String() ||
		!repo.recs[0].HasScreenshot() || blobs.n != 1 {
		t.Fatalf("switch on: %+v blobs %d", repo.recs, blobs.n)
	}
	// Switch off: the text only, no file.
	repo.recs, blobs.n = nil, 0
	p.recordWebEvidence(ctx, off, report("https://app.example.com"), existing, all)
	if len(repo.recs) != 1 || repo.recs[0].HasScreenshot() || blobs.n != 0 {
		t.Fatalf("switch off: %+v blobs %d", repo.recs, blobs.n)
	}
	// A service this tenant does not have.
	repo.recs = nil
	p.recordWebEvidence(ctx, on, report("https://other-tenant.example.net"), existing, all)
	// A service the report may not change.
	p.recordWebEvidence(ctx, on, report("https://app.example.com"), existing, func(shared.ID) bool { return false })
	if len(repo.recs) != 0 {
		t.Fatalf("recorded for an unknown or locked service: %+v", repo.recs)
	}
}

// A changed title, status code, redirect target or favicon of a stored web
// service is a page change; a first value, an unchanged page and another
// asset type are not.
func TestPageSignature(t *testing.T) {
	svc := func(props map[string]any) *asset.Asset {
		a, _ := asset.NewAsset("https://app.example.com", asset.AssetTypeService, asset.CriticalityMedium)
		a.SetSubType("http")
		a.SetProperties(props)
		return a
	}
	base := svc(map[string]any{"title": "Home", "status_code": 200})
	if pageSignature(base) == "" || pageSignature(base) != pageSignature(svc(map[string]any{"status_code": 200, "title": "Home"})) {
		t.Fatal("signature is stable")
	}
	for name, props := range map[string]map[string]any{
		"title":    {"title": "Login", "status_code": 200},
		"status":   {"title": "Home", "status_code": 500},
		"redirect": {"title": "Home", "status_code": 200, "redirect_url": "https://x.example.com/"},
		"favicon":  {"title": "Home", "status_code": 200, propFaviconMMH3: "123"},
	} {
		if pageSignature(svc(props)) == pageSignature(base) {
			t.Errorf("%s change not seen", name)
		}
	}
	if pageSignature(svc(map[string]any{"server": "nginx"})) != "" {
		t.Fatal("an unwatched property is no page")
	}
	host, _ := asset.NewAsset("h.example.com", asset.AssetTypeHost, asset.CriticalityMedium)
	host.SetProperties(map[string]any{"title": "x"})
	if pageSignature(host) != "" {
		t.Fatal("only an http service is watched")
	}
}

type pageNotes struct{ ids []shared.ID }

func (n *pageNotes) PagesChanged(_ context.Context, _ shared.ID, ids []shared.ID) error {
	n.ids = append(n.ids, ids...)
	return nil
}

// A probe that changes what a stored web service's page looks like is
// collected for re-capture; the same page seen again is not.
func TestMergeCollectsChangedPages(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	a, _ := asset.NewAsset("https://app.example.com", asset.AssetTypeService, asset.CriticalityMedium)
	a.SetSubType("http")
	a.SetProperties(map[string]any{"title": "Home", "status_code": 200})
	var changed []shared.ID
	probe := func(title string) {
		p.mergeTrackingExposure(shared.NewID(), a, &ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: a.Name(),
			Properties: ctis.Properties{"title": title}}, nil, time.Now(), nil, nil, &changed)
	}
	probe("Home")
	if len(changed) != 0 {
		t.Fatalf("an unchanged page: %v", changed)
	}
	probe("Login")
	if len(changed) != 1 || changed[0] != a.ID() {
		t.Fatalf("a changed title: %v", changed)
	}
	n := &pageNotes{}
	p.SetPageChangeNotifier(n)
	p.notifyPagesChanged(context.Background(), shared.NewID(), changed)
	if len(n.ids) != 1 {
		t.Fatal("the notifier was not called")
	}
}
