package handler

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/webevidence"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeWebEvidenceAssets struct {
	visible *assetdom.Asset
	tenants []string
}

func (f *fakeWebEvidenceAssets) GetAssetInCallerScope(_ context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	f.tenants = append(f.tenants, tenantID)
	if f.visible != nil && f.visible.ID().String() == assetID {
		return f.visible, nil
	}
	return nil, shared.ErrNotFound
}

type fakeWebEvidence struct {
	recs []webevidence.Record
	png  []byte
}

func (f *fakeWebEvidence) List(context.Context, shared.ID, shared.ID) ([]webevidence.Record, error) {
	return f.recs, nil
}

func (f *fakeWebEvidence) Screenshot(_ context.Context, _, _ shared.ID, id string) (io.ReadCloser, *webevidence.Record, error) {
	if id != "e1" {
		return nil, nil, shared.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(f.png)), &webevidence.Record{ScreenshotSize: len(f.png)}, nil
}

func webEvidenceReq(t *testing.T, path string, tenantID shared.ID, pathValues map[string]string) *http.Request {
	t.Helper()
	r := seedReq(http.MethodGet, path, "", tenantID, "u1")
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	return r
}

// Web evidence is served only for an asset in the caller's data scope
// (404 otherwise, like a missing asset), and the screenshot is served as a
// sandboxed PNG.
func TestAssetWebEvidenceHandler(t *testing.T) {
	tenantID := shared.NewID()
	a, err := assetdom.NewAsset("app.example.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	scope := &fakeWebEvidenceAssets{visible: a}
	svc := &fakeWebEvidence{
		recs: []webevidence.Record{{ID: "e1", Capture: webevidence.Capture{URL: "https://app.example.com/", Title: "<script>x</script>"}, ScreenshotKey: "k"}},
		png:  []byte("\x89PNG\r\n\x1a\nfake"),
	}
	h := NewAssetWebEvidenceHandler(scope, svc, logger.NewNop())

	w := httptest.NewRecorder()
	h.List(w, webEvidenceReq(t, "/", tenantID, map[string]string{"id": a.ID().String()}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"has_screenshot":true`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if scope.tenants[0] != tenantID.String() {
		t.Fatal("asset not resolved in the token's tenant")
	}

	// Out of scope or another tenant's asset: 404 for both routes.
	other := shared.NewID().String()
	w = httptest.NewRecorder()
	h.List(w, webEvidenceReq(t, "/", tenantID, map[string]string{"id": other}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope list: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Screenshot(w, webEvidenceReq(t, "/", tenantID, map[string]string{"id": other, "evidence_id": "e1"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope screenshot: %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.Screenshot(w, webEvidenceReq(t, "/", tenantID, map[string]string{"id": a.ID().String(), "evidence_id": "e1"}))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("screenshot: %d %v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	h.Screenshot(w, webEvidenceReq(t, "/", tenantID, map[string]string{"id": a.ID().String(), "evidence_id": "nope"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing screenshot: %d", w.Code)
	}
}

// scopedEvidence keeps one capture of one asset of one tenant, like the
// repository (every read matches tenant, asset and capture id).
type scopedEvidence struct {
	tenant, asset shared.ID
	png           []byte
}

func (f *scopedEvidence) List(context.Context, shared.ID, shared.ID) ([]webevidence.Record, error) {
	return nil, nil
}

func (f *scopedEvidence) Screenshot(_ context.Context, tenantID, assetID shared.ID, id string) (io.ReadCloser, *webevidence.Record, error) {
	if tenantID != f.tenant || assetID != f.asset || id != "e1" {
		return nil, nil, shared.ErrNotFound
	}
	// The page said it was HTML; the handler never repeats that.
	rec := &webevidence.Record{ScreenshotSize: len(f.png), Capture: webevidence.Capture{ContentType: "text/html"}}
	return io.NopCloser(bytes.NewReader(f.png)), rec, nil
}

// The screenshot route answers 404 (never the picture) for another tenant
// that guesses the ids, for a valid capture id under another asset, and for
// a member whose data scope lacks the asset; it always serves a fixed PNG
// type, not anything the page or sensor sent, uncached.
func TestAssetWebEvidenceScreenshot_Isolation(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	mine, _ := assetdom.NewAsset("https://app.example.com", assetdom.AssetTypeService, assetdom.CriticalityMedium)
	sibling, _ := assetdom.NewAsset("https://www.example.com", assetdom.AssetTypeService, assetdom.CriticalityMedium)
	svc := &scopedEvidence{tenant: tenantA, asset: mine.ID(), png: []byte("\x89PNG\r\n\x1a\nfake")}
	get := func(scope *fakeWebEvidenceAssets, tenant shared.ID, assetID, evidence string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		NewAssetWebEvidenceHandler(scope, svc, logger.NewNop()).Screenshot(w,
			webEvidenceReq(t, "/", tenant, map[string]string{"id": assetID, "evidence_id": evidence}))
		return w
	}

	w := get(&fakeWebEvidenceAssets{visible: mine}, tenantA, mine.ID().String(), "e1")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" ||
		w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("own screenshot: %d %v", w.Code, w.Header())
	}
	// Tenant B guesses tenant A's asset and capture ids: the asset does not
	// resolve in B's tenant.
	if w := get(&fakeWebEvidenceAssets{}, tenantB, mine.ID().String(), "e1"); w.Code != http.StatusNotFound || w.Body.Len() > 400 {
		t.Fatalf("cross-tenant: %d", w.Code)
	}
	// Even if the asset resolved, the capture is read in the caller's tenant.
	if w := get(&fakeWebEvidenceAssets{visible: mine}, tenantB, mine.ID().String(), "e1"); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant capture: %d", w.Code)
	}
	// A valid capture id under another visible asset of the same tenant.
	if w := get(&fakeWebEvidenceAssets{visible: sibling}, tenantA, sibling.ID().String(), "e1"); w.Code != http.StatusNotFound {
		t.Fatalf("capture of another asset: %d", w.Code)
	}
	// A member outside the data scope: the asset is not visible.
	if w := get(&fakeWebEvidenceAssets{}, tenantA, mine.ID().String(), "e1"); w.Code != http.StatusNotFound {
		t.Fatalf("out of data scope: %d", w.Code)
	}
}

// The screenshot switch is off by default and omitted keeps it.
func TestEASMSettingsWebScreenshots(t *testing.T) {
	tenantID := shared.NewID()
	store := &fakeEASMSettingsStore{es: tenant.EASMSettings{}}
	h := NewEASMSettingsHandler(store, nil, &fakeSweeper{}, EASMPlatform{}, &settingsAudit{}, logger.NewNop())
	w := httptest.NewRecorder()
	h.Get(w, seedReq(http.MethodGet, "/", "", tenantID, "u1"))
	if !strings.Contains(w.Body.String(), `"web_screenshots_enabled":false`) {
		t.Fatalf("default: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true,"web_screenshots_enabled":true}`, tenantID, "u1"))
	if w.Code != http.StatusOK || !store.es.WebScreenshotsEnabled {
		t.Fatalf("enable: %d %+v", w.Code, store.es)
	}
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true}`, tenantID, "u1"))
	if !store.es.WebScreenshotsEnabled {
		t.Fatal("omitted field turned screenshots off")
	}
}
