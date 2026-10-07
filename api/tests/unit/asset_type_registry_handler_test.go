package unit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// GET /api/v1/asset-types serves the RFC-042 type registry, with a strong
// ETag, and keeps the legacy asset_types rows (data/total/...) unchanged.

func newRegistryHandler(t *testing.T) (*handler.AssetTypeHandler, *mockAssetTypeRepository) {
	t.Helper()
	svc, repo, _ := newTestAssetTypeService()
	return handler.NewAssetTypeHandler(svc, validator.New(), logger.NewNop()), repo
}

func getAssetTypes(t *testing.T, h *handler.AssetTypeHandler, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ListAssetTypes(rec, req)
	return rec
}

func TestAssetTypesEndpoint_ServesTheRegistry(t *testing.T) {
	h, _ := newRegistryHandler(t)
	rec := getAssetTypes(t, h, "/api/v1/asset-types", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var body handler.AssetTypeRegistryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg := asset.RegistryDocument()
	if body.Version != asset.RegistryVersion {
		t.Errorf("version %q, want %q", body.Version, asset.RegistryVersion)
	}
	if len(body.Types) != len(reg.Types) || len(body.Classes) != len(reg.Classes) || len(body.Lenses) != len(reg.Lenses) {
		t.Errorf("types/classes/lenses = %d/%d/%d, want %d/%d/%d",
			len(body.Types), len(body.Classes), len(body.Lenses), len(reg.Types), len(reg.Classes), len(reg.Lenses))
	}
	if len(body.Sections) == 0 || len(body.Cards) == 0 || len(body.CoreFields) == 0 {
		t.Error("sections, cards and core_fields must be served")
	}

	byType := map[asset.AssetType]asset.TypeDefinition{}
	for _, d := range body.Types {
		byType[d.Type] = d
	}
	repo := byType[asset.AssetTypeRepository]
	if repo.Class != asset.ClassCodeRepo || repo.Lens != asset.LensCode {
		t.Errorf("repository: class %q lens %q", repo.Class, repo.Lens)
	}
	if len(repo.IdentityKeys) == 0 || len(repo.Attributes) == 0 || len(repo.Facets) == 0 ||
		len(repo.Columns) == 0 || repo.Card == "" || len(repo.Sections) == 0 || len(repo.Relationships.Out) == 0 {
		t.Errorf("repository entry is missing registry data: %+v", repo)
	}
	if fn := byType[asset.AssetTypeServerless]; fn.Class != asset.ClassFunction || fn.AliasOf == nil || fn.AliasOf.Type != asset.AssetTypeHost {
		t.Errorf("serverless: %+v", fn)
	}

	// The property schema (RFC-042 §6.3.9): ip_addresses with its labels,
	// format and synonyms.
	var ips *asset.PropertyDefinition
	for i := range body.Properties {
		if body.Properties[i].Key == asset.PropKeyIPAddresses {
			ips = &body.Properties[i]
		}
	}
	if ips == nil || ips.Label == "" || ips.LabelVI == "" || ips.Format != asset.PropertyFormatIP || len(ips.Synonyms) == 0 {
		t.Errorf("ip_addresses property = %+v", ips)
	}
	if len(body.CommonProperties) == 0 {
		t.Error("common_properties must be served")
	}

	// The wire names the web relies on.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "lenses", "classes", "types", "sections", "cards", "core_fields", "properties", "common_properties", "data", "total"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response has no %q", k)
		}
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("content-type %q", rec.Header().Get("Content-Type"))
	}
}

func TestAssetTypesEndpoint_ETagAnswers304(t *testing.T) {
	h, _ := newRegistryHandler(t)
	first := getAssetTypes(t, h, "/api/v1/asset-types", nil)
	etag := first.Header().Get("ETag")
	if len(etag) < 3 || etag[0] != '"' {
		t.Fatalf("missing strong ETag: %q", etag)
	}
	if again := getAssetTypes(t, h, "/api/v1/asset-types", nil); again.Header().Get("ETag") != etag {
		t.Errorf("ETag not stable: %q then %q", etag, again.Header().Get("ETag"))
	}

	notModified := getAssetTypes(t, h, "/api/v1/asset-types", http.Header{"If-None-Match": {`"stale", ` + etag}})
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Errorf("If-None-Match with the ETag: status %d, %d body bytes", notModified.Code, notModified.Body.Len())
	}
	if stale := getAssetTypes(t, h, "/api/v1/asset-types", http.Header{"If-None-Match": {`"stale"`}}); stale.Code != http.StatusOK {
		t.Errorf("stale ETag: status %d", stale.Code)
	}
}

// The legacy rows keep their old shapes: active_only has data+total only,
// the paginated form also page/per_page/total_pages.
func TestAssetTypesEndpoint_KeepsLegacyRows(t *testing.T) {
	h, repo := newRegistryHandler(t)
	at := makeTestAssetType("domain", "Domain", nil)
	repo.assetTypes[at.ID().String()] = at

	for _, tc := range []struct {
		query     string
		paginated bool
	}{
		{"?active_only=true", false},
		{"?page=1&per_page=10", true},
		{"", true},
	} {
		rec := getAssetTypes(t, h, "/api/v1/asset-types"+tc.query, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.query, rec.Code)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		var data []map[string]any
		if err := json.Unmarshal(raw["data"], &data); err != nil || len(data) != 1 || data[0]["code"] != "domain" {
			t.Errorf("%s: legacy data %s", tc.query, raw["data"])
		}
		if _, ok := raw["total_pages"]; ok != tc.paginated {
			t.Errorf("%s: total_pages present = %v, want %v", tc.query, ok, tc.paginated)
		}
	}
}
