package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GET /api/v1/admin/target-mappings/types lists exactly what Create accepts,
// so the console stops keeping its own copy of the two lists.
func TestAdminTargetMappingTypes_ListsWhatCreateAccepts(t *testing.T) {
	h := NewAdminTargetMappingHandler(nil, logger.NewNop())
	rec := httptest.NewRecorder()
	h.Types(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/target-mappings/types", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var got TargetMappingTypesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !slices.Equal(got.TargetTypes, tool.ValidTargetTypes) {
		t.Errorf("target_types: got %v, want %v", got.TargetTypes, tool.ValidTargetTypes)
	}
	want := make([]string, 0, len(asset.AllAssetTypes()))
	for _, a := range asset.AllAssetTypes() {
		want = append(want, string(a))
	}
	if !slices.Equal(got.AssetTypes, want) {
		t.Errorf("asset_types: got %v, want %v", got.AssetTypes, want)
	}
	for _, tt := range got.TargetTypes {
		if !tool.IsValidTargetType(tt) {
			t.Errorf("listed target type %q is refused by Create", tt)
		}
	}
	for _, at := range got.AssetTypes {
		if !asset.AssetType(at).IsValid() {
			t.Errorf("listed asset type %q is refused by Create", at)
		}
	}
	// The values seeded before the fix are not on the lists.
	for _, stale := range []string{"cloud"} {
		if slices.Contains(got.TargetTypes, stale) {
			t.Errorf("stale target type %q listed", stale)
		}
	}
	for _, stale := range []string{"ip", "server", "serverless_function"} {
		if slices.Contains(got.AssetTypes, stale) {
			t.Errorf("stale asset type %q listed", stale)
		}
	}
}
