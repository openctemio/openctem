package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An asset_id that is not a UUID is refused before any query runs.
func TestMergeLog_InvalidAssetID(t *testing.T) {
	h := NewAdminDedupHandler(nil, logger.NewNop())
	for _, id := range []string{"nope", "1' OR '1'='1", "123"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/dedup/merge-log", nil)
		q := req.URL.Query()
		q.Set("asset_id", id)
		req.URL.RawQuery = q.Encode()
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "11111111-1111-7111-8111-111111111111"))
		rec := httptest.NewRecorder()
		h.MergeLog(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("asset_id %q: got %d, want 400", id, rec.Code)
		}
	}
}
