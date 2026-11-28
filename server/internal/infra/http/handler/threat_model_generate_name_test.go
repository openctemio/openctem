package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A threat model is named after its scope and renamed with it on every
// regeneration, so a name in the generate request cannot be kept. It used to
// be dropped without a word; it is now refused with a code that says why,
// before anything is generated.
func TestThreatModelGenerate_RefusesName(t *testing.T) {
	h := NewThreatModelHandler(nil, logger.NewNop())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/threat-models/generate",
		strings.NewReader(`{"scope_type":"tenant","name":"Board review 2026"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.Generate(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codeThreatModelNameFromScope) {
		t.Fatalf("generate with a name: %d %s, want 400 %s", rec.Code, rec.Body, codeThreatModelNameFromScope)
	}
}
