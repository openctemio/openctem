package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// newEvidenceTestHandler builds a handler with a nil service — sufficient for
// the request-boundary tests below, which all return before the service is
// consulted (bad path value / undecodable body).
func newEvidenceTestHandler() *VulnerabilityHandler {
	return NewVulnerabilityHandler(nil, validator.New(), logger.NewNop())
}

func TestAddFindingEvidence_InvalidBody400(t *testing.T) {
	h := newEvidenceTestHandler()
	req := httptest.NewRequest("POST", "/api/v1/findings/f1/evidence", strings.NewReader("{not-json"))
	req.SetPathValue("id", "f1")
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "tenant-1"))
	rec := httptest.NewRecorder()

	h.AddFindingEvidence(rec, req)

	if rec.Code != 400 {
		t.Fatalf("invalid body: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAddFindingEvidence_MissingID400(t *testing.T) {
	h := newEvidenceTestHandler()
	req := httptest.NewRequest("POST", "/api/v1/findings//evidence", strings.NewReader(`{"description":"x"}`))
	// No path value set → empty id.
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "tenant-1"))
	rec := httptest.NewRecorder()

	h.AddFindingEvidence(rec, req)

	if rec.Code != 400 {
		t.Fatalf("missing id: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAddRemediationStep_InvalidBody400(t *testing.T) {
	h := newEvidenceTestHandler()
	req := httptest.NewRequest("POST", "/api/v1/findings/f1/remediation/steps", strings.NewReader("]["))
	req.SetPathValue("id", "f1")
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "tenant-1"))
	rec := httptest.NewRecorder()

	h.AddRemediationStep(rec, req)

	if rec.Code != 400 {
		t.Fatalf("invalid body: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}
