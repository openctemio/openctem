package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeValidationCoverageReader struct {
	byPriority validation.ValidationCoverage
	priErr     error
	gotTenant  string
}

func (f *fakeValidationCoverageReader) CoverageBySeverity(context.Context, shared.ID) ([]validation.SeverityCoverage, error) {
	return nil, nil
}

func (f *fakeValidationCoverageReader) DowngradeStats(context.Context, shared.ID) (int, int, error) {
	return 0, 0, nil
}

func (f *fakeValidationCoverageReader) CoverageByPriority(_ context.Context, tenantID string) (validation.ValidationCoverage, error) {
	f.gotTenant = tenantID
	return f.byPriority, f.priErr
}

func callCoverage(t *testing.T, reader CoverageReader) map[string]any {
	t.Helper()
	h := NewValidationHandler(nil, logger.NewNop())
	h.SetCoverageReader(reader)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validation/coverage", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "019d9095-a3fb-75dd-bc23-a244713dcc51"))
	rec := httptest.NewRecorder()
	h.Coverage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCoverage_ReportsPriorityClassCoverageForTheCallersTenant(t *testing.T) {
	reader := &fakeValidationCoverageReader{byPriority: validation.ValidationCoverage{
		P0Total: 4, P0WithEvidence: 3, P1Total: 6, P1WithEvidence: 2, P2Total: 10, P2WithEvidence: 1,
	}}
	out := callCoverage(t, reader)

	if reader.gotTenant != "019d9095-a3fb-75dd-bc23-a244713dcc51" {
		t.Fatalf("queried tenant %q, want the caller's", reader.gotTenant)
	}
	if out["p0_p1_total"].(float64) != 10 || out["p0_p1_validated"].(float64) != 5 {
		t.Fatalf("p0_p1 = %v/%v, want 5/10", out["p0_p1_validated"], out["p0_p1_total"])
	}
	rows := out["by_priority"].([]any)
	if len(rows) != 4 {
		t.Fatalf("by_priority has %d rows, want 4", len(rows))
	}
	p0 := rows[0].(map[string]any)
	if p0["priority"] != "P0" || p0["total"].(float64) != 4 || p0["validated"].(float64) != 3 {
		t.Fatalf("P0 row = %v", p0)
	}
}

func TestCoverage_PriorityFailureDegradesToEmpty(t *testing.T) {
	out := callCoverage(t, &fakeValidationCoverageReader{priErr: errors.New("boom")})
	if rows := out["by_priority"].([]any); len(rows) != 0 {
		t.Fatalf("by_priority = %v, want empty", rows)
	}
	if out["p0_p1_total"].(float64) != 0 {
		t.Fatalf("p0_p1_total = %v, want 0", out["p0_p1_total"])
	}
	if _, ok := out["by_severity"]; !ok {
		t.Fatal("by_severity missing: the severity KPI must still be served")
	}
}
