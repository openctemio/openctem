package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app/scancoverage"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeCoverageReader struct {
	gotTenant shared.ID
	gotWindow int
	stats     *scancoverage.CoverageStats
	err       error
}

func (f *fakeCoverageReader) CoverageStats(_ context.Context, tenantID shared.ID, window int) (*scancoverage.CoverageStats, error) {
	f.gotTenant = tenantID
	f.gotWindow = window
	if f.err != nil {
		return nil, f.err
	}
	return f.stats, nil
}

func newCoverageHandler(reader scancoverage.CoverageStatsReader) *ScanHandler {
	return NewScanHandler(nil, nil, reader, nil, logger.NewNop())
}

func reqWithTenant(target string, tenant shared.ID) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	return req.WithContext(ctx)
}

func TestCoverageStatus_Success_DefaultWindow(t *testing.T) {
	tenant := shared.NewID()
	reader := &fakeCoverageReader{stats: &scancoverage.CoverageStats{
		WindowDays: scancoverage.DefaultCoverageWindowDays, TotalScannable: 10,
		CoveredInWindow: 4, CoveragePercent: 40,
	}}
	rec := httptest.NewRecorder()
	newCoverageHandler(reader).CoverageStatus(rec, reqWithTenant("/api/v1/scans/coverage", tenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if reader.gotTenant != tenant {
		t.Fatal("tenant not forwarded to reader")
	}
	if reader.gotWindow != scancoverage.DefaultCoverageWindowDays {
		t.Fatalf("default window should be %d, got %d", scancoverage.DefaultCoverageWindowDays, reader.gotWindow)
	}
	var body scancoverage.CoverageStats
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TotalScannable != 10 || body.CoveragePercent != 40 {
		t.Fatalf("body wrong: %+v", body)
	}
}

func TestCoverageStatus_CustomWindow(t *testing.T) {
	reader := &fakeCoverageReader{stats: &scancoverage.CoverageStats{}}
	rec := httptest.NewRecorder()
	newCoverageHandler(reader).CoverageStatus(rec, reqWithTenant("/api/v1/scans/coverage?window_days=7", shared.NewID()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if reader.gotWindow != 7 {
		t.Fatalf("window should be 7, got %d", reader.gotWindow)
	}
}

func TestCoverageStatus_InvalidWindow(t *testing.T) {
	for _, w := range []string{"abc", "0", "-3", "99999"} {
		reader := &fakeCoverageReader{stats: &scancoverage.CoverageStats{}}
		rec := httptest.NewRecorder()
		newCoverageHandler(reader).CoverageStatus(rec, reqWithTenant("/api/v1/scans/coverage?window_days="+w, shared.NewID()))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("window %q should be 400, got %d", w, rec.Code)
		}
		if reader.gotWindow != 0 {
			t.Fatalf("reader must not be called for invalid window %q", w)
		}
	}
}

func TestCoverageStatus_MissingTenant(t *testing.T) {
	rec := httptest.NewRecorder()
	// no tenant in context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/coverage", nil)
	newCoverageHandler(&fakeCoverageReader{stats: &scancoverage.CoverageStats{}}).CoverageStatus(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant should be 401, got %d", rec.Code)
	}
}

func TestCoverageStatus_NilReader(t *testing.T) {
	rec := httptest.NewRecorder()
	newCoverageHandler(nil).CoverageStatus(rec, reqWithTenant("/api/v1/scans/coverage", shared.NewID()))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil reader should be 500, got %d", rec.Code)
	}
}
