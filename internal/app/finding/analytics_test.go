package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakeSourceReader struct {
	stats []vulnerability.SourceStat
	err   error
}

func (r fakeSourceReader) SourceBreakdown(_ context.Context, _ shared.ID) ([]vulnerability.SourceStat, error) {
	return r.stats, r.err
}

func TestGetSourceAnalytics_ComputesDependencyRatio(t *testing.T) {
	reader := fakeSourceReader{stats: []vulnerability.SourceStat{
		{Source: "integration", ToolName: "defectdojo", Total: 60, Open: 40},
		{Source: "sast", ToolName: "semgrep", Total: 30, Open: 20},
		{Source: "sca", ToolName: "trivy", Total: 10, Open: 5},
	}}
	svc := NewSourceAnalyticsService(reader, logger.NewNop())

	out, err := svc.GetSourceAnalytics(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("GetSourceAnalytics: %v", err)
	}
	if out.Total != 100 || out.OpenTotal != 65 {
		t.Errorf("Total=%d Open=%d, want 100/65", out.Total, out.OpenTotal)
	}
	if out.DefectDojoTotal != 60 || out.NativeTotal != 40 {
		t.Errorf("DD=%d native=%d, want 60/40", out.DefectDojoTotal, out.NativeTotal)
	}
	if out.DefectDojoDependencyRatio != 0.6 {
		t.Errorf("dependency ratio = %v, want 0.6", out.DefectDojoDependencyRatio)
	}
}

func TestGetSourceAnalytics_EmptyNoDivideByZero(t *testing.T) {
	svc := NewSourceAnalyticsService(fakeSourceReader{}, logger.NewNop())
	out, err := svc.GetSourceAnalytics(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("GetSourceAnalytics: %v", err)
	}
	if out.Total != 0 || out.DefectDojoDependencyRatio != 0 {
		t.Errorf("empty tenant should yield zero totals/ratio, got %+v", out)
	}
}

func TestGetSourceAnalytics_NoDefectDojo_RatioZero(t *testing.T) {
	reader := fakeSourceReader{stats: []vulnerability.SourceStat{
		{ToolName: "semgrep", Total: 20, Open: 10},
	}}
	out, err := NewSourceAnalyticsService(reader, logger.NewNop()).
		GetSourceAnalytics(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("GetSourceAnalytics: %v", err)
	}
	if out.DefectDojoDependencyRatio != 0 || out.NativeTotal != 20 {
		t.Errorf("no-DD tenant: ratio=%v native=%d, want 0/20", out.DefectDojoDependencyRatio, out.NativeTotal)
	}
}

func TestGetSourceAnalytics_InvalidTenant(t *testing.T) {
	svc := NewSourceAnalyticsService(fakeSourceReader{}, logger.NewNop())
	if _, err := svc.GetSourceAnalytics(context.Background(), "not-a-uuid"); err == nil {
		t.Fatal("expected validation error for a bad tenant id")
	}
}
