package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// defectDojoTool is the tool_name findings imported via the DefectDojo connector
// carry (RFC-013). Used to compute the dependency ratio.
const defectDojoTool = "defectdojo"

// SourceBreakdownReader is the narrow read surface the analytics service needs.
// Satisfied by *postgres.FindingRepository — kept narrow so it isn't forced
// onto every FindingRepository implementation/mock.
type SourceBreakdownReader interface {
	SourceBreakdown(ctx context.Context, tenantID shared.ID) ([]vulnerability.SourceStat, error)
}

// SourceAnalytics is the per-source finding breakdown plus the headline metrics:
// Tool Insights (which scanner contributes what) and the DefectDojo-dependency
// ratio — RFC-013's measure-to-phase-out guardrail.
type SourceAnalytics struct {
	Sources         []vulnerability.SourceStat `json:"sources"`
	Total           int                        `json:"total"`
	OpenTotal       int                        `json:"open_total"`
	DefectDojoTotal int                        `json:"defectdojo_total"`
	NativeTotal     int                        `json:"native_total"`
	// DefectDojoDependencyRatio is defectdojo findings / total, 0..1. As native
	// parsers cover more tools this trends to 0 — the signal that DefectDojo can
	// be phased out (RFC-013 Phase 3).
	DefectDojoDependencyRatio float64 `json:"defectdojo_dependency_ratio"`
}

// SourceAnalyticsService computes the source breakdown + dependency metrics.
type SourceAnalyticsService struct {
	reader SourceBreakdownReader
	logger *logger.Logger
}

// NewSourceAnalyticsService wires the analytics service.
func NewSourceAnalyticsService(reader SourceBreakdownReader, log *logger.Logger) *SourceAnalyticsService {
	return &SourceAnalyticsService{reader: reader, logger: log}
}

// GetSourceAnalytics returns the tenant's finding source breakdown + metrics.
func (s *SourceAnalyticsService) GetSourceAnalytics(ctx context.Context, tenantID string) (*SourceAnalytics, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	stats, err := s.reader.SourceBreakdown(ctx, tid)
	if err != nil {
		return nil, err
	}

	out := &SourceAnalytics{Sources: stats}
	for _, st := range stats {
		out.Total += st.Total
		out.OpenTotal += st.Open
		if st.ToolName == defectDojoTool {
			out.DefectDojoTotal += st.Total
		} else {
			out.NativeTotal += st.Total
		}
	}
	if out.Total > 0 {
		out.DefectDojoDependencyRatio = float64(out.DefectDojoTotal) / float64(out.Total)
	}
	return out, nil
}
