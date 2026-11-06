package ingest

// Info-severity matches of template scanners (docs/architecture/exposure-taxonomy.md,
// "Template scanner info matches"): a nuclei info match says what a host
// shows (technology, a login panel, TLS and header posture), not what is
// wrong with it. Unless the organization files them as findings
// (EASM settings info_matches_as_findings), they leave the report's
// findings before finding ingest, become info exposures of their assets,
// and the step run that reported them counts them (output
// info_observations), so a run that found no vulnerability still shows
// what it saw.
//
// Only matches the finding pipeline would have accepted are moved: the asset
// must resolve in this ingest's asset map and must not be excluded, outside
// the bound job or outside the uploader's scope (those stay in the findings
// and are refused there with the usual receipt item).

import (
	"context"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// TemplateMatchProjector files template matches as exposures
// (*exposurebridge.Bridge).
type TemplateMatchProjector interface {
	ProjectTemplateMatches(ctx context.Context, tenantID shared.ID, matches []exposure.TemplateMatch) (int, error)
}

// StepInfoRecorder adds to the info_observations count of a step run
// (*postgres.ScanHopRepository). Tenant-scoped: a step run of another tenant
// is not changed.
type StepInfoRecorder interface {
	AddStepInfoObservations(ctx context.Context, tenantID, stepRunID shared.ID, n int) error
}

// StepDispositionRecorder adds the findings a step run's reports left
// unstored (*postgres.ScanHopRepository): held for review and refused.
type StepDispositionRecorder interface {
	AddStepFindingDispositions(ctx context.Context, tenantID, stepRunID shared.ID, held, refused int) error
}

// SetStepDispositionRecorder wires the per-run held and refused counts. Nil-safe.
func (s *Service) SetStepDispositionRecorder(r StepDispositionRecorder) { s.stepDispositions = r }

// recordStepDispositions adds what a command-bound segment held or refused
// to its step run, so the step's findings count (what the sensor reported)
// reconciles with the findings list.
func (s *Service) recordStepDispositions(ctx context.Context, tenantID shared.ID, binding Binding, held, refused int) {
	if s.stepDispositions == nil || binding.Kind != BindingCommand || binding.StepRunID == nil {
		return
	}
	if err := s.stepDispositions.AddStepFindingDispositions(ctx, tenantID, *binding.StepRunID, held, refused); err != nil {
		s.logger.Warn("ingest: step run finding dispositions not counted",
			"tenant_id", tenantID.String(), "scan_run_step_id", binding.StepRunID.String(), "error", logger.SanitizeError(err))
	}
}

// SetTemplateMatchProjector wires the info match projection. Nil-safe:
// unwired, info matches stay findings.
func (s *Service) SetTemplateMatchProjector(p TemplateMatchProjector) { s.templateMatches = p }

// SetStepInfoRecorder wires the per-run info observation count. Nil-safe.
func (s *Service) SetStepInfoRecorder(r StepInfoRecorder) { s.stepInfo = r }

// templateScanner reports whether tool runs vulnerability templates or web
// application checks (the tools whose info matches are context).
func templateScanner(tool string) bool {
	for _, st := range stage.ForTool(tool) {
		if st.Key == stage.VulnTemplates || st.Key == stage.DASTWeb {
			return true
		}
	}
	return false
}

// splitInfoMatches splits the report's findings into those that stay
// findings and the info matches of a template scanner that become
// exposures. Pure: the report is not changed.
func splitInfoMatches(report *ctis.Report, assetMap map[string]shared.ID, output *Output, stepRunID *shared.ID) ([]ctis.Finding, []exposure.TemplateMatch) {
	if report == nil || report.Tool == nil || !templateScanner(report.Tool.Name) {
		return report.Findings, nil
	}
	var matches []exposure.TemplateMatch
	keep := make([]ctis.Finding, 0, len(report.Findings))
	for i := range report.Findings {
		f := &report.Findings[i]
		assetID, ok := assetMap[f.AssetRef]
		if f.Severity != ctis.SeverityInfo || !ok || assetID.IsZero() ||
			output.ExcludedAssetRefs[f.AssetRef] || output.OverCapAssetRefs[f.AssetRef] || output.OutOfScopeAssetRefs[f.AssetRef] {
			keep = append(keep, *f)
			continue
		}
		m := exposure.TemplateMatch{AssetID: assetID, Tool: report.Tool.Name, RuleID: f.RuleID, Title: f.Title,
			Matcher: f.SourceExtra["matcher_name"], Tags: f.Tags, StepRunID: stepRunID}
		if f.Web != nil {
			m.URL = f.Web.URL
		}
		matches = append(matches, m)
	}
	return keep, matches
}

// routeInfoMatches moves the report's template info matches to exposures
// (see the file comment) and counts them on output and on the step run.
// When the organization files them as findings, or nothing is wired, the
// report is left as it is.
func (s *Service) routeInfoMatches(ctx context.Context, tenantID shared.ID, report *ctis.Report, assetMap map[string]shared.ID, output *Output, binding Binding) {
	if s.templateMatches == nil || report == nil || len(report.Findings) == 0 {
		return
	}
	keep, matches := splitInfoMatches(report, assetMap, output, binding.StepRunID)
	if len(matches) == 0 || s.infoMatchesAsFindings(ctx, tenantID) {
		return
	}
	n, err := s.templateMatches.ProjectTemplateMatches(ctx, tenantID, matches)
	if err != nil {
		// Not filed: they stay findings rather than vanish.
		s.logger.Warn("ingest: info matches not filed as exposures; kept as findings",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	report.Findings = keep
	output.InfoObservations += n
	if s.stepInfo != nil && binding.Kind == BindingCommand && binding.StepRunID != nil && n > 0 {
		if err := s.stepInfo.AddStepInfoObservations(ctx, tenantID, *binding.StepRunID, n); err != nil {
			s.logger.Warn("ingest: step run info observations not counted",
				"tenant_id", tenantID.String(), "scan_run_step_id", binding.StepRunID.String(), "error", logger.SanitizeError(err))
		}
	}
}

// infoMatchesAsFindings reads the organization's choice (false when the
// tenant cannot be read: the default).
func (s *Service) infoMatchesAsFindings(ctx context.Context, tenantID shared.ID) bool {
	if s.tenantRepo == nil {
		return false
	}
	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		return false
	}
	return t.TypedSettings().EASM.InfoMatchesAsFindings
}
