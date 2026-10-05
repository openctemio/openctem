package ingest

// Coverage-scoped auto-resolve for non-repository findings.
//
// The report-level auto-resolve (CommitV2Report, Ingest step 3) only runs for
// a full scan of a repository's default branch, so a host/web finding (nuclei,
// trivy image, ...) is never closed by a later scan that no longer reports it.
// This closes that gap, conservatively: a finding is closed only when a scan
// command that ran the same tool (and the same scan profile) COMPLETED with
// full coverage of the finding's asset and did not report it. A failed,
// canceled, expired or partial run, a report that does not declare
// coverage_type "full" (an absent value is not full), a report with rejected items, an asset the
// run never reached, or a finding whose last sighting cannot be tied to a run
// of the same profile: none of them close anything.
//
// The decision is made once both halves are known — the command is completed
// AND every report filed under it is completed — so it is evaluated from both
// ends (command completion, report finalize); whichever comes second decides.
//
// Mode (INGEST_COVERAGE_AUTO_RESOLVE): off, dry_run (the default: log, metric
// and a "would resolve" audit entry, no state change) or enforce.

import (
	"context"
	"encoding/json"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// CoverageAutoResolveMode is how coverage-scoped auto-resolve acts.
type CoverageAutoResolveMode string

const (
	CoverageAutoResolveOff     CoverageAutoResolveMode = "off"
	CoverageAutoResolveDryRun  CoverageAutoResolveMode = "dry_run"
	CoverageAutoResolveEnforce CoverageAutoResolveMode = "enforce"
)

// ParseCoverageAutoResolveMode reads the configured mode. Anything that is not
// "off" or "enforce" is dry_run: an unknown value must never start closing
// findings.
func ParseCoverageAutoResolveMode(v string) CoverageAutoResolveMode {
	switch CoverageAutoResolveMode(strings.ToLower(strings.TrimSpace(v))) {
	case CoverageAutoResolveOff:
		return CoverageAutoResolveOff
	case CoverageAutoResolveEnforce:
		return CoverageAutoResolveEnforce
	default:
		return CoverageAutoResolveDryRun
	}
}

// isCoverageCommandType: the command types whose completed full-coverage run
// may close findings by absence: scans, and Tenable.sc scans launched through
// the connector (RFC-047). A connector_sync never does (a pull window proves
// nothing about absence).
func isCoverageCommandType(t string) bool {
	return t == string(command.CommandTypeScan) || t == string(command.CommandTypeConnectorScan)
}

// IsCoverageCommandType is isCoverageCommandType for the command handler.
func IsCoverageCommandType(t string) bool { return isCoverageCommandType(t) }

// coverageRepo is implemented by the postgres finding repository. Optional: a
// finding repository without it (tests, mocks) disables the feature.
type coverageRepo interface {
	CommandCoverage(ctx context.Context, tenantID, commandID shared.ID) (*ingestreport.CommandCoverage, error)
	CoverageStaleFindings(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) (stale []shared.ID, open int, err error)
	ResolveCoverageStale(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error)
}

// Coverage decision reasons (metric label values; keep the set small).
const (
	coverageEligible            = "eligible"
	coverageNotScanCommand      = "not_scan_command"
	coverageCommandNotCompleted = "command_not_completed"
	coverageNonZeroExit         = "nonzero_exit"
	coverageNoReports           = "no_reports"
	coverageReportsPending      = "reports_pending"
	coverageReportNotCompleted  = "report_failed"
	coverageRejectedItems       = "report_rejected_items"
	coveragePartial             = "partial_coverage"
	coverageUndeclared          = "coverage_undeclared"
	coverageRepositoryScan      = "repository_scan"
	coverageNotRepositoryScan   = "not_repository_scan"
	coverageNotDefaultBranch    = "not_default_branch"
	coverageToolMismatch        = "tool_ambiguous"
	coverageReservedTool        = "reserved_tool"
	coverageNoCoveredAssets     = "no_covered_assets"
)

// coverageDecision is the pure verdict on one command's run.
type coverageDecision struct {
	reason string
	query  ingestreport.CoverageQuery
}

func (d coverageDecision) eligible() bool { return d.reason == coverageEligible }

// decideCoverage says whether a command's run proves coverage of non-repository
// assets, and of what.
func decideCoverage(c *ingestreport.CommandCoverage) coverageDecision {
	return decideRunCoverage(c, false)
}

// decideRepoCoverage is decideCoverage for a repository run: every report must
// be an explicitly full scan of a default branch.
func decideRepoCoverage(c *ingestreport.CommandCoverage) coverageDecision {
	return decideRunCoverage(c, true)
}

// decideRunCoverage says whether a command's run proves coverage, and of what.
// The run must have completed with exit code 0 and every report must have
// completed with nothing rejected, quarantined or in error: a scanner that
// failed, crashed or dropped results proves nothing about what it did not
// report.
//
//nolint:cyclop,gocognit // a flat list of independent refusals, each with its reason
func decideRunCoverage(c *ingestreport.CommandCoverage, repo bool) coverageDecision {
	if c == nil || !isCoverageCommandType(c.CommandType) {
		return coverageDecision{reason: coverageNotScanCommand}
	}
	if c.CommandStatus != string(command.CommandStatusCompleted) {
		return coverageDecision{reason: coverageCommandNotCompleted}
	}
	var result struct {
		ExitCode *int `json:"exit_code"`
	}
	if len(c.Result) > 0 && json.Unmarshal(c.Result, &result) == nil && result.ExitCode != nil && *result.ExitCode != 0 {
		return coverageDecision{reason: coverageNonZeroExit}
	}
	if len(c.Reports) == 0 {
		return coverageDecision{reason: coverageNoReports}
	}

	q := ingestreport.CoverageQuery{ProfileID: c.ProfileID}
	seenAssets := map[shared.ID]struct{}{}
	templates, templatesSet := "", false
	for _, r := range c.Reports {
		switch r.State {
		case protov2.StateCompleted:
		case protov2.StateFailed, protov2.StateExpired:
			return coverageDecision{reason: coverageReportNotCompleted}
		default:
			return coverageDecision{reason: coverageReportsPending}
		}
		for _, o := range r.SegmentOutcomes {
			if o.RejectedFindings > 0 || o.QuarantinedFindings > 0 || o.RejectedAssets > 0 ||
				o.QuarantinedAssets > 0 || len(o.Errors) > 0 || o.ErrorsTruncated {
				return coverageDecision{reason: coverageRejectedItems}
			}
		}
		var header V2Header
		if len(r.Header) > 0 {
			_ = json.Unmarshal(r.Header, &header)
		}
		if repo {
			// A repository run closes default-branch findings only for a scan
			// of a default branch (the coverage check below applies to both).
			if header.Metadata.Branch == nil {
				return coverageDecision{reason: coverageNotRepositoryScan}
			}
			if !header.Metadata.Branch.IsDefaultBranch {
				return coverageDecision{reason: coverageNotDefaultBranch}
			}
		} else if header.Metadata.Branch != nil {
			// Repository scans have their own (default-branch) evaluation.
			return coverageDecision{reason: coverageRepositoryScan}
		}
		// Only an explicit "full" proves coverage. An absent coverage_type is
		// not full (CTIS spec 4.5), the same as the report-level path
		// (Input.ShouldAutoResolve): a sensor that does not say it covered
		// everything closes nothing.
		switch strings.ToLower(strings.TrimSpace(header.Metadata.CoverageType)) {
		case string(CoverageTypeFull):
		case "":
			return coverageDecision{reason: coverageUndeclared}
		default:
			return coverageDecision{reason: coveragePartial}
		}
		tool := strings.TrimSpace(r.ToolName)
		switch {
		case tool == "":
			return coverageDecision{reason: coverageToolMismatch}
		case q.ToolName == "":
			q.ToolName = tool
		case q.ToolName != tool:
			return coverageDecision{reason: coverageToolMismatch}
		}
		q.SeenScanIDs = append(q.SeenScanIDs, r.ReportID)
		// The template release of the run: one value across its reports,
		// else unknown.
		_, d := reportTemplateRelease(header.Tool)
		d = vulnerability.SanitizeTemplateDigest(d)
		switch {
		case !templatesSet:
			templates, templatesSet = d, true
		case templates != d:
			templates = ""
		}
		for _, a := range r.TouchedAssetIDs {
			if _, dup := seenAssets[a]; !dup {
				seenAssets[a] = struct{}{}
				q.AssetIDs = append(q.AssetIDs, a)
			}
		}
	}
	if _, reserved := reservedAutoResolveTools[strings.ToLower(q.ToolName)]; reserved {
		return coverageDecision{reason: coverageReservedTool}
	}
	if len(q.AssetIDs) == 0 {
		return coverageDecision{reason: coverageNoCoveredAssets}
	}
	q.TemplatesDigest = templates
	return coverageDecision{reason: coverageEligible, query: q}
}

// CoverageOutcome is what one evaluation did.
type CoverageOutcome struct {
	Mode         CoverageAutoResolveMode
	Reason       string
	WouldResolve []shared.ID
	Resolved     []shared.ID
	// TemplateDrift are the candidates whose last sighting ran other
	// template content than this run (research/18 O6): not proven fixed,
	// marked not_observed (NotObserved) in enforce mode.
	TemplateDrift []shared.ID
	NotObserved   []shared.ID
	Held          bool
}

// templateDriftRepo is implemented by the postgres finding repository.
type templateDriftRepo interface {
	TemplateDriftedFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID, runDigest string) ([]shared.ID, error)
	MarkCoverageNotObserved(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error)
}

// splitTemplateDrift separates, from the stale candidates, those whose last
// sighting recorded a template release other than the run's. A lookup
// error keeps every candidate open (fail closed): ok is false.
func (s *Service) splitTemplateDrift(ctx context.Context, tenantID shared.ID, stale []shared.ID, runDigest string) (resolvable, drifted []shared.ID, ok bool) {
	repo, has := s.findingRepo.(templateDriftRepo)
	if !has {
		return stale, nil, true
	}
	drifted, err := repo.TemplateDriftedFindings(ctx, tenantID, stale, runDigest)
	if err != nil {
		s.logger.Warn("coverage auto-resolve: template drift check failed; nothing closed", "error", err)
		return nil, nil, false
	}
	if len(drifted) == 0 {
		return stale, nil, true
	}
	skip := make(map[shared.ID]struct{}, len(drifted))
	for _, id := range drifted {
		skip[id] = struct{}{}
	}
	resolvable = make([]shared.ID, 0, len(stale)-len(drifted))
	for _, id := range stale {
		if _, d := skip[id]; !d {
			resolvable = append(resolvable, id)
		}
	}
	return resolvable, drifted, true
}

// SetCoverageAutoResolve sets the mode and the blinding guard (the same guard
// a v2 commit applies: a run that would close too many of the open findings at
// once is held for review).
func (s *Service) SetCoverageAutoResolve(mode CoverageAutoResolveMode, guard BlindingGuard) {
	s.coverageMode = mode
	s.coverageGuard = guard
}

func (s *Service) coverageAutoResolveMode() CoverageAutoResolveMode {
	if s.coverageMode == "" {
		return CoverageAutoResolveDryRun
	}
	return s.coverageMode
}

// EvaluateCommandCoverage decides, for one scan command, whether its run
// proves that open findings of its tool on the assets it covered are gone, and
// acts per the mode. Safe to call repeatedly and from both ends (command
// completion, report finalize): until both are done it does nothing, and an
// enforce run only ever closes still-open findings.
//
// A repository run (default-branch reports) is evaluated by
// evaluateRepoCoverage instead, whatever the coverage mode: repository
// findings have always been closed by a covered default-branch scan.
func (s *Service) EvaluateCommandCoverage(ctx context.Context, tenantID, commandID shared.ID) CoverageOutcome {
	mode := s.coverageAutoResolveMode()
	out := CoverageOutcome{Mode: mode}
	repo, ok := s.findingRepo.(coverageRepo)
	if !ok || tenantID.IsZero() || commandID.IsZero() {
		out.Reason = "disabled"
		return out
	}

	cov, err := repo.CommandCoverage(ctx, tenantID, commandID)
	if err != nil {
		s.logger.Warn("coverage auto-resolve: could not load the command's run", "command_id", commandID.String(), "error", err)
		out.Reason = "error"
		return out
	}
	d := decideCoverage(cov)
	if d.reason == coverageRepositoryScan {
		return s.evaluateRepoCoverage(ctx, tenantID, commandID, cov, s.coverageGuard)
	}
	if mode == CoverageAutoResolveOff {
		out.Reason = "disabled"
		return out
	}
	out.Reason = d.reason
	if d.eligible() && !s.sensorsDeclareTool(ctx, cov, d.query.ToolName) {
		out.Reason = coverageToolMismatch
	}
	metrics.CoverageAutoResolveEvaluations.WithLabelValues(string(mode), out.Reason).Inc()
	if out.Reason != coverageEligible {
		s.logger.Debug("coverage auto-resolve: not eligible", "command_id", commandID.String(), "reason", out.Reason)
		return out
	}

	stale, open, err := repo.CoverageStaleFindings(ctx, tenantID, d.query)
	if err != nil {
		s.logger.Warn("coverage auto-resolve: candidate query failed", "command_id", commandID.String(), "error", err)
		out.Reason = "error"
		return out
	}
	if len(stale) == 0 {
		return out
	}
	out.Held = s.coverageGuard.Holds(len(stale), open)
	resolvable, drifted, ok := s.splitTemplateDrift(ctx, tenantID, stale, d.query.TemplatesDigest)
	if !ok {
		out.Reason = "error"
		return out
	}
	out.WouldResolve, out.TemplateDrift = resolvable, drifted
	stale = resolvable

	logArgs := []any{
		"command_id", commandID.String(), "tool_name", sanitizeIngestLogField(d.query.ToolName),
		"profile_id", d.query.ProfileID, "covered_assets", len(d.query.AssetIDs),
		"would_resolve", len(stale), "template_drift", len(drifted), "open", open, "held", out.Held, "mode", string(mode),
	}
	switch {
	case out.Held:
		metrics.FindingsCoverageAutoResolve.WithLabelValues(string(mode), "held").Add(float64(len(stale)))
		s.logger.Warn("coverage auto-resolve held for review (blinding guard)", logArgs...)
	case mode == CoverageAutoResolveDryRun:
		metrics.FindingsCoverageAutoResolve.WithLabelValues(string(mode), "would_resolve").Add(float64(len(stale)))
		s.logger.Info("coverage auto-resolve (dry run): would resolve findings", logArgs...)
	default:
		if len(drifted) > 0 {
			// Template drift: the run's absence proves nothing; the finding
			// is stale, not fixed, until a new sighting re-baselines it.
			if dr, ok := s.findingRepo.(templateDriftRepo); ok {
				marked, err := dr.MarkCoverageNotObserved(ctx, tenantID, drifted)
				if err != nil {
					s.logger.Warn("coverage auto-resolve: marking template-drifted findings not_observed failed", append(logArgs, "error", err)...)
				} else {
					out.NotObserved = marked
					metrics.FindingsCoverageAutoResolve.WithLabelValues(string(mode), "not_observed").Add(float64(len(marked)))
				}
			}
		}
		resolved, err := repo.ResolveCoverageStale(ctx, tenantID, stale)
		if err != nil {
			s.logger.Warn("coverage auto-resolve failed", append(logArgs, "error", err)...)
			return out
		}
		out.Resolved = resolved
		metrics.FindingsCoverageAutoResolve.WithLabelValues(string(mode), "resolved").Add(float64(len(resolved)))
		s.logger.Info("coverage auto-resolve: resolved findings", append(logArgs, "resolved", len(resolved))...)
		if s.activityService != nil && len(resolved) > 0 {
			if err := s.activityService.RecordBatchAutoResolved(ctx, tenantID, resolved, d.query.ToolName, commandID.String()); err != nil {
				s.logger.Warn("failed to record coverage auto-resolve activities", "error", err)
			}
		}
	}
	s.auditCoverageAutoResolve(ctx, tenantID, commandID, d.query, out, open)
	return out
}

// repoCoverageRepo is implemented by the postgres finding repository.
type repoCoverageRepo interface {
	RepoCoverageStaleFindings(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) (stale []shared.ID, open int, err error)
	ResolveRepoCoverageStale(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error)
}

// evaluateRepoCoverage is the only way a scan closes default-branch
// (repository) findings (research 18 F3). It needs:
//   - a run bound to a command (a report without one, a CI or tenant upload,
//     never closes anything: owner decision O11);
//   - the command completed with exit code 0 and every report completed with
//     nothing rejected, quarantined or in error;
//   - every report an explicitly full scan of a default branch, of one tool
//     the reporting sensors declare;
//   - candidates on assets the command covers, last seen by the same tool
//     under the same scan profile (the ruleset did not change);
//   - the blinding guard.
//
// It always enforces (the coverage mode governs non-repository findings
// only). Safe to run repeatedly: the UPDATE re-checks every condition.
func (s *Service) evaluateRepoCoverage(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage, guard BlindingGuard) CoverageOutcome {
	out := CoverageOutcome{Mode: CoverageAutoResolveEnforce}
	repo, ok := s.findingRepo.(repoCoverageRepo)
	if !ok {
		out.Reason = "disabled"
		return out
	}
	d := decideRepoCoverage(cov)
	out.Reason = d.reason
	if d.eligible() && !s.sensorsDeclareTool(ctx, cov, d.query.ToolName) {
		out.Reason = coverageToolMismatch
	}
	if out.Reason == coverageEligible {
		d.query.AssetIDs = s.coveredByCommand(ctx, tenantID, &commandID, d.query.AssetIDs)
		if len(d.query.AssetIDs) == 0 {
			out.Reason = coverageNoCoveredAssets
		}
	}
	metrics.CoverageAutoResolveEvaluations.WithLabelValues("repository", out.Reason).Inc()
	if out.Reason != coverageEligible {
		s.logger.Debug("repository auto-resolve: not eligible", "command_id", commandID.String(), "reason", out.Reason)
		return out
	}

	stale, open, err := repo.RepoCoverageStaleFindings(ctx, tenantID, d.query)
	if err != nil {
		s.logger.Warn("repository auto-resolve: candidate query failed", "command_id", commandID.String(), "error", err)
		out.Reason = "error"
		return out
	}
	if len(stale) == 0 {
		return out
	}
	out.WouldResolve = stale
	out.Held = guard.Holds(len(stale), open)
	logArgs := []any{
		"command_id", commandID.String(), "tool_name", sanitizeIngestLogField(d.query.ToolName),
		"profile_id", d.query.ProfileID, "covered_assets", len(d.query.AssetIDs),
		"would_resolve", len(stale), "open", open, "held", out.Held,
	}
	if out.Held {
		metrics.FindingsCoverageAutoResolve.WithLabelValues("repository", "held").Add(float64(len(stale)))
		s.logger.Warn("repository auto-resolve held for review (blinding guard)", logArgs...)
	} else {
		resolved, err := repo.ResolveRepoCoverageStale(ctx, tenantID, stale)
		if err != nil {
			s.logger.Warn("repository auto-resolve failed", append(logArgs, "error", err)...)
			return out
		}
		out.Resolved = resolved
		metrics.FindingsCoverageAutoResolve.WithLabelValues("repository", "resolved").Add(float64(len(resolved)))
		metrics.FindingsAutoResolved.
			WithLabelValues().Add(float64(len(resolved)))
		s.logger.Info("repository auto-resolve: resolved findings", append(logArgs, "resolved", len(resolved))...)
		if s.activityService != nil && len(resolved) > 0 {
			if err := s.activityService.RecordBatchAutoResolved(ctx, tenantID, resolved, d.query.ToolName, commandID.String()); err != nil {
				s.logger.Warn("failed to record repository auto-resolve activities", "error", err)
			}
		}
	}
	s.auditCoverageAutoResolve(ctx, tenantID, commandID, d.query, out, open)
	return out
}

// sensorsDeclareTool applies the v2 tool gate to every sensor that filed a
// report of the run: a sensor that never declared the tool cannot close its
// findings.
func (s *Service) sensorsDeclareTool(ctx context.Context, cov *ingestreport.CommandCoverage, toolName string) bool {
	if s.sensorRepo == nil {
		return false
	}
	checked := map[shared.ID]bool{}
	for _, r := range cov.Reports {
		if _, done := checked[r.SensorID]; done {
			continue
		}
		stored, err := s.sensorRepo.GetByID(ctx, r.SensorID)
		if err != nil || stored == nil || !SensorDeclaresTool(stored.EffectiveTools(), toolName) {
			return false
		}
		checked[r.SensorID] = true
	}
	return true
}

// maxAuditedFindingIDs caps the finding ids listed in one audit entry.
const maxAuditedFindingIDs = 200

func (s *Service) auditCoverageAutoResolve(ctx context.Context, tenantID, commandID shared.ID, q ingestreport.CoverageQuery, out CoverageOutcome, open int) {
	if s.auditSvc == nil && s.auditRepo == nil {
		return
	}
	action := audit.ActionIngestCoverageAutoResolved
	ids := out.Resolved
	if out.Mode != CoverageAutoResolveEnforce || out.Held {
		action = audit.ActionIngestCoverageAutoResolveDryRun
		ids = out.WouldResolve
	}
	listed := make([]string, 0, min(len(ids), maxAuditedFindingIDs))
	for i, id := range ids {
		if i == maxAuditedFindingIDs {
			break
		}
		listed = append(listed, id.String())
	}
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeIngest, commandID.String())
	event.ResourceName = q.ToolName
	event.Message = "coverage-scoped auto-resolve"
	event.Metadata = map[string]any{
		"mode": string(out.Mode), "held": out.Held, "tool_name": q.ToolName, "profile_id": q.ProfileID,
		"covered_assets": len(q.AssetIDs), "open": open, "count": len(ids),
		"template_drift": len(out.TemplateDrift), "not_observed": len(out.NotObserved),
		"finding_ids": listed, "finding_ids_truncated": len(ids) > maxAuditedFindingIDs,
	}
	if err := s.writeIngestAuditLog(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
		s.logger.Warn("failed to write coverage auto-resolve audit log", "command_id", commandID.String(), "error", err)
	}
}
