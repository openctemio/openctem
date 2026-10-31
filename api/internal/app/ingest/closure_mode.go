package ingest

import (
	"context"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/internal/app/closuremode"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The organization's closing mode in front of the automatic closes of this
// package: coverage auto-resolve (method covered_scan) and the default-branch
// close (method ci_default_branch)
// (docs/architecture/finding-verification-plan.md, "Closing mode"). The env
// INGEST_COVERAGE_AUTO_RESOLVE is the platform ceiling for the first: only in
// enforce (or its alias tenant) does the organization's mode decide, finding
// by finding, whether a covered scan closes, proposes or keeps.

// ClosureSettingsReader reads an organization's closing policy. The tenant
// service implements it.
type ClosureSettingsReader = closuremode.SettingsReader

// SetClosureSettings wires the organization closing policy. Without it every
// organization is in review: a covered scan proposes and closes nothing.
func (s *Service) SetClosureSettings(r ClosureSettingsReader) { s.closureSettings = r }

// closureDecider is the shared closing-mode rule over this service's
// settings reader and finding repository.
func (s *Service) closureDecider() closuremode.Decider {
	return closuremode.Decider{Settings: s.closureSettings, Repo: s.findingRepo, Log: s.logger}
}

// splitByClosureDecision sorts the findings a scan no longer sees into
// close, propose and keep for the method (closuremode.Decider.Split).
func (s *Service) splitByClosureDecision(ctx context.Context, tenantID shared.ID, ids []shared.ID, method vulnerability.ClosureMethod) (closeIDs, propose, keep []shared.ID) {
	return s.closureDecider().Split(ctx, tenantID, ids, method)
}

// proposeClosures records a Ready to close proposal (method covered_scan)
// for each finding, with the evidence of the look: the command, its tool,
// profile and template release, the sensors that reported, and whether the
// blinding guard held the run. It returns ids (the decision stands even if
// recording fails, which is logged: nothing closes either way).
func (s *Service) proposeClosures(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage,
	q ingestreport.CoverageQuery, ids []shared.ID, held bool, method vulnerability.ClosureMethod) []shared.ID {
	if len(ids) == 0 {
		return ids
	}
	if _, ok := s.findingRepo.(vulnerability.ClosureProposalRepository); !ok {
		return ids
	}
	// The look happened when the command completed; a sighting ingested
	// after that (even before this write) must invalidate the proposal.
	observedAt := time.Now().UTC()
	if cov != nil && !cov.CompletedAt.IsZero() && cov.CompletedAt.Before(observedAt) {
		observedAt = cov.CompletedAt.UTC()
	}
	evidence := map[string]any{
		"command_id": commandID.String(), "tool": q.ToolName, "profile_id": q.ProfileID,
		"templates_digest": q.TemplatesDigest, "held": held, "covered_assets": len(q.AssetIDs),
		"observed_at": observedAt.Format(time.RFC3339),
	}
	sensors := make([]string, 0, 2)
	for _, r := range reportsOf(cov) {
		if r.SensorID.IsZero() || slices.Contains(sensors, r.SensorID.String()) || len(sensors) == 4 {
			continue
		}
		sensors = append(sensors, r.SensorID.String())
	}
	evidence["sensor_ids"] = sensors
	recs := make([]vulnerability.ClosureProposalRecord, len(ids))
	for i, id := range ids {
		recs[i] = vulnerability.ClosureProposalRecord{FindingID: id, Method: method, CommandID: commandID, Evidence: evidence, EvidenceAt: observedAt}
	}
	s.closureDecider().Record(ctx, tenantID, recs)
	return ids
}

// cancelStaleProposals cancels the tenant's proposals whose finding was seen
// again or left the open statuses since. Best effort: a confirm re-checks
// eligibility anyway.
func (s *Service) cancelStaleProposals(ctx context.Context, tenantID shared.ID) {
	repo, ok := s.findingRepo.(vulnerability.ClosureProposalRepository)
	if !ok {
		return
	}
	if _, err := repo.CancelStaleClosureProposals(ctx, tenantID); err != nil {
		s.logger.Warn("coverage auto-resolve: canceling stale closure proposals failed", "tenant_id", tenantID.String(), "error", err)
	}
}

func reportsOf(cov *ingestreport.CommandCoverage) []ingestreport.CoverageReport {
	if cov == nil {
		return nil
	}
	return cov.Reports
}
