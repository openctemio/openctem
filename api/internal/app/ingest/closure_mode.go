package ingest

import (
	"context"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The organization's closing mode in front of coverage auto-resolve
// (docs/architecture/finding-verification-plan.md, "Closing mode"). The env
// INGEST_COVERAGE_AUTO_RESOLVE is the platform ceiling: only in enforce (or
// its alias tenant) does the organization's mode decide, finding by finding,
// whether a covered scan closes, proposes or keeps.

// ClosureSettingsReader reads an organization's closing policy. The tenant
// service implements it.
type ClosureSettingsReader interface {
	GetClosureSettings(ctx context.Context, tenantID string) (*tenant.ClosureSettings, error)
}

// SetClosureSettings wires the organization closing policy. Without it every
// organization is in review: a covered scan proposes and closes nothing.
func (s *Service) SetClosureSettings(r ClosureSettingsReader) { s.closureSettings = r }

// findingRiskTierRepo is implemented by the postgres finding repository.
type findingRiskTierRepo interface {
	FindingRiskTiers(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]vulnerability.RiskTier, error)
}

// tenantClosureSettings loads the organization's policy once per evaluation.
// No reader or a read failure is review: never closes, still records.
func (s *Service) tenantClosureSettings(ctx context.Context, tenantID shared.ID) tenant.ClosureSettings {
	if s.closureSettings == nil {
		return tenant.ClosureSettings{}
	}
	cs, err := s.closureSettings.GetClosureSettings(ctx, tenantID.String())
	if err != nil || cs == nil {
		s.logger.Warn("coverage auto-resolve: could not read the closing mode, using review", "tenant_id", tenantID.String(), "error", err)
		return tenant.ClosureSettings{}
	}
	return *cs
}

// splitByClosureDecision sorts the findings a covered scan no longer sees
// into close, propose and keep (method covered_scan). The tiers are read in
// one tenant-scoped query; when they cannot be read every finding is
// treated as critical (proposed unless the owner opted in), and an id the
// query does not return (another tenant's, or deleted) is kept.
func (s *Service) splitByClosureDecision(ctx context.Context, tenantID shared.ID, ids []shared.ID) (closeIDs, propose, keep []shared.ID) {
	cs := s.tenantClosureSettings(ctx, tenantID)
	mode := cs.EffectiveMode()
	if mode == tenant.ClosingModeOff {
		return nil, nil, ids
	}
	var tiers map[shared.ID]vulnerability.RiskTier
	if mode == tenant.ClosingModeAuto {
		var err error
		if tr, ok := s.findingRepo.(findingRiskTierRepo); ok {
			tiers, err = tr.FindingRiskTiers(ctx, tenantID, ids)
		}
		if err != nil || tiers == nil {
			s.logger.Warn("coverage auto-resolve: could not read finding tiers, treating them as critical", "tenant_id", tenantID.String(), "error", err)
			tiers = make(map[shared.ID]vulnerability.RiskTier, len(ids))
			for _, id := range ids {
				tiers[id] = vulnerability.RiskTierCritical
			}
		}
	}
	for _, id := range ids {
		tier := vulnerability.RiskTierCritical
		if tiers != nil {
			t, ok := tiers[id]
			if !ok {
				keep = append(keep, id)
				continue
			}
			tier = t
		}
		// No per-asset flaky mark exists yet: flaky is false.
		switch vulnerability.DecideClosure(mode, tier, vulnerability.ClosureMethodCoveredScan, false, cs.CriticalAutoClose) {
		case vulnerability.ClosureDecisionClose:
			closeIDs = append(closeIDs, id)
		case vulnerability.ClosureDecisionPropose:
			propose = append(propose, id)
		default:
			keep = append(keep, id)
		}
	}
	return closeIDs, propose, keep
}

// proposeClosures records a Ready to close proposal (method covered_scan)
// for each finding, with the evidence of the look: the command, its tool,
// profile and template release, the sensors that reported, and whether the
// blinding guard held the run. It returns ids (the decision stands even if
// recording fails, which is logged: nothing closes either way).
func (s *Service) proposeClosures(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage,
	q ingestreport.CoverageQuery, ids []shared.ID, held bool) []shared.ID {
	if len(ids) == 0 {
		return ids
	}
	repo, ok := s.findingRepo.(vulnerability.ClosureProposalRepository)
	if !ok {
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
		recs[i] = vulnerability.ClosureProposalRecord{FindingID: id, Method: vulnerability.ClosureMethodCoveredScan, CommandID: commandID, Evidence: evidence, EvidenceAt: observedAt}
	}
	if _, err := repo.RecordClosureProposals(ctx, tenantID, recs); err != nil {
		s.logger.Warn("coverage auto-resolve: recording closure proposals failed", "tenant_id", tenantID.String(), "command_id", commandID.String(), "error", err)
	}
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
