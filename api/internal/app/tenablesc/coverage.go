package tenablesc

// License-aware rolling coverage on the connector (RFC-047 §9; license
// rotation: research/143 §4). The planner picks the next batch of assets from
// the coverage ledger; each batch is one connector_scan launched through the
// sensor, which checks Tenable.sc's free license capacity before launching
// (the license guard) and reports how each target ended. The next batch waits
// until the previous one finished and its reports were ingested; its outcomes
// settle the ledger per target.
//
// Rotation (an administrator's acknowledged choice per connector):
//   - off: no data is removed; assets the license already counts are
//     rescanned, new ones only while the license has room (the rest is a
//     visible license gap);
//   - aging: the rotation repository's lifetimes free the license at
//     Tenable.sc's nightly cleanup; the next batch is tried after the wait
//     and the license guard verifies the capacity;
//   - recycle: the next batch asks the sensor to delete and recreate the
//     rotation repository first, only after the previous batch's results
//     were ingested; a batch that failed after it launched stalls rotation
//     until an administrator resumes it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/ctis/outcome"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Coverage waits.
const (
	// capacityRetry is how long a batch the license guard refused waits.
	capacityRetry = time.Hour
	// batchFailureRetry is how long the next batch waits after a failed one.
	batchFailureRetry = 30 * time.Minute
	// licenseCapacityCode starts the sensor's license-guard refusal.
	licenseCapacityCode = "LICENCE_CAPACITY" //nolint:misspell // the connector's published wire code
	// refusedBeforeLaunch starts a sensor admission refusal (nothing was
	// created in Tenable.sc).
	refusedBeforeLaunch = "tenable.sc connector refused the job"
)

// CoverageLedger settles a batch's targets in the coverage ledger and reads
// the progress of the current coverage cycle. Satisfied by the postgres scan
// coverage repository. Tenant-scoped.
type CoverageLedger interface {
	SettleConnectorBatch(ctx context.Context, tenantID shared.ID, b scancoverage.BatchSettlement) error
	ConnectorCycleProgress(ctx context.Context, tenantID shared.ID, since time.Time) (eligible, assessed int, err error)
}

// SetCoverageLedger wires the ledger. Without it batches settle the
// connector state only.
func (s *Service) SetCoverageLedger(l CoverageLedger) { s.ledger = l }

// CoverageStatus is whether a connector integration may receive a coverage
// batch now, and the numbers to size it.
type CoverageStatus struct {
	Ready  bool
	Reason string // why not, when not ready
	Policy scancoverage.LicensePolicy
	// ActiveIPs is Tenable.sc's active-IP count after the last batch.
	ActiveIPs    int
	DefaultBatch int
	// NewHeadroom is how many addresses the next batch may add to the
	// license count; AllNew: every address counts (rotation removed the
	// data). The sensor's license guard verifies it before launching.
	NewHeadroom int
	AllNew      bool
}

// coverageScanConfig is the scanner_config of the integration's coverage
// batches, from its config keys coverage_policy_id, coverage_repository_id,
// coverage_zone_id and coverage_max_scan_seconds.
func coverageScanConfig(intg *integration.Integration) (map[string]any, error) {
	cfg := intg.Config()
	m := map[string]any{"integration_id": intg.ID().String()}
	for _, k := range []string{"policy_id", "repository_id", "zone_id", "max_scan_seconds"} {
		if v, ok := cfg["coverage_"+k]; ok && v != nil {
			m[k] = v
		}
	}
	if _, err := ParseScanConfig(m); err != nil {
		return nil, err
	}
	return m, nil
}

// validateCoverageConfig checks the coverage keys of a connector whose
// coverage is enabled (create and update). Rotation other than off needs the
// administrator's acknowledgement (ParseTenableConfig refuses it otherwise).
func validateCoverageConfig(cfg map[string]any) error {
	tc, err := scancoverage.ParseTenableConfig(cfg)
	if err != nil {
		if strings.Contains(err.Error(), "coverage_rotation") {
			return invalid(err.Error())
		}
		return nil // reported by ParseConnectorConfigMap
	}
	if !tc.CoverageEnabled {
		return nil
	}
	m := map[string]any{"integration_id": shared.NewID().String()}
	for _, k := range []string{"policy_id", "repository_id", "zone_id", "max_scan_seconds"} {
		if v, ok := cfg["coverage_"+k]; ok && v != nil {
			m[k] = v
		}
	}
	if _, err := ParseScanConfig(m); err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) {
			return invalid("coverage is enabled: " + de.Message + " (set coverage_policy_id and coverage_repository_id)")
		}
		return err
	}
	return nil
}

// CoverageStatus settles the integration's previous coverage batch and says
// whether a new one may be dispatched. It never dispatches.
func (s *Service) CoverageStatus(ctx context.Context, intg *integration.Integration) (CoverageStatus, error) {
	notReady := func(reason string) (CoverageStatus, error) { return CoverageStatus{Reason: reason}, nil }
	if !IsConnector(intg) {
		return notReady("not a Tenable.sc sensor connector")
	}
	tc, err := scancoverage.ParseTenableConfig(intg.Config())
	if err != nil || !tc.CoverageEnabled {
		return notReady("coverage is not enabled")
	}
	if intg.Status() == integration.StatusDisabled {
		return notReady("the integration is disabled")
	}
	if _, err := coverageScanConfig(intg); err != nil {
		return notReady(err.Error())
	}

	state := readState(intg)
	if state.CoverageCommandID != "" {
		settled, err := s.settleCoverage(ctx, intg, &state, tc)
		if err != nil {
			return CoverageStatus{}, err
		}
		if !settled {
			return notReady("the previous coverage batch is still running or being ingested")
		}
	}
	if state.RotationStalled != "" {
		return notReady(state.RotationStalled)
	}
	if state.NextBatchAt != nil && s.now().Before(*state.NextBatchAt) {
		return notReady("waiting until " + state.NextBatchAt.UTC().Format(time.RFC3339) + ": " + state.CoverageWait)
	}
	if state.LicensedIPs <= 0 {
		return notReady("no license numbers yet: waiting for a successful sync of the connector")
	}
	limit := state.LicensedIPs
	if tc.LicenseCap > 0 && tc.LicenseCap < limit {
		limit = tc.LicenseCap
	}
	// What the license holds outside the next batch: everything active with
	// rotation off; with rotation, the last batch's addresses leave the count
	// (aging cleanup or recycling), so only the rest stays.
	base := state.ActiveIPs
	if tc.Rotation != scancoverage.RotationOff {
		base = max(0, state.ActiveIPs-state.LastBatchAdded)
	}
	headroom := max(0, limit-tc.SafetyMargin-base)
	batch := tc.EffectiveBatchSize()
	if tc.Rotation != scancoverage.RotationOff {
		batch = min(batch, headroom)
	}
	return CoverageStatus{
		Ready:        true,
		Policy:       scancoverage.LicensePolicy{Mode: scancoverage.LicenseActiveIPCap, Cap: limit, SafetyMargin: tc.SafetyMargin},
		ActiveIPs:    state.ActiveIPs,
		DefaultBatch: batch,
		NewHeadroom:  headroom,
		AllNew:       tc.Rotation != scancoverage.RotationOff,
	}, nil
}

// settleCoverage checks the open coverage command. Once the command finished
// (and, when it completed, every report it filed finished) it settles the
// batch's targets in the ledger, records the license numbers and decides
// when the next batch may go, then clears it and returns true.
func (s *Service) settleCoverage(ctx context.Context, intg *integration.Integration, state *SyncState,
	tc scancoverage.TenableConfig) (bool, error) {
	id, err := shared.IDFromString(state.CoverageCommandID)
	if err != nil {
		state.CoverageCommandID = ""
		writeState(intg, *state)
		return true, s.integrations.Update(ctx, intg)
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, intg.TenantID(), id)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		cmd = nil
	case err != nil:
		return false, err
	}
	if cmd != nil {
		switch cmd.Status {
		case command.CommandStatusPending, command.CommandStatusAcknowledged, command.CommandStatusRunning:
			return false, nil
		case command.CommandStatusCompleted:
			done, _, err := s.reportsSettled(ctx, intg.TenantID(), cmd.ID)
			if err != nil || !done {
				return false, err
			}
		}
		res := parseSyncResult(cmd)
		if res.LicensedIPs > 0 {
			state.LicensedIPs = res.LicensedIPs
		}
		if res.LicensedIPs > 0 || res.ActiveIPs > 0 {
			state.ActiveIPs = res.ActiveIPs
		}
		state.LastCoverageOutcome = string(cmd.Status)
		settlement := batchSettlement(cmd)
		if s.ledger != nil {
			if err := s.ledger.SettleConnectorBatch(ctx, intg.TenantID(), settlement); err != nil {
				return false, fmt.Errorf("settle coverage batch in the ledger: %w", err)
			}
		}
		s.afterBatch(intg, state, tc, cmd)
		s.updateCycle(ctx, intg.TenantID(), state)
	}
	state.CoverageCommandID = ""
	writeState(intg, *state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		return false, fmt.Errorf("record coverage batch outcome: %w", err)
	}
	return true, nil
}

// afterBatch decides when the next batch may go and whether it recycles.
func (s *Service) afterBatch(intg *integration.Integration, state *SyncState, tc scancoverage.TenableConfig, cmd *command.Command) {
	now := s.now().UTC()
	wait := func(d time.Duration, why string) {
		at := now.Add(d)
		state.NextBatchAt, state.CoverageWait = &at, why
	}
	state.NextBatchAt, state.CoverageWait = nil, ""
	msg := cmd.ErrorMessage
	switch {
	case cmd.Status == command.CommandStatusCompleted:
		state.LastBatchAt = &now
		state.LastBatchAdded = max(0, state.ActiveIPs-activeBefore(cmd))
		switch tc.Rotation {
		case scancoverage.RotationAging:
			wait(time.Duration(tc.RotationWaitHours)*time.Hour,
				"the rotation repository's license is freed by Tenable.sc's nightly cleanup")
		case scancoverage.RotationRecycle:
			// The results are ingested: the rotation repository may be
			// recycled before the next batch.
			state.RecycleNext = true
		}
	case strings.Contains(msg, licenseCapacityCode):
		wait(capacityRetry, "the Tenable.sc license capacity the batch needs is not free yet")
	default:
		wait(batchFailureRetry, "the previous batch failed")
		if tc.Rotation == scancoverage.RotationRecycle && !strings.Contains(msg, refusedBeforeLaunch) {
			// It may have imported results that were never ingested: never
			// recycle them away without an administrator's decision.
			state.RecycleNext = false
			state.RotationStalled = "rotation stalled: the previous batch failed after it launched, so its results may not be ingested; an administrator resumes rotation to recycle the rotation repository"
			s.logger.Warn("tenable.sc coverage rotation stalled after a failed batch",
				"integration_id", intg.ID().String(), "tenant_id", intg.TenantID().String(), "command_id", cmd.ID.String())
		}
	}
}

// updateCycle refreshes the cycle progress: eligible assets and those the
// connector assessed since the cycle started; a cycle that covered them all
// starts the next one.
func (s *Service) updateCycle(ctx context.Context, tenantID shared.ID, state *SyncState) {
	if s.ledger == nil || state.CycleStartedAt == nil {
		return
	}
	eligible, assessed, err := s.ledger.ConnectorCycleProgress(ctx, tenantID, *state.CycleStartedAt)
	if err != nil {
		s.logger.Warn("coverage cycle progress unavailable", "tenant_id", tenantID.String(), "error", err)
		return
	}
	now := s.now().UTC()
	state.CycleEligible, state.CycleAssessed, state.CycleETA = eligible, assessed, nil
	if eligible > 0 && assessed >= eligible {
		state.Cycle++
		state.CycleStartedAt = &now
		state.CycleAssessed = 0
		return
	}
	if elapsed := now.Sub(*state.CycleStartedAt); assessed > 0 && elapsed > 0 {
		perAsset := elapsed / time.Duration(assessed)
		eta := now.Add(perAsset * time.Duration(eligible-assessed))
		state.CycleETA = &eta
	}
}

// batchSettlement reads a finished coverage command per target, against its
// own payload targets: outcomes of a completed command (an older sensor that
// reports none: all assessed when its coverage was full, else unfinished); a
// license-guard refusal leaves every target unfinished (nothing ran); any
// other failure fails them all.
func batchSettlement(cmd *command.Command) scancoverage.BatchSettlement {
	targets := command.PayloadTargets(cmd.Payload)
	var b scancoverage.BatchSettlement
	if cmd.Status != command.CommandStatusCompleted {
		if strings.Contains(cmd.ErrorMessage, licenseCapacityCode) {
			b.Unfinished = targets
			return b
		}
		b.Failed, b.Error = targets, capText(cmd.ErrorMessage, 500)
		if b.Error == "" {
			b.Error = "the coverage batch ended " + string(cmd.Status)
		}
		return b
	}
	var res struct {
		Outcomes *[]outcome.Target `json:"target_outcomes"`
		Metadata struct {
			Coverage string `json:"coverage"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(cmd.Result, &res)
	if command.ResultTruncated(cmd.Result) {
		// Cut short: nothing it reports as done is trusted.
		res.Metadata.Coverage = ""
		if res.Outcomes != nil {
			kept := make([]outcome.Target, 0, len(*res.Outcomes))
			for _, o := range *res.Outcomes {
				if o.State != outcome.Done {
					kept = append(kept, o)
				}
			}
			res.Outcomes = &kept
		}
	}
	if res.Outcomes == nil {
		if res.Metadata.Coverage == "full" {
			b.Done = targets
		} else {
			b.Unfinished = targets
		}
		return b
	}
	for _, o := range outcome.Normalize(*res.Outcomes, targets) {
		switch o.State {
		case outcome.Done:
			b.Done = append(b.Done, o.Target)
		case outcome.Failed, outcome.Skipped:
			b.Unreachable = append(b.Unreachable, o.Target)
		default:
			b.Unfinished = append(b.Unfinished, o.Target)
		}
	}
	return b
}

// activeBefore is the license count the sensor read before the batch
// launched (0 when it did not report one).
func activeBefore(cmd *command.Command) int {
	var r struct {
		Metadata map[string]any `json:"metadata"`
	}
	if json.Unmarshal(cmd.Result, &r) != nil || r.Metadata == nil {
		return 0
	}
	if _, ok := r.Metadata["active_ips_before"]; !ok {
		return clampCount(r.Metadata["active_ips"])
	}
	return clampCount(r.Metadata["active_ips_before"])
}

// DispatchCoverageBatch queues one coverage batch: a connector_scan of the
// gated targets with the integration's coverage policy and repository, the
// license guard for newAddresses and, with rotation recycle, the rotation
// repository (recycled first when the previous batch was ingested). The
// targets already passed the coverage scheduler's target gate. Read
// tenant-scoped; refused while a previous batch is open.
func (s *Service) DispatchCoverageBatch(ctx context.Context, tenantID, integrationID shared.ID, targets []string,
	sessionID string, newAddresses int) (shared.ID, error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return shared.ID{}, err
	}
	state := readState(intg)
	if state.CoverageCommandID != "" {
		return shared.ID{}, ErrCoverageBusy
	}
	cfg, err := coverageScanConfig(intg)
	if err != nil {
		return shared.ID{}, err
	}
	tc, err := scancoverage.ParseTenableConfig(intg.Config())
	if err != nil {
		return shared.ID{}, invalid(err.Error())
	}
	ex := batchExtras{guard: &LicenseGuard{NewAddresses: max(newAddresses, 0), Headroom: tc.SafetyMargin}}
	if tc.Rotation == scancoverage.RotationRecycle {
		ex.rotation, ex.recycle = true, state.RecycleNext
	}
	cmd, err := s.newScanCommand(ctx, tenantID, cfg, targets, map[string]string{"run_id": sessionID}, ex)
	if err != nil {
		return shared.ID{}, err
	}
	if err := s.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("create coverage connector_scan: %w", err)
	}
	now := s.now().UTC()
	state.CoverageCommandID = cmd.ID.String()
	if ex.recycle {
		state.RecycleNext = false
	}
	if state.CycleStartedAt == nil {
		state.Cycle, state.CycleStartedAt = 1, &now
	}
	writeState(intg, state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		return cmd.ID, fmt.Errorf("record coverage batch on the integration: %w", err)
	}
	return cmd.ID, nil
}

// ErrCoverageBusy: the previous coverage batch of the integration is open.
var ErrCoverageBusy = shared.NewDomainError("COVERAGE_BATCH_OPEN",
	"the previous coverage batch of this integration has not finished", shared.ErrConflict)

// ErrRotationNotStalled: there is no stalled rotation to resume.
var ErrRotationNotStalled = shared.NewDomainError("ROTATION_NOT_STALLED",
	"the connector's license rotation is not stalled", shared.ErrConflict)

// ResumeRotation is an administrator's decision to resume a stalled
// recycle rotation: the next batch recycles the rotation repository, whose
// results from the failed batch may not be ingested (their targets are due
// again and are scanned anew). Tenant-scoped, audited.
func (s *Service) ResumeRotation(ctx context.Context, tenantID, integrationID shared.ID, actx *auditapp.AuditContext) (*integration.Integration, error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if !IsConnector(intg) {
		return nil, ErrNotConnector
	}
	state := readState(intg)
	if state.RotationStalled == "" {
		return nil, ErrRotationNotStalled
	}
	state.RotationStalled = ""
	state.RecycleNext = true
	writeState(intg, state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("resume rotation: %w", err)
	}
	s.auditRotationResumed(ctx, intg, actx)
	return intg, nil
}

func (s *Service) auditRotationResumed(ctx context.Context, intg *integration.Integration, actx *auditapp.AuditContext) {
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionIntegrationUpdated, audit.ResourceTypeIntegration, intg.ID().String()).
		WithResourceName(intg.Name()).
		WithMessage(fmt.Sprintf("Tenable.sc license rotation resumed for integration '%s': the next batch recycles the rotation repository", intg.Name())).
		WithMetadata("change", "coverage_rotation_resumed"))
}
