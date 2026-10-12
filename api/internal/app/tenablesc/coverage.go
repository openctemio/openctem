package tenablesc

// License-aware rolling coverage on the connector (RFC-047 §9): the RFC-007
// planner picks the next batch of assets; each batch is one connector_scan
// launched through the sensor. The license numbers come from Tenable.sc
// itself (/rest/status, reported with every sync and scan); the next batch
// waits until the previous one finished and its reports were ingested, so the
// active-IP count it is sized against already includes the last batch.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CoverageStatus is whether a connector integration may receive a coverage
// batch now, and the numbers to size it.
type CoverageStatus struct {
	Ready  bool
	Reason string // why not, when not ready
	Policy scancoverage.LicensePolicy
	// ActiveIPs is Tenable.sc's active-IP count after the last batch.
	ActiveIPs    int
	DefaultBatch int
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
// coverage is enabled (create and update).
func validateCoverageConfig(cfg map[string]any) error {
	// A malformed config is reported by ParseConnectorConfigMap.
	tc, _ := scancoverage.ParseTenableConfig(cfg)
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
		settled, err := s.settleCoverage(ctx, intg, &state)
		if err != nil {
			return CoverageStatus{}, err
		}
		if !settled {
			return notReady("the previous coverage batch is still running or being ingested")
		}
	}
	if state.LicensedIPs <= 0 {
		return notReady("no license numbers yet: waiting for a successful sync of the connector")
	}
	limit := state.LicensedIPs
	if tc.LicenseCap > 0 && tc.LicenseCap < limit {
		limit = tc.LicenseCap
	}
	return CoverageStatus{
		Ready:        true,
		Policy:       scancoverage.LicensePolicy{Mode: scancoverage.LicenseActiveIPCap, Cap: limit, SafetyMargin: tc.SafetyMargin},
		ActiveIPs:    state.ActiveIPs,
		DefaultBatch: tc.EffectiveBatchSize(),
	}, nil
}

// settleCoverage checks the open coverage command. It returns true (and
// clears it, taking the license numbers its result reported) once the
// command finished and every report it filed finished.
func (s *Service) settleCoverage(ctx context.Context, intg *integration.Integration, state *SyncState) (bool, error) {
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
	}
	state.CoverageCommandID = ""
	writeState(intg, *state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		return false, fmt.Errorf("record coverage batch outcome: %w", err)
	}
	return true, nil
}

// DispatchCoverageBatch queues one coverage batch: a connector_scan of the
// gated targets with the integration's coverage policy and repository. The
// targets already passed the coverage scheduler's target gate. Read
// tenant-scoped; refused while a previous batch is open.
func (s *Service) DispatchCoverageBatch(ctx context.Context, tenantID, integrationID shared.ID, targets []string,
	sessionID string) (shared.ID, error) {
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
	cmd, err := s.NewScanCommand(ctx, tenantID, cfg, targets, map[string]string{"run_id": sessionID})
	if err != nil {
		return shared.ID{}, err
	}
	if err := s.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("create coverage connector_scan: %w", err)
	}
	state.CoverageCommandID = cmd.ID.String()
	writeState(intg, state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		return cmd.ID, fmt.Errorf("record coverage batch on the integration: %w", err)
	}
	return cmd.ID, nil
}

// ErrCoverageBusy: the previous coverage batch of the integration is open.
var ErrCoverageBusy = shared.NewDomainError("COVERAGE_BATCH_OPEN",
	"the previous coverage batch of this integration has not finished", shared.ErrConflict)
