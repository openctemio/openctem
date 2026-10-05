package scan

// Scans whose scanner is a connector (the Tenable.sc sensor connector,
// docs/rfcs/RFC-047-tenable-sc-sensor-connector.md §5.2): OpenCTEM owns the
// scan, its targets and its schedule; the run becomes one connector_scan
// command pinned to the connector's sensor, which launches the scan in
// Tenable.sc and pushes its results through the normal ingest.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// ConnectorScans validates connector scan configs and builds their commands
// (tenablesc.Service).
type ConnectorScans interface {
	ValidateScanConfig(ctx context.Context, tenantID shared.ID, cfg map[string]any) error
	// NewScanCommand builds the command; bookkeeping carries the run's
	// pipeline keys (run_id, scan_id, pipeline_run_id, step_key,
	// step_run_id).
	NewScanCommand(ctx context.Context, tenantID shared.ID, cfg map[string]any, targets []string,
		bookkeeping map[string]string) (*command.Command, error)
}

// WithConnectorScans wires connector scans. Without it a connector cannot be
// a scan's scanner.
func WithConnectorScans(c ConnectorScans) ServiceOption {
	return func(s *Service) { s.connectorScans = c }
}

// ErrConnectorScansUnavailable: a connector is the scanner but connector
// scans are not wired.
var ErrConnectorScansUnavailable = shared.NewDomainError("TOOL_NOT_SCANNER",
	"connector scans are not available in this installation", shared.ErrValidation)

// validateConnectorScanner checks a connector scan's config at create/update.
func (s *Service) validateConnectorScanner(ctx context.Context, tenantID shared.ID, cfg map[string]any) error {
	if s.connectorScans == nil {
		return ErrConnectorScansUnavailable
	}
	return s.connectorScans.ValidateScanConfig(ctx, tenantID, cfg)
}

// isConnectorScanner reports whether the scan's scanner is a connector.
func (s *Service) isConnectorScanner(ctx context.Context, tenantID shared.ID, scannerName string) (*tool.Tool, bool) {
	if scannerName == "" || s.toolRepo == nil {
		return nil, false
	}
	t, err := s.toolRepo.GetByName(ctx, tenantID, scannerName)
	if err != nil || t == nil {
		return nil, false
	}
	connector := t.IsConnector()
	return t, connector
}

// connectorRunUser is the person a connector run acts for: the scan's
// creator (scheduled runs have no caller). The gate uses the request caller
// first when there is one.
func connectorRunUser(sc *scan.Scan) *shared.ID {
	return sc.CreatedBy
}

// triggerConnectorScan runs a connector scan: its resolved targets (direct
// targets and group members, minus exclusions, unconfirmed assets and what the
// actor may not scan) pass the active-probe gate once more (target validator,
// private ranges only inside a scan zone, exclusions, act scope), then one
// connector_scan command is queued for the connector's sensor.
func (s *Service) triggerConnectorScan(ctx context.Context, sc *scan.Scan, resolved *resolvedTargets,
	triggerType pipeline.TriggerType, triggeredBy string, runContext map[string]any, retryAttempt int,
	scheduledFor *time.Time, freezeOverride bool) (*pipeline.Run, error) {
	if s.connectorScans == nil {
		return nil, ErrConnectorScansUnavailable
	}
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID:     sc.TenantID,
		Targets:      resolved.Targets,
		ActScope:     true,
		FallbackUser: connectorRunUser(sc),
	})
	if err != nil {
		return nil, err
	}
	if len(gated.Refused) > 0 {
		runContext["connector_refused_targets"] = gated.Refused
	}
	if len(gated.Excluded) > 0 {
		runContext["connector_excluded_targets"] = gated.Excluded
	}
	if len(gated.Allowed) == 0 {
		return nil, shared.NewDomainError("NO_DISPATCHABLE_TARGETS",
			"no target of this scan passed the scan target checks; nothing was sent to Tenable.sc", shared.ErrValidation)
	}

	// A connector scan is active work outside any zone.
	override, err := s.checkFreeze(ctx, sc, freezeRequest{triggerType, triggeredBy, freezeOverride}, nil, true)
	if err != nil {
		return nil, err
	}

	quickScanTemplateID, _ := shared.IDFromString(QuickScanTemplateID)
	run, err := pipeline.NewRun(quickScanTemplateID, sc.TenantID, nil, triggerType, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create run: %w", err)
	}
	run.FreezeOverride = override
	run.SetTotalSteps(1)
	run.RetryAttempt = retryAttempt
	run.ScheduledFor = scheduledFor
	run.Start()
	run.ScanID = &sc.ID
	if sc.ProfileID != nil {
		run.ScanProfileID = sc.ProfileID
	}
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerScan, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err
	}
	stepRun := s.createSingleScanStepRun(ctx, run)

	bk := map[string]string{"run_id": run.ID.String(), "scan_id": sc.ID.String()}
	if stepRun != nil {
		bk[pipeline.PayloadKeyPipelineRunID] = run.ID.String()
		bk[pipeline.PayloadKeyStepKey] = stepRun.StepKey
		bk[pipeline.PayloadKeyStepRunID] = stepRun.ID.String()
	}
	cmd, err := s.connectorScans.NewScanCommand(ctx, sc.TenantID, sc.ScannerConfig, gated.Allowed, bk)
	if err == nil {
		cmd.FreezeOverride = run.FreezeOverride
		err = s.commandRepo.Create(ctx, cmd)
	}
	if err != nil {
		run.Fail("Failed to create command: " + err.Error())
		_ = s.runRepo.Update(ctx, run)
		var de *shared.DomainError
		if errors.As(err, &de) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to create connector scan command: %w", err)
	}
	if stepRun != nil {
		stepRun.CommandID = &cmd.ID
		stepRun.Queue()
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Warn("failed to link step run to command",
				"run_id", run.ID.String(), "command_id", cmd.ID.String(), "error", err)
		}
	}
	return run, nil
}
