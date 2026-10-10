package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// usableWorkflow returns a scan workflow the tenant may USE (create, edit or
// run a scan with): its own workflow, or a shared system template (a starter
// workflow), which every tenant uses read-only. Another tenant's private
// workflow is ErrScanWorkflowNotFound, exactly like a missing one (no IDOR).
// A retired workflow is ErrScanWorkflowRetired and an inactive one a
// validation error naming it. Changing a workflow (edit, delete, activate)
// keeps the tenant-only lookup: a system template is never the tenant's to
// change.
func (s *Service) usableWorkflow(ctx context.Context, tenantID, workflowID shared.ID) (*scanworkflow.Workflow, error) {
	wf, err := s.templateRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if errors.Is(err, shared.ErrNotFound) {
		wf, err = s.templateRepo.GetSystemTemplateByID(ctx, workflowID)
	}
	if errors.Is(err, shared.ErrNotFound) || (err == nil && wf == nil) {
		return nil, scanworkflow.ErrScanWorkflowNotFound
	}
	if err != nil {
		return nil, err
	}
	if wf.RetiredAt != nil {
		return nil, scanworkflow.ErrScanWorkflowRetired
	}
	if !wf.IsActive {
		return nil, fmt.Errorf("%w: scan workflow %q is disabled; enable it or pick another workflow",
			shared.ErrValidation, wf.Name)
	}
	return wf, nil
}

// =============================================================================
// Scan Runs Operations
// =============================================================================

// ListScanRuns lists runs for a specific scan.
func (s *Service) ListScanRuns(ctx context.Context, tenantID, scanID string, page, perPage int) (map[string]any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan id", shared.ErrValidation)
	}

	// Verify scan exists
	if _, err := s.scanRepo.GetByTenantAndID(ctx, tid, sid); err != nil {
		return nil, err
	}

	// Get runs for this scan
	runs, total, err := s.runRepo.ListByScanID(ctx, sid, page, perPage)
	if err != nil {
		return nil, err
	}

	totalPages := (total + int64(perPage) - 1) / int64(perPage)

	return map[string]any{
		"items":       runs,
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
	}, nil
}

// GetLatestScanRun gets the latest run for a specific scan.
func (s *Service) GetLatestScanRun(ctx context.Context, tenantID, scanID string) (*scanrun.Run, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan id", shared.ErrValidation)
	}

	// Verify scan exists
	sc, err := s.scanRepo.GetByTenantAndID(ctx, tid, sid)
	if err != nil {
		return nil, err
	}

	if sc.LastRunID == nil {
		return nil, shared.ErrNotFound
	}

	return s.runRepo.GetByID(ctx, *sc.LastRunID)
}

// GetScanRun gets a specific run for a scan.
func (s *Service) GetScanRun(ctx context.Context, tenantID, scanID, runID string) (*scanrun.Run, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan id", shared.ErrValidation)
	}

	rid, err := shared.IDFromString(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid run id", shared.ErrValidation)
	}

	// Verify scan exists
	if _, err := s.scanRepo.GetByTenantAndID(ctx, tid, sid); err != nil {
		return nil, err
	}

	// Get the run and verify it belongs to this scan
	run, err := s.runRepo.GetByID(ctx, rid)
	if err != nil {
		return nil, err
	}

	if run.ScanID == nil || *run.ScanID != sid {
		return nil, shared.ErrNotFound
	}

	return run, nil
}

// =============================================================================
// Quick Scan Operations
// =============================================================================

// QuickScanInput represents the input for quick scan.
type QuickScanInput struct {
	TenantID    string         `json:"tenant_id" validate:"required,uuid"`
	Targets     []string       `json:"targets" validate:"required,min=1,max=1000"`
	ScannerName string         `json:"scanner_name" validate:"omitempty,max=100"`
	WorkflowID  string         `json:"workflow_id" validate:"omitempty,uuid"`
	Config      map[string]any `json:"config"`
	Tags        []string       `json:"tags" validate:"max=20,dive,max=50"`
	// Intensity is the probe ceiling (RFC-071); "" = the tier the scanner
	// or workflow probes at.
	Intensity string `json:"intensity" validate:"omitempty,oneof=passive active intrusive"`
	CreatedBy string `json:"created_by" validate:"omitempty,uuid"`
}

// QuickScanResult represents the result of a quick scan.
type QuickScanResult struct {
	ScanRunID string `json:"scan_run_id"`
	ScanID    string `json:"scan_id"`
	// AssetGroupID is always empty now: quick scans create no asset group.
	// Kept so older clients that read it do not break.
	AssetGroupID string `json:"asset_group_id"`
	Status       string `json:"status"`
	TargetCount  int    `json:"target_count"`
}

// QuickScan performs an immediate scan on provided targets: it creates an ad-hoc
// scan (no asset group, hidden from the Configurations list) and triggers it.
// SaveQuickScan turns it into a saved configuration.
func (s *Service) QuickScan(ctx context.Context, input QuickScanInput) (*QuickScanResult, error) {
	s.logger.Info("quick scan requested", "tenant_id", input.TenantID, "target_count", len(input.Targets))

	// Validate: need either scanner_name or workflow_id
	if input.ScannerName == "" && input.WorkflowID == "" {
		return nil, fmt.Errorf("%w: scanner_name or workflow_id is required", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	// SECURITY: apply SSRF target validation (blocks internal/localhost/private
	// IPs) to BOTH the single-scanner and workflow paths. The workflow path
	// previously skipped this entirely, which both let internal targets through
	// AND silently dropped the targets (they were never attached to the run, so
	// the workflow scanned an empty asset group — nothing).
	validatedTargets, err := s.validateScanTargets(ctx, CreateScanInput{
		TenantID: input.TenantID,
		Targets:  input.Targets,
	})
	if err != nil {
		return nil, err
	}
	input.Targets = validatedTargets
	if err := s.refuseOutOfActScope(ctx, tenantID, userIDPtr(input.CreatedBy), input.Targets); err != nil {
		return nil, err
	}
	if err := s.refuseUnprovenIntrusive(ctx, tenantID, input.ScannerName, input.Targets); err != nil {
		return nil, err
	}
	if err := s.refuseTierExceeded(ctx, tenantID, input.ScannerName, input.Targets); err != nil {
		return nil, err
	}
	if err := s.refuseUnownedTargets(ctx, tenantID, "quick_scan", input.Targets, IsTakeoverOnlyProbe(input.ScannerName, input.Config)); err != nil {
		return nil, err
	}

	// Determine scan type
	scanType := scan.ScanTypeSingle
	var scanWorkflowID *shared.ID
	if input.WorkflowID != "" {
		scanType = scan.ScanTypeWorkflow
		pid, err := shared.IDFromString(input.WorkflowID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid workflow_id", shared.ErrValidation)
		}
		scanWorkflowID = &pid

		// SECURITY: verify the workflow/scan workflow belongs to this
		// tenant (or is a system template). GetByID alone is unscoped and
		// would let a caller trigger another tenant's private scan workflow (IDOR).
		if _, err := s.usableWorkflow(ctx, tenantID, pid); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				s.logger.Warn("SECURITY: cross-tenant quick-scan workflow attempt",
					"tenant_id", tenantID.String(), "workflow_id", pid.String())
			}
			return nil, err
		}
	} else {
		// SECURITY: single-scanner QuickScan bypasses CreateScan, so apply the
		// same scanner-config validation here before targets reach a sensor.
		if err := s.validateScanSecurityInputs(ctx, tenantID, CreateScanInput{
			TenantID:      input.TenantID,
			Tags:          input.Tags,
			ScannerConfig: input.Config,
		}); err != nil {
			return nil, err
		}
	}

	// The scan the run belongs to. It is ad hoc (owner decision D10): not a
	// configuration, hidden from the Configurations list until someone saves
	// it (SaveQuickScan). No asset group is created: the targets live on the
	// scan, which both trigger paths read.
	sc, err := scan.NewScan(tenantID, quickScanName(time.Now(), shared.NewID()), shared.ID{}, scanType)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	sc.AdHoc = true

	sc.Description = fmt.Sprintf("Quick scan of %d targets", len(input.Targets))

	// Persist the direct targets on the scan for BOTH paths. The single-scanner
	// path also mirrors them into scanner_config below (the sensor scanner reads
	// config), while the workflow path relies on sc.Targets being propagated
	// into the workflow run context (see triggerWorkflow) so the step commands
	// actually carry the targets to the sensor.
	sc.SetTargets(input.Targets)

	if scanType == scan.ScanTypeWorkflow {
		if err := sc.SetWorkflow(*scanWorkflowID); err != nil {
			return nil, fmt.Errorf("failed to set workflow: %w", err)
		}
	} else {
		config := input.Config
		if config == nil {
			config = make(map[string]any)
		}
		config["targets"] = input.Targets
		if err := sc.SetSingleScanner(input.ScannerName, config, 1); err != nil {
			return nil, fmt.Errorf("failed to set scanner: %w", err)
		}
	}

	if len(input.Tags) > 0 {
		sc.SetTags(input.Tags)
	}

	// Refused before the ad-hoc scan is stored: a wildcard pattern only for
	// a tool that takes it as a root domain.
	if err := s.refuseWildcardTargets(ctx, sc); err != nil {
		return nil, err
	}
	if err := s.applyIntensity(ctx, sc, input.Intensity); err != nil {
		return nil, err
	}

	if input.CreatedBy != "" {
		userID, _ := shared.IDFromString(input.CreatedBy)
		sc.SetCreatedBy(userID)
	}

	if err := s.scanRepo.Create(ctx, sc); err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	// Trigger the scan immediately
	triggerInput := TriggerScanExecInput{
		TenantID:    input.TenantID,
		ScanID:      sc.ID.String(),
		TriggeredBy: input.CreatedBy,
		Context: map[string]any{
			"trigger":      "quick_scan",
			"target_count": len(input.Targets),
		},
	}

	run, err := s.TriggerScan(ctx, triggerInput)
	if err != nil {
		return nil, fmt.Errorf("failed to trigger scan: %w", err)
	}

	s.logger.Info("quick scan triggered",
		"scan_id", sc.ID.String(),
		"run_id", run.ID.String(),
		"target_count", len(input.Targets),
	)

	return &QuickScanResult{
		ScanRunID:   run.ID.String(),
		ScanID:      sc.ID.String(),
		Status:      string(run.Status),
		TargetCount: len(input.Targets),
	}, nil
}

// quickScanName names an ad-hoc quick scan. The time alone collided when two
// quick scans started in the same second (409 "scan with this name already
// exists", 22c B8); a short random suffix keeps every name unique.
func quickScanName(now time.Time, nonce shared.ID) string {
	return fmt.Sprintf("Quick Scan - %s-%s", now.Format("20060102-150405"), strings.ReplaceAll(nonce.String(), "-", "")[24:])
}

// SaveQuickScan turns an ad-hoc quick scan into a saved configuration named
// name ("Save as scan"). Its runs stay attached; it then appears in the
// Configurations list and can be edited and scheduled like any other.
func (s *Service) SaveQuickScan(ctx context.Context, tenantID, scanID, name string) (*scan.Scan, error) {
	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	if err := sc.SaveAsConfiguration(name); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, err
	}
	s.logger.Info("quick scan saved as configuration", "scan_id", sc.ID.String(), "tenant_id", tenantID)
	return sc, nil
}

// =============================================================================
// Overview Stats Operations
// =============================================================================

// OverviewStats represents aggregated statistics for scan management overview.
type OverviewStats struct {
	ScanRuns StatusCounts `json:"scan_runs"`
	Scans    StatusCounts `json:"scans"`
	Jobs     StatusCounts `json:"jobs"`
}

// StatusCounts represents counts grouped by status.
type StatusCounts struct {
	Total     int64 `json:"total"`
	Running   int64 `json:"running"`
	Pending   int64 `json:"pending"`
	Completed int64 `json:"completed"`
	Partial   int64 `json:"partial"`
	Failed    int64 `json:"failed"`
	Canceled  int64 `json:"canceled"`
}

// GetOverviewStats returns aggregated statistics for scan management.
// This includes scan runs, step runs (scans), and commands (jobs).
func (s *Service) GetOverviewStats(ctx context.Context, tenantID string) (*OverviewStats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	stats := &OverviewStats{}

	// Get scan run stats
	pipelineStats, err := s.getScanRunStats(ctx, tid)
	if err != nil {
		s.logger.Warn("failed to get scan run stats", "error", err)
	} else {
		stats.ScanRuns = pipelineStats
	}

	// Get step run (scan) stats
	scanStats, err := s.getStepRunStats(ctx, tid)
	if err != nil {
		s.logger.Warn("failed to get scan stats", "error", err)
	} else {
		stats.Scans = scanStats
	}

	// Get command (job) stats
	jobStats, err := s.getCommandStats(ctx, tid)
	if err != nil {
		s.logger.Warn("failed to get job stats", "error", err)
	} else {
		stats.Jobs = jobStats
	}

	return stats, nil
}

// getScanRunStats counts scan runs by status.
// OPTIMIZED: Uses single aggregation query instead of N queries per status.
func (s *Service) getScanRunStats(ctx context.Context, tenantID shared.ID) (StatusCounts, error) {
	// Use optimized single-query aggregation from repository
	stats, err := s.runRepo.GetStatsByTenant(ctx, tenantID)
	if err != nil {
		return StatusCounts{}, err
	}

	return StatusCounts{
		Total:     stats.Total,
		Pending:   stats.Pending,
		Running:   stats.Running,
		Completed: stats.Completed,
		Partial:   stats.Partial,
		Failed:    stats.Failed,
		Canceled:  stats.Canceled,
	}, nil
}

// getStepRunStats counts step runs by status.
// OPTIMIZED: Uses single aggregation query with JOIN instead of N+1 queries.
func (s *Service) getStepRunStats(ctx context.Context, tenantID shared.ID) (StatusCounts, error) {
	// Use optimized single-query aggregation from repository
	stats, err := s.stepRunRepo.GetStatsByTenant(ctx, tenantID)
	if err != nil {
		return StatusCounts{}, err
	}

	return StatusCounts{
		Total:     stats.Total,
		Pending:   stats.Pending,
		Running:   stats.Running,
		Completed: stats.Completed,
		Partial:   stats.Partial,
		Failed:    stats.Failed,
		Canceled:  stats.Canceled,
	}, nil
}

// getCommandStats counts commands by status.
// OPTIMIZED: Uses single aggregation query instead of N queries per status.
func (s *Service) getCommandStats(ctx context.Context, tenantID shared.ID) (StatusCounts, error) {
	// Use optimized single-query aggregation from repository
	stats, err := s.commandRepo.GetStatsByTenant(ctx, tenantID)
	if err != nil {
		return StatusCounts{}, err
	}

	return StatusCounts{
		Total:     stats.Total,
		Pending:   stats.Pending,
		Running:   stats.Running,
		Completed: stats.Completed,
		Failed:    stats.Failed,
		Canceled:  stats.Canceled,
	}, nil
}

// =============================================================================
// Retry Operations
// =============================================================================

// RetryScanRun creates a new scan run for a scan as part of automatic retry.
// Called by the ScanRetryController when a previous run failed and the scan
// has retry budget remaining.
//
// The new run is tagged with retry_attempt = previous attempt + 1.
func (s *Service) RetryScanRun(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error {
	sc, err := s.scanRepo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		return fmt.Errorf("scan not found for retry: %w", err)
	}

	// Defensive: if scan is no longer active or has no retry budget, skip
	if sc.Status != scan.StatusActive {
		s.logger.Info("skipping retry: scan no longer active", "scan_id", scanID.String())
		return nil
	}
	if !sc.ShouldRetry(retryAttempt - 1) {
		s.logger.Info("skipping retry: retry budget exhausted", "scan_id", scanID.String(), "attempt", retryAttempt, "max", sc.MaxRetries)
		return nil
	}

	// Trigger a new run via the standard trigger path, with retry attempt in context
	// The new run is created with its retry_attempt. Setting it afterwards
	// with a full-row update raced the run itself: a run that already finished
	// was not updated, kept retry_attempt 0, and the retry budget never ran out.
	run, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   scanID.String(),
		Context: map[string]any{
			"triggered_by":  "retry-controller",
			"retry_attempt": retryAttempt,
			"retried_at":    time.Now().Unix(),
		},
		RetryAttempt: retryAttempt,
		// A retry is started by the platform, not by a person.
		TriggerType: scanworkflow.TriggerTypeSystem,
	})
	if err != nil {
		return fmt.Errorf("failed to trigger retry: %w", err)
	}

	s.logger.Info("scan retry triggered",
		"scan_id", scanID.String(),
		"new_run_id", func() string {
			if run != nil {
				return run.ID.String()
			}
			return ""
		}(),
		"attempt", retryAttempt)
	return nil
}
