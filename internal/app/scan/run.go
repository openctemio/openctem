package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
)

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
func (s *Service) GetLatestScanRun(ctx context.Context, tenantID, scanID string) (*pipeline.Run, error) {
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
func (s *Service) GetScanRun(ctx context.Context, tenantID, scanID, runID string) (*pipeline.Run, error) {
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
	CreatedBy   string         `json:"created_by" validate:"omitempty,uuid"`
}

// QuickScanResult represents the result of a quick scan.
type QuickScanResult struct {
	PipelineRunID string `json:"pipeline_run_id"`
	ScanID        string `json:"scan_id"`
	AssetGroupID  string `json:"asset_group_id"`
	Status        string `json:"status"`
	TargetCount   int    `json:"target_count"`
}

// QuickScan performs an immediate scan on provided targets.
// It creates an ephemeral asset group and scan, then triggers immediately.
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

	// Determine scan type
	scanType := scan.ScanTypeSingle
	var pipelineID *shared.ID
	if input.WorkflowID != "" {
		scanType = scan.ScanTypeWorkflow
		pid, err := shared.IDFromString(input.WorkflowID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid workflow_id", shared.ErrValidation)
		}
		pipelineID = &pid

		// Verify workflow exists
		if _, err := s.templateRepo.GetByID(ctx, pid); err != nil {
			return nil, fmt.Errorf("workflow not found: %w", err)
		}
	}

	// Create ephemeral asset group
	timestamp := time.Now().Format("20060102-150405")
	assetGroupName := fmt.Sprintf("quick-scan-%s", timestamp)

	ag, err := assetgroup.NewAssetGroupWithTenant(
		tenantID,
		assetGroupName,
		assetgroup.EnvironmentProduction, // Default for quick scan
		assetgroup.CriticalityMedium,     // Default for quick scan
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create asset group: %w", err)
	}
	ag.UpdateDescription(fmt.Sprintf("Auto-created for quick scan with %d targets", len(input.Targets)))

	if err := s.assetGroupRepo.Create(ctx, ag); err != nil {
		return nil, fmt.Errorf("failed to create asset group: %w", err)
	}

	// Create ephemeral scan
	scanName := fmt.Sprintf("Quick Scan - %s", timestamp)
	sc, err := scan.NewScan(tenantID, scanName, ag.ID(), scanType)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	sc.Description = fmt.Sprintf("Quick scan of %d targets", len(input.Targets))

	if scanType == scan.ScanTypeWorkflow {
		if err := sc.SetWorkflow(*pipelineID); err != nil {
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
		PipelineRunID: run.ID.String(),
		ScanID:        sc.ID.String(),
		AssetGroupID:  ag.ID().String(),
		Status:        string(run.Status),
		TargetCount:   len(input.Targets),
	}, nil
}

// =============================================================================
// Overview Stats Operations
// =============================================================================

// OverviewStats represents aggregated statistics for scan management overview.
type OverviewStats struct {
	Pipelines StatusCounts `json:"pipelines"`
	Scans     StatusCounts `json:"scans"`
	Jobs      StatusCounts `json:"jobs"`
}

// StatusCounts represents counts grouped by status.
type StatusCounts struct {
	Total     int64 `json:"total"`
	Running   int64 `json:"running"`
	Pending   int64 `json:"pending"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Canceled  int64 `json:"canceled"`
}

// GetOverviewStats returns aggregated statistics for scan management.
// This includes pipeline runs, step runs (scans), and commands (jobs).
func (s *Service) GetOverviewStats(ctx context.Context, tenantID string) (*OverviewStats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	stats := &OverviewStats{}

	// Get pipeline run stats
	pipelineStats, err := s.getPipelineRunStats(ctx, tid)
	if err != nil {
		s.logger.Warn("failed to get pipeline stats", "error", err)
	} else {
		stats.Pipelines = pipelineStats
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

// getPipelineRunStats counts pipeline runs by status.
// OPTIMIZED: Uses single aggregation query instead of N queries per status.
func (s *Service) getPipelineRunStats(ctx context.Context, tenantID shared.ID) (StatusCounts, error) {
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
