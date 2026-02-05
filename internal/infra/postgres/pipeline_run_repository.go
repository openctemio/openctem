package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// PipelineRunRepository implements pipeline.RunRepository using PostgreSQL.
type PipelineRunRepository struct {
	db *DB
}

// NewPipelineRunRepository creates a new PipelineRunRepository.
func NewPipelineRunRepository(db *DB) *PipelineRunRepository {
	return &PipelineRunRepository{db: db}
}

// Create persists a new pipeline run.
func (r *PipelineRunRepository) Create(ctx context.Context, run *pipeline.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	query := `
		INSERT INTO pipeline_runs (
			id, pipeline_id, tenant_id, asset_id, scan_id,
			trigger_type, triggered_by, status, context,
			total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
			started_at, completed_at, error_message,
			scan_profile_id, quality_gate_result,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	_, err = r.db.ExecContext(ctx, query,
		run.ID.String(),
		run.PipelineID.String(),
		run.TenantID.String(),
		nullID(run.AssetID),
		nullID(run.ScanID),
		string(run.TriggerType),
		run.TriggeredBy,
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
		run.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create pipeline run: %w", err)
	}

	return nil
}

// GetByID retrieves a run by ID.
func (r *PipelineRunRepository) GetByID(ctx context.Context, id shared.ID) (*pipeline.Run, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRun(row)
}

// GetByTenantAndID retrieves a run by tenant and ID.
func (r *PipelineRunRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*pipeline.Run, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRun(row)
}

// List lists runs with filters and pagination.
func (r *PipelineRunRepository) List(ctx context.Context, filter pipeline.RunFilter, page pagination.Pagination) (pagination.Result[*pipeline.Run], error) {
	var result pagination.Result[*pipeline.Run]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM pipeline_runs"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count pipeline runs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list pipeline runs: %w", err)
	}
	defer rows.Close()

	var runs []*pipeline.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return result, err
		}
		runs = append(runs, run)
	}

	return pagination.NewResult(runs, total, page), nil
}

// Update updates a run.
func (r *PipelineRunRepository) Update(ctx context.Context, run *pipeline.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	query := `
		UPDATE pipeline_runs
		SET status = $2, context = $3,
		    total_steps = $4, completed_steps = $5, failed_steps = $6, skipped_steps = $7, total_findings = $8,
		    started_at = $9, completed_at = $10, error_message = $11,
		    scan_profile_id = $12, quality_gate_result = $13
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		run.ID.String(),
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
	)

	if err != nil {
		return fmt.Errorf("failed to update pipeline run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a run.
func (r *PipelineRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM pipeline_runs WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete pipeline run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetWithStepRuns retrieves a run with its step runs.
func (r *PipelineRunRepository) GetWithStepRuns(ctx context.Context, id shared.ID) (*pipeline.Run, error) {
	run, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	stepRunRepo := NewStepRunRepository(r.db)
	stepRuns, err := stepRunRepo.GetByPipelineRunID(ctx, id)
	if err != nil {
		return nil, err
	}

	run.StepRuns = stepRuns
	return run, nil
}

// GetActiveByPipelineID retrieves active runs for a pipeline.
func (r *PipelineRunRepository) GetActiveByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*pipeline.Run, error) {
	query := r.selectQuery() + " WHERE pipeline_id = $1 AND status IN ('pending', 'running')"
	rows, err := r.db.QueryContext(ctx, query, pipelineID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*pipeline.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}

	return runs, nil
}

// GetActiveByAssetID retrieves active runs for an asset.
func (r *PipelineRunRepository) GetActiveByAssetID(ctx context.Context, assetID shared.ID) ([]*pipeline.Run, error) {
	query := r.selectQuery() + " WHERE asset_id = $1 AND status IN ('pending', 'running')"
	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*pipeline.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}

	return runs, nil
}

// CountActiveByPipelineID counts active runs (pending/running) for a pipeline.
func (r *PipelineRunRepository) CountActiveByPipelineID(ctx context.Context, pipelineID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM pipeline_runs WHERE pipeline_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, pipelineID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by pipeline: %w", err)
	}
	return count, nil
}

// CountActiveByTenantID counts active runs (pending/running) for a tenant.
func (r *PipelineRunRepository) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM pipeline_runs WHERE tenant_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by tenant: %w", err)
	}
	return count, nil
}

// CountActiveByScanID counts active runs (pending/running) for a scan config.
func (r *PipelineRunRepository) CountActiveByScanID(ctx context.Context, scanID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM pipeline_runs WHERE scan_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, scanID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by scan: %w", err)
	}
	return count, nil
}

// UpdateStats updates run statistics.
func (r *PipelineRunRepository) UpdateStats(ctx context.Context, id shared.ID, completed, failed, skipped, findings int) error {
	query := `
		UPDATE pipeline_runs
		SET completed_steps = $2, failed_steps = $3, skipped_steps = $4, total_findings = $5
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), completed, failed, skipped, findings)
	return err
}

// UpdateStatus updates run status.
func (r *PipelineRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status pipeline.RunStatus, errorMessage string) error {
	query := `
		UPDATE pipeline_runs
		SET status = $2, error_message = $3,
		    completed_at = CASE WHEN $2 IN ('completed', 'failed', 'cancelled', 'timeout') THEN NOW() ELSE completed_at END
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage)
	return err
}

// CreateRunIfUnderLimit atomically checks concurrent run limits and creates run if under limit.
// Uses a transaction with row-level locking to prevent race conditions.
func (r *PipelineRunRepository) CreateRunIfUnderLimit(ctx context.Context, run *pipeline.Run, maxPerScan, maxPerTenant int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Lock the scan config row to serialize concurrent triggers for the same scan
	// This prevents race conditions where multiple triggers check limits simultaneously
	lockQuery := `SELECT id FROM scans WHERE id = $1 FOR UPDATE`
	if _, err := tx.ExecContext(ctx, lockQuery, run.ScanID.String()); err != nil {
		return fmt.Errorf("failed to lock scan config: %w", err)
	}

	// Count active runs for this scan (no FOR UPDATE needed - we already hold lock on scans row)
	var scanActiveCount int
	scanCountQuery := `
		SELECT COUNT(*) FROM pipeline_runs
		WHERE scan_id = $1 AND status IN ('pending', 'running')
	`
	if err := tx.QueryRowContext(ctx, scanCountQuery, run.ScanID.String()).Scan(&scanActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs for scan: %w", err)
	}
	if scanActiveCount >= maxPerScan {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent runs (%d) reached for this scan config", maxPerScan),
			shared.ErrValidation,
		)
	}

	// Count active runs for this tenant
	var tenantActiveCount int
	tenantCountQuery := `
		SELECT COUNT(*) FROM pipeline_runs
		WHERE tenant_id = $1 AND status IN ('pending', 'running')
	`
	if err := tx.QueryRowContext(ctx, tenantCountQuery, run.TenantID.String()).Scan(&tenantActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs for tenant: %w", err)
	}
	if tenantActiveCount >= maxPerTenant {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent runs (%d) reached for this tenant", maxPerTenant),
			shared.ErrValidation,
		)
	}

	// Create the run within the same transaction
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	insertQuery := `
		INSERT INTO pipeline_runs (
			id, pipeline_id, tenant_id, asset_id, scan_id,
			trigger_type, triggered_by, status, context,
			total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
			started_at, completed_at, error_message,
			scan_profile_id, quality_gate_result,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	_, err = tx.ExecContext(ctx, insertQuery,
		run.ID.String(),
		run.PipelineID.String(),
		run.TenantID.String(),
		nullID(run.AssetID),
		nullID(run.ScanID),
		string(run.TriggerType),
		run.TriggeredBy,
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
		run.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create pipeline run: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListByScanID lists runs for a specific scan with pagination.
func (r *PipelineRunRepository) ListByScanID(ctx context.Context, scanID shared.ID, page, perPage int) ([]*pipeline.Run, int64, error) {
	// Get total count
	countQuery := "SELECT COUNT(*) FROM pipeline_runs WHERE scan_id = $1"
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, scanID.String()).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count runs: %w", err)
	}

	// Get runs
	offset := (page - 1) * perPage
	if offset < 0 {
		offset = 0
	}
	query := r.selectQuery() + fmt.Sprintf(" WHERE scan_id = $1 ORDER BY created_at DESC LIMIT %d OFFSET %d", perPage, offset)

	rows, err := r.db.QueryContext(ctx, query, scanID.String())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []*pipeline.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		runs = append(runs, run)
	}

	return runs, total, nil
}

func (r *PipelineRunRepository) selectQuery() string {
	return `
		SELECT id, pipeline_id, tenant_id, asset_id, scan_id,
		       trigger_type, triggered_by, status, context,
		       total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
		       started_at, completed_at, error_message,
		       scan_profile_id, quality_gate_result,
		       created_at
		FROM pipeline_runs
	`
}

func (r *PipelineRunRepository) buildWhereClause(filter pipeline.RunFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.PipelineID != nil {
		conditions = append(conditions, fmt.Sprintf("pipeline_id = $%d", argIndex))
		args = append(args, filter.PipelineID.String())
		argIndex++
	}

	if filter.AssetID != nil {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", argIndex))
		args = append(args, filter.AssetID.String())
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.TriggerType != nil {
		conditions = append(conditions, fmt.Sprintf("trigger_type = $%d", argIndex))
		args = append(args, string(*filter.TriggerType))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *PipelineRunRepository) scanRun(row *sql.Row) (*pipeline.Run, error) {
	run := &pipeline.Run{}
	var (
		id                string
		pipelineID        string
		tenantID          string
		assetID           sql.NullString
		scanID            sql.NullString
		triggerType       string
		status            string
		context           []byte
		startedAt         sql.NullTime
		completedAt       sql.NullTime
		scanProfileID     sql.NullString
		qualityGateResult []byte
	)

	err := row.Scan(
		&id,
		&pipelineID,
		&tenantID,
		&assetID,
		&scanID,
		&triggerType,
		&run.TriggeredBy,
		&status,
		&context,
		&run.TotalSteps,
		&run.CompletedSteps,
		&run.FailedSteps,
		&run.SkippedSteps,
		&run.TotalFindings,
		&startedAt,
		&completedAt,
		&run.ErrorMessage,
		&scanProfileID,
		&qualityGateResult,
		&run.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan pipeline run: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.PipelineID, _ = shared.IDFromString(pipelineID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = pipeline.TriggerType(triggerType)
	run.Status = pipeline.RunStatus(status)

	if assetID.Valid {
		aid, _ := shared.IDFromString(assetID.String)
		run.AssetID = &aid
	}

	if scanID.Valid {
		sid, _ := shared.IDFromString(scanID.String)
		run.ScanID = &sid
	}

	if scanProfileID.Valid {
		spid, _ := shared.IDFromString(scanProfileID.String)
		run.ScanProfileID = &spid
	}

	if startedAt.Valid {
		run.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		run.CompletedAt = &completedAt.Time
	}

	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}

	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			run.QualityGateResult = &qgr
		}
	}

	return run, nil
}

func (r *PipelineRunRepository) scanRunFromRows(rows *sql.Rows) (*pipeline.Run, error) {
	run := &pipeline.Run{}
	var (
		id                string
		pipelineID        string
		tenantID          string
		assetID           sql.NullString
		scanID            sql.NullString
		triggerType       string
		status            string
		context           []byte
		startedAt         sql.NullTime
		completedAt       sql.NullTime
		scanProfileID     sql.NullString
		qualityGateResult []byte
	)

	err := rows.Scan(
		&id,
		&pipelineID,
		&tenantID,
		&assetID,
		&scanID,
		&triggerType,
		&run.TriggeredBy,
		&status,
		&context,
		&run.TotalSteps,
		&run.CompletedSteps,
		&run.FailedSteps,
		&run.SkippedSteps,
		&run.TotalFindings,
		&startedAt,
		&completedAt,
		&run.ErrorMessage,
		&scanProfileID,
		&qualityGateResult,
		&run.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan pipeline run: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.PipelineID, _ = shared.IDFromString(pipelineID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = pipeline.TriggerType(triggerType)
	run.Status = pipeline.RunStatus(status)

	if assetID.Valid {
		aid, _ := shared.IDFromString(assetID.String)
		run.AssetID = &aid
	}

	if scanID.Valid {
		sid, _ := shared.IDFromString(scanID.String)
		run.ScanID = &sid
	}

	if scanProfileID.Valid {
		spid, _ := shared.IDFromString(scanProfileID.String)
		run.ScanProfileID = &spid
	}

	if startedAt.Valid {
		run.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		run.CompletedAt = &completedAt.Time
	}

	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}

	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			run.QualityGateResult = &qgr
		}
	}

	return run, nil
}

// GetStatsByTenant returns aggregated run statistics for a tenant in a single query.
// This is optimized to avoid N+1 queries when fetching stats.
func (r *PipelineRunRepository) GetStatsByTenant(ctx context.Context, tenantID shared.ID) (pipeline.RunStats, error) {
	var stats pipeline.RunStats

	// Single aggregation query - much more efficient than N queries
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status = 'running') as running,
			COUNT(*) FILTER (WHERE status = 'completed') as completed,
			COUNT(*) FILTER (WHERE status = 'failed' OR status = 'timeout') as failed,
			COUNT(*) FILTER (WHERE status = 'canceled') as canceled
		FROM pipeline_runs
		WHERE tenant_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Failed,
		&stats.Canceled,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to get pipeline run stats: %w", err)
	}

	return stats, nil
}

// StepRunRepository implements pipeline.StepRunRepository using PostgreSQL.
type StepRunRepository struct {
	db *DB
}

// NewStepRunRepository creates a new StepRunRepository.
func NewStepRunRepository(db *DB) *StepRunRepository {
	return &StepRunRepository{db: db}
}

// Create persists a new step run.
func (r *StepRunRepository) Create(ctx context.Context, sr *pipeline.StepRun) error {
	output, err := json.Marshal(sr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		INSERT INTO step_runs (
			id, pipeline_run_id, step_id, step_key, step_order, status,
			agent_id, command_id, condition_evaluated, condition_result, skip_reason,
			findings_count, output, attempt, max_attempts,
			queued_at, started_at, completed_at, error_message, error_code, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
	`

	_, err = r.db.ExecContext(ctx, query,
		sr.ID.String(),
		sr.PipelineRunID.String(),
		sr.StepID.String(),
		sr.StepKey,
		sr.StepOrder,
		string(sr.Status),
		nullID(sr.AgentID),
		nullID(sr.CommandID),
		sr.ConditionEvaluated,
		sr.ConditionResult,
		sr.SkipReason,
		sr.FindingsCount,
		output,
		sr.Attempt,
		sr.MaxAttempts,
		nullTime(sr.QueuedAt),
		nullTime(sr.StartedAt),
		nullTime(sr.CompletedAt),
		sr.ErrorMessage,
		sr.ErrorCode,
		sr.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create step run: %w", err)
	}

	return nil
}

// CreateBatch creates multiple step runs.
func (r *StepRunRepository) CreateBatch(ctx context.Context, stepRuns []*pipeline.StepRun) error {
	for _, sr := range stepRuns {
		if err := r.Create(ctx, sr); err != nil {
			return err
		}
	}
	return nil
}

// GetByID retrieves a step run by ID.
func (r *StepRunRepository) GetByID(ctx context.Context, id shared.ID) (*pipeline.StepRun, error) {
	query := r.selectQuery() + " WHERE id = $1"
	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get step run: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return r.scanStepRun(rows)
}

// GetByPipelineRunID retrieves all step runs for a pipeline run.
func (r *StepRunRepository) GetByPipelineRunID(ctx context.Context, pipelineRunID shared.ID) ([]*pipeline.StepRun, error) {
	query := r.selectQuery() + " WHERE pipeline_run_id = $1 ORDER BY step_order ASC"
	rows, err := r.db.QueryContext(ctx, query, pipelineRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*pipeline.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}

	return stepRuns, nil
}

// GetByStepKey retrieves a step run by pipeline run ID and step key.
func (r *StepRunRepository) GetByStepKey(ctx context.Context, pipelineRunID shared.ID, stepKey string) (*pipeline.StepRun, error) {
	query := r.selectQuery() + " WHERE pipeline_run_id = $1 AND step_key = $2"
	rows, err := r.db.QueryContext(ctx, query, pipelineRunID.String(), stepKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get step run: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return r.scanStepRun(rows)
}

// List lists step runs with filters.
func (r *StepRunRepository) List(ctx context.Context, filter pipeline.StepRunFilter) ([]*pipeline.StepRun, error) {
	query := r.selectQuery()
	var conditions []string
	var args []any
	argIndex := 1

	if filter.PipelineRunID != nil {
		conditions = append(conditions, fmt.Sprintf("pipeline_run_id = $%d", argIndex))
		args = append(args, filter.PipelineRunID.String())
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY step_order ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*pipeline.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}

	return stepRuns, nil
}

// Update updates a step run.
func (r *StepRunRepository) Update(ctx context.Context, sr *pipeline.StepRun) error {
	output, err := json.Marshal(sr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE step_runs
		SET status = $2, agent_id = $3, command_id = $4,
		    condition_evaluated = $5, condition_result = $6, skip_reason = $7,
		    findings_count = $8, output = $9, attempt = $10,
		    queued_at = $11, started_at = $12, completed_at = $13,
		    error_message = $14, error_code = $15
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		sr.ID.String(),
		string(sr.Status),
		nullID(sr.AgentID),
		nullID(sr.CommandID),
		sr.ConditionEvaluated,
		sr.ConditionResult,
		sr.SkipReason,
		sr.FindingsCount,
		output,
		sr.Attempt,
		nullTime(sr.QueuedAt),
		nullTime(sr.StartedAt),
		nullTime(sr.CompletedAt),
		sr.ErrorMessage,
		sr.ErrorCode,
	)

	if err != nil {
		return fmt.Errorf("failed to update step run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a step run.
func (r *StepRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM step_runs WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete step run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateStatus updates step run status.
func (r *StepRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status pipeline.StepRunStatus, errorMessage, errorCode string) error {
	query := `
		UPDATE step_runs
		SET status = $2, error_message = $3, error_code = $4,
		    completed_at = CASE WHEN $2 IN ('completed', 'failed', 'skipped', 'cancelled', 'timeout') THEN NOW() ELSE completed_at END
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage, errorCode)
	return err
}

// AssignAgent assigns an agent and command to a step run.
func (r *StepRunRepository) AssignAgent(ctx context.Context, id shared.ID, agentID, commandID shared.ID) error {
	query := `
		UPDATE step_runs
		SET agent_id = $2, command_id = $3, status = 'running', started_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), agentID.String(), commandID.String())
	return err
}

// Complete marks a step run as completed.
func (r *StepRunRepository) Complete(ctx context.Context, id shared.ID, findingsCount int, output map[string]any) error {
	outputJSON, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE step_runs
		SET status = 'completed', findings_count = $2, output = $3, completed_at = NOW()
		WHERE id = $1
	`
	_, err = r.db.ExecContext(ctx, query, id.String(), findingsCount, outputJSON)
	return err
}

// GetPendingByDependencies gets step runs that are pending and have their dependencies completed.
func (r *StepRunRepository) GetPendingByDependencies(ctx context.Context, pipelineRunID shared.ID, completedStepKeys []string) ([]*pipeline.StepRun, error) {
	// This is a simplified implementation. A more complex version would check dependencies.
	query := r.selectQuery() + " WHERE pipeline_run_id = $1 AND status = 'pending' ORDER BY step_order ASC"
	rows, err := r.db.QueryContext(ctx, query, pipelineRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get pending step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*pipeline.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}

	return stepRuns, nil
}

// GetStatsByTenant returns aggregated step run statistics for a tenant in a single query.
// Uses a JOIN to filter by tenant through the pipeline_runs table.
func (r *StepRunRepository) GetStatsByTenant(ctx context.Context, tenantID shared.ID) (pipeline.RunStats, error) {
	var stats pipeline.RunStats

	// Single aggregation query with JOIN - avoids N+1 queries
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE sr.status = 'pending') as pending,
			COUNT(*) FILTER (WHERE sr.status IN ('queued', 'running')) as running,
			COUNT(*) FILTER (WHERE sr.status = 'completed') as completed,
			COUNT(*) FILTER (WHERE sr.status IN ('failed', 'timeout')) as failed,
			COUNT(*) FILTER (WHERE sr.status IN ('canceled', 'skipped')) as canceled
		FROM step_runs sr
		JOIN pipeline_runs pr ON sr.pipeline_run_id = pr.id
		WHERE pr.tenant_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Failed,
		&stats.Canceled,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to get step run stats: %w", err)
	}

	return stats, nil
}

func (r *StepRunRepository) selectQuery() string {
	return `
		SELECT id, pipeline_run_id, step_id, step_key, step_order, status,
		       agent_id, command_id, condition_evaluated, condition_result, skip_reason,
		       findings_count, output, attempt, max_attempts,
		       queued_at, started_at, completed_at, error_message, error_code, created_at
		FROM step_runs
	`
}

func (r *StepRunRepository) scanStepRun(rows *sql.Rows) (*pipeline.StepRun, error) {
	sr := &pipeline.StepRun{}
	var (
		id              string
		pipelineRunID   string
		stepID          string
		status          string
		agentID         sql.NullString
		commandID       sql.NullString
		conditionResult sql.NullBool
		output          []byte
		queuedAt        sql.NullTime
		startedAt       sql.NullTime
		completedAt     sql.NullTime
	)

	err := rows.Scan(
		&id,
		&pipelineRunID,
		&stepID,
		&sr.StepKey,
		&sr.StepOrder,
		&status,
		&agentID,
		&commandID,
		&sr.ConditionEvaluated,
		&conditionResult,
		&sr.SkipReason,
		&sr.FindingsCount,
		&output,
		&sr.Attempt,
		&sr.MaxAttempts,
		&queuedAt,
		&startedAt,
		&completedAt,
		&sr.ErrorMessage,
		&sr.ErrorCode,
		&sr.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan step run: %w", err)
	}

	sr.ID, _ = shared.IDFromString(id)
	sr.PipelineRunID, _ = shared.IDFromString(pipelineRunID)
	sr.StepID, _ = shared.IDFromString(stepID)
	sr.Status = pipeline.StepRunStatus(status)

	if agentID.Valid {
		wid, _ := shared.IDFromString(agentID.String)
		sr.AgentID = &wid
	}
	if commandID.Valid {
		cid, _ := shared.IDFromString(commandID.String)
		sr.CommandID = &cid
	}
	if conditionResult.Valid {
		sr.ConditionResult = &conditionResult.Bool
	}
	if queuedAt.Valid {
		sr.QueuedAt = &queuedAt.Time
	}
	if startedAt.Valid {
		sr.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		sr.CompletedAt = &completedAt.Time
	}

	if len(output) > 0 {
		_ = json.Unmarshal(output, &sr.Output)
	}

	return sr, nil
}
