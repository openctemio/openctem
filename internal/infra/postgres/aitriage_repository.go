package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/aitriage"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AITriageRepository implements aitriage.Repository using PostgreSQL.
type AITriageRepository struct {
	db *DB
}

// NewAITriageRepository creates a new AITriageRepository.
func NewAITriageRepository(db *DB) *AITriageRepository {
	return &AITriageRepository{db: db}
}

// Create creates a new triage result.
func (r *AITriageRepository) Create(ctx context.Context, result *aitriage.TriageResult) error {
	remediationSteps, err := json.Marshal(result.RemediationSteps())
	if err != nil {
		return fmt.Errorf("failed to marshal remediation_steps: %w", err)
	}

	rawResponse, err := json.Marshal(result.RawResponse())
	if err != nil {
		return fmt.Errorf("failed to marshal raw_response: %w", err)
	}

	metadata, err := json.Marshal(result.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO ai_triage_results (
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17,
			$18, $19, $20,
			$21, $22, $23, $24,
			$25, $26, $27, $28,
			$29, $30, $31
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		result.ID(),
		result.TenantID(),
		result.FindingID(),
		result.TriageType(),
		nullID(result.RequestedBy()),
		result.RequestedAt(),
		result.Status(),
		nullTime(result.StartedAt()),
		nullTime(result.CompletedAt()),
		nullString(result.ErrorMessage()),
		nullString(result.LLMProvider()),
		nullString(result.LLMModel()),
		result.PromptTokens(),
		result.CompletionTokens(),
		nullString(result.SeverityAssessment()),
		nullString(result.SeverityJustification()),
		result.RiskScore(),
		nullableExploitability(result.Exploitability()),
		nullString(result.ExploitabilityDetails()),
		nullString(result.BusinessImpact()),
		result.PriorityRank(),
		remediationSteps,
		result.FalsePositiveLikelihood(),
		nullString(result.FalsePositiveReason()),
		pq.Array(result.RelatedCVEs()),
		pq.Array(result.RelatedCWEs()),
		rawResponse,
		nullString(result.AnalysisSummary()),
		metadata,
		result.CreatedAt(),
		result.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to create triage result: %w", err)
	}

	return nil
}

// Update updates an existing triage result.
func (r *AITriageRepository) Update(ctx context.Context, result *aitriage.TriageResult) error {
	remediationSteps, err := json.Marshal(result.RemediationSteps())
	if err != nil {
		return fmt.Errorf("failed to marshal remediation_steps: %w", err)
	}

	rawResponse, err := json.Marshal(result.RawResponse())
	if err != nil {
		return fmt.Errorf("failed to marshal raw_response: %w", err)
	}

	metadata, err := json.Marshal(result.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE ai_triage_results SET
			status = $1,
			started_at = $2,
			completed_at = $3,
			error_message = $4,
			llm_provider = $5,
			llm_model = $6,
			prompt_tokens = $7,
			completion_tokens = $8,
			severity_assessment = $9,
			severity_justification = $10,
			risk_score = $11,
			exploitability = $12,
			exploitability_details = $13,
			business_impact = $14,
			priority_rank = $15,
			remediation_steps = $16,
			false_positive_likelihood = $17,
			false_positive_reason = $18,
			related_cves = $19,
			related_cwes = $20,
			raw_response = $21,
			analysis_summary = $22,
			metadata = $23,
			updated_at = $24
		WHERE id = $25 AND tenant_id = $26
	`

	res, err := r.db.ExecContext(ctx, query,
		result.Status(),
		nullTime(result.StartedAt()),
		nullTime(result.CompletedAt()),
		nullString(result.ErrorMessage()),
		nullString(result.LLMProvider()),
		nullString(result.LLMModel()),
		result.PromptTokens(),
		result.CompletionTokens(),
		nullString(result.SeverityAssessment()),
		nullString(result.SeverityJustification()),
		result.RiskScore(),
		nullableExploitability(result.Exploitability()),
		nullString(result.ExploitabilityDetails()),
		nullString(result.BusinessImpact()),
		result.PriorityRank(),
		remediationSteps,
		result.FalsePositiveLikelihood(),
		nullString(result.FalsePositiveReason()),
		pq.Array(result.RelatedCVEs()),
		pq.Array(result.RelatedCWEs()),
		rawResponse,
		nullString(result.AnalysisSummary()),
		metadata,
		result.UpdatedAt(),
		result.ID(),
		result.TenantID(),
	)

	if err != nil {
		return fmt.Errorf("failed to update triage result: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetByID retrieves a triage result by ID.
func (r *AITriageRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*aitriage.TriageResult, error) {
	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE id = $1 AND tenant_id = $2
	`

	return r.scanOne(r.db.QueryRowContext(ctx, query, id, tenantID))
}

// GetByFindingID retrieves the latest triage result for a finding.
func (r *AITriageRepository) GetByFindingID(ctx context.Context, tenantID, findingID shared.ID) (*aitriage.TriageResult, error) {
	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE finding_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	return r.scanOne(r.db.QueryRowContext(ctx, query, findingID, tenantID))
}

// ListByFindingID retrieves all triage results for a finding (history).
func (r *AITriageRepository) ListByFindingID(ctx context.Context, tenantID, findingID shared.ID, limit, offset int) ([]*aitriage.TriageResult, int, error) {
	countQuery := `
		SELECT COUNT(*) FROM ai_triage_results
		WHERE finding_id = $1 AND tenant_id = $2
	`

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, findingID, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count triage results: %w", err)
	}

	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE finding_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := r.db.QueryContext(ctx, query, findingID, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list triage results: %w", err)
	}
	defer rows.Close()

	results, err := r.scanMany(rows)
	if err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

// GetPendingJobs retrieves pending triage jobs for processing.
// SECURITY: Orders by tenant_id to group jobs by tenant for proper isolation.
// Workers should process results grouped by tenant_id to prevent cross-tenant leakage.
// Consider using GetPendingJobsByTenant for better isolation.
func (r *AITriageRepository) GetPendingJobs(ctx context.Context, limit int) ([]*aitriage.TriageResult, error) {
	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE status = 'pending'
		ORDER BY tenant_id ASC, requested_at ASC
		LIMIT $1
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending jobs: %w", err)
	}
	defer rows.Close()

	return r.scanMany(rows)
}

// GetPendingJobsByTenant retrieves pending triage jobs for a specific tenant.
// SECURITY: This is the preferred method - ensures proper tenant isolation.
func (r *AITriageRepository) GetPendingJobsByTenant(ctx context.Context, tenantID shared.ID, limit int) ([]*aitriage.TriageResult, error) {
	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY requested_at ASC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending jobs for tenant: %w", err)
	}
	defer rows.Close()

	return r.scanMany(rows)
}

// GetTenantsWithPendingJobs returns tenant IDs that have pending triage jobs.
// SECURITY: Use this to iterate tenants, then call GetPendingJobsByTenant for each.
func (r *AITriageRepository) GetTenantsWithPendingJobs(ctx context.Context, limit int) ([]shared.ID, error) {
	query := `
		SELECT DISTINCT tenant_id
		FROM ai_triage_results
		WHERE status = 'pending'
		LIMIT $1
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants with pending jobs: %w", err)
	}
	defer rows.Close()

	var tenantIDs []shared.ID
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("failed to scan tenant id: %w", err)
		}
		tenantIDs = append(tenantIDs, tenantID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return tenantIDs, nil
}

// CountByTenantThisMonth counts triage jobs for token usage tracking.
// Uses UTC timezone for consistent month boundaries across all regions.
func (r *AITriageRepository) CountByTenantThisMonth(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM ai_triage_results
		WHERE tenant_id = $1
		  AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
		  AND status = 'completed'
	`

	var count int
	if err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count triage results: %w", err)
	}

	return count, nil
}

// SumTokensByTenantThisMonth sums tokens used this month.
// Uses UTC timezone for consistent month boundaries across all regions.
func (r *AITriageRepository) SumTokensByTenantThisMonth(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0)
		FROM ai_triage_results
		WHERE tenant_id = $1
		  AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
		  AND status = 'completed'
	`

	var sum int
	if err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&sum); err != nil {
		return 0, fmt.Errorf("failed to sum tokens: %w", err)
	}

	return sum, nil
}

// HasPendingOrProcessing checks if a finding has a pending or processing triage job.
// Used for deduplication to prevent multiple concurrent triage requests for the same finding.
func (r *AITriageRepository) HasPendingOrProcessing(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM ai_triage_results
			WHERE tenant_id = $1
			  AND finding_id = $2
			  AND status IN ('pending', 'processing')
		)
	`

	var exists bool
	if err := r.db.QueryRowContext(ctx, query, tenantID, findingID).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check pending/processing jobs: %w", err)
	}

	return exists, nil
}

// =============================================================================
// Scan Helpers
// =============================================================================

func (r *AITriageRepository) scanOne(row *sql.Row) (*aitriage.TriageResult, error) {
	var (
		id                      shared.ID
		tenantID                shared.ID
		findingID               shared.ID
		triageType              string
		requestedBy             sql.NullString
		requestedAt             time.Time
		status                  string
		startedAt               sql.NullTime
		completedAt             sql.NullTime
		errorMessage            sql.NullString
		llmProvider             sql.NullString
		llmModel                sql.NullString
		promptTokens            int
		completionTokens        int
		severityAssessment      sql.NullString
		severityJustification   sql.NullString
		riskScore               sql.NullFloat64
		exploitability          sql.NullString
		exploitabilityDetails   sql.NullString
		businessImpact          sql.NullString
		priorityRank            sql.NullInt32
		remediationStepsJSON    []byte
		falsePositiveLikelihood sql.NullFloat64
		falsePositiveReason     sql.NullString
		relatedCVEs             pq.StringArray
		relatedCWEs             pq.StringArray
		rawResponseJSON         []byte
		analysisSummary         sql.NullString
		metadataJSON            []byte
		createdAt               time.Time
		updatedAt               time.Time
	)

	err := row.Scan(
		&id, &tenantID, &findingID,
		&triageType, &requestedBy, &requestedAt,
		&status, &startedAt, &completedAt, &errorMessage,
		&llmProvider, &llmModel, &promptTokens, &completionTokens,
		&severityAssessment, &severityJustification, &riskScore,
		&exploitability, &exploitabilityDetails, &businessImpact,
		&priorityRank, &remediationStepsJSON, &falsePositiveLikelihood, &falsePositiveReason,
		&relatedCVEs, &relatedCWEs, &rawResponseJSON, &analysisSummary,
		&metadataJSON, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan triage result: %w", err)
	}

	// Parse JSON fields
	var remediationSteps []aitriage.RemediationStep
	if len(remediationStepsJSON) > 0 {
		_ = json.Unmarshal(remediationStepsJSON, &remediationSteps)
	}

	var rawResponse map[string]any
	if len(rawResponseJSON) > 0 {
		_ = json.Unmarshal(rawResponseJSON, &rawResponse)
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &metadata)
	}

	// Convert nullable values
	var requestedByPtr *shared.ID
	if requestedBy.Valid {
		id := shared.MustIDFromString(requestedBy.String)
		requestedByPtr = &id
	}

	var startedAtPtr *time.Time
	if startedAt.Valid {
		startedAtPtr = &startedAt.Time
	}

	var completedAtPtr *time.Time
	if completedAt.Valid {
		completedAtPtr = &completedAt.Time
	}

	return aitriage.Reconstitute(
		id, tenantID, findingID,
		aitriage.TriageType(triageType),
		requestedByPtr,
		requestedAt,
		aitriage.TriageStatus(status),
		startedAtPtr, completedAtPtr,
		nullStringValue(errorMessage),
		nullStringValue(llmProvider),
		nullStringValue(llmModel),
		promptTokens, completionTokens,
		nullStringValue(severityAssessment),
		nullStringValue(severityJustification),
		nullFloatValue(riskScore),
		aitriage.Exploitability(nullStringValue(exploitability)),
		nullStringValue(exploitabilityDetails),
		nullStringValue(businessImpact),
		nullIntValue(priorityRank),
		remediationSteps,
		nullFloatValue(falsePositiveLikelihood),
		nullStringValue(falsePositiveReason),
		[]string(relatedCVEs),
		[]string(relatedCWEs),
		rawResponse,
		nullStringValue(analysisSummary),
		metadata,
		createdAt, updatedAt,
	), nil
}

func (r *AITriageRepository) scanMany(rows *sql.Rows) ([]*aitriage.TriageResult, error) {
	var results []*aitriage.TriageResult
	for rows.Next() {
		var (
			id                      shared.ID
			tenantID                shared.ID
			findingID               shared.ID
			triageType              string
			requestedBy             sql.NullString
			requestedAt             time.Time
			status                  string
			startedAt               sql.NullTime
			completedAt             sql.NullTime
			errorMessage            sql.NullString
			llmProvider             sql.NullString
			llmModel                sql.NullString
			promptTokens            int
			completionTokens        int
			severityAssessment      sql.NullString
			severityJustification   sql.NullString
			riskScore               sql.NullFloat64
			exploitability          sql.NullString
			exploitabilityDetails   sql.NullString
			businessImpact          sql.NullString
			priorityRank            sql.NullInt32
			remediationStepsJSON    []byte
			falsePositiveLikelihood sql.NullFloat64
			falsePositiveReason     sql.NullString
			relatedCVEs             pq.StringArray
			relatedCWEs             pq.StringArray
			rawResponseJSON         []byte
			analysisSummary         sql.NullString
			metadataJSON            []byte
			createdAt               time.Time
			updatedAt               time.Time
		)

		err := rows.Scan(
			&id, &tenantID, &findingID,
			&triageType, &requestedBy, &requestedAt,
			&status, &startedAt, &completedAt, &errorMessage,
			&llmProvider, &llmModel, &promptTokens, &completionTokens,
			&severityAssessment, &severityJustification, &riskScore,
			&exploitability, &exploitabilityDetails, &businessImpact,
			&priorityRank, &remediationStepsJSON, &falsePositiveLikelihood, &falsePositiveReason,
			&relatedCVEs, &relatedCWEs, &rawResponseJSON, &analysisSummary,
			&metadataJSON, &createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan triage result: %w", err)
		}

		// Parse JSON fields
		var remediationSteps []aitriage.RemediationStep
		if len(remediationStepsJSON) > 0 {
			_ = json.Unmarshal(remediationStepsJSON, &remediationSteps)
		}

		var rawResponse map[string]any
		if len(rawResponseJSON) > 0 {
			_ = json.Unmarshal(rawResponseJSON, &rawResponse)
		}

		var metadata map[string]any
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &metadata)
		}

		// Convert nullable values
		var requestedByPtr *shared.ID
		if requestedBy.Valid {
			id := shared.MustIDFromString(requestedBy.String)
			requestedByPtr = &id
		}

		var startedAtPtr *time.Time
		if startedAt.Valid {
			startedAtPtr = &startedAt.Time
		}

		var completedAtPtr *time.Time
		if completedAt.Valid {
			completedAtPtr = &completedAt.Time
		}

		result := aitriage.Reconstitute(
			id, tenantID, findingID,
			aitriage.TriageType(triageType),
			requestedByPtr,
			requestedAt,
			aitriage.TriageStatus(status),
			startedAtPtr, completedAtPtr,
			nullStringValue(errorMessage),
			nullStringValue(llmProvider),
			nullStringValue(llmModel),
			promptTokens, completionTokens,
			nullStringValue(severityAssessment),
			nullStringValue(severityJustification),
			nullFloatValue(riskScore),
			aitriage.Exploitability(nullStringValue(exploitability)),
			nullStringValue(exploitabilityDetails),
			nullStringValue(businessImpact),
			nullIntValue(priorityRank),
			remediationSteps,
			nullFloatValue(falsePositiveLikelihood),
			nullStringValue(falsePositiveReason),
			[]string(relatedCVEs),
			[]string(relatedCWEs),
			rawResponse,
			nullStringValue(analysisSummary),
			metadata,
			createdAt, updatedAt,
		)

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return results, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func nullableExploitability(e aitriage.Exploitability) any {
	if e == "" {
		return nil
	}
	return string(e)
}

func nullIntValue(n sql.NullInt32) int {
	if n.Valid {
		return int(n.Int32)
	}
	return 0
}

func nullFloatValue(n sql.NullFloat64) float64 {
	if n.Valid {
		return n.Float64
	}
	return 0
}

// AcquireTriageSlot atomically checks token limit and reserves a slot for processing.
// Uses SELECT FOR UPDATE to prevent race conditions when multiple workers process concurrently.
// This method:
// 1. Locks the triage result row with FOR UPDATE
// 2. Checks if status is 'pending' (not already processing)
// 3. Calculates current token usage with locking
// 4. Checks against monthly token limit
// 5. Updates status to 'processing' atomically
// Returns the triage context if slot acquired, or appropriate error.
func (r *AITriageRepository) AcquireTriageSlot(ctx context.Context, tenantID, resultID shared.ID) (*aitriage.TriageContext, error) {
	// Start a transaction for atomic operations
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Query with FOR UPDATE to lock the row and prevent concurrent processing
	// Also get tenant settings and token usage in same query
	query := `
		WITH token_usage AS (
			SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0) as total_tokens
			FROM ai_triage_results
			WHERE tenant_id = $1
			  AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
			  AND status = 'completed'
		)
		SELECT
			tr.id, tr.tenant_id, tr.finding_id,
			tr.triage_type, tr.requested_by, tr.requested_at,
			tr.status, tr.started_at, tr.completed_at, tr.error_message,
			tr.llm_provider, tr.llm_model, tr.prompt_tokens, tr.completion_tokens,
			tr.severity_assessment, tr.severity_justification, tr.risk_score,
			tr.exploitability, tr.exploitability_details, tr.business_impact,
			tr.priority_rank, tr.remediation_steps, tr.false_positive_likelihood, tr.false_positive_reason,
			tr.related_cves, tr.related_cwes, tr.raw_response, tr.analysis_summary,
			tr.metadata, tr.created_at, tr.updated_at,
			t.settings as tenant_settings,
			tu.total_tokens as tokens_used_month
		FROM ai_triage_results tr
		JOIN tenants t ON t.id = tr.tenant_id
		CROSS JOIN token_usage tu
		WHERE tr.id = $2 AND tr.tenant_id = $1
		FOR UPDATE OF tr
	`

	var (
		id                      shared.ID
		tenantIDResult          shared.ID
		findingID               shared.ID
		triageType              string
		requestedBy             sql.NullString
		requestedAt             time.Time
		status                  string
		startedAt               sql.NullTime
		completedAt             sql.NullTime
		errorMessage            sql.NullString
		llmProvider             sql.NullString
		llmModel                sql.NullString
		promptTokens            int
		completionTokens        int
		severityAssessment      sql.NullString
		severityJustification   sql.NullString
		riskScore               sql.NullFloat64
		exploitability          sql.NullString
		exploitabilityDetails   sql.NullString
		businessImpact          sql.NullString
		priorityRank            sql.NullInt32
		remediationStepsJSON    []byte
		falsePositiveLikelihood sql.NullFloat64
		falsePositiveReason     sql.NullString
		relatedCVEs             pq.StringArray
		relatedCWEs             pq.StringArray
		rawResponseJSON         []byte
		analysisSummary         sql.NullString
		metadataJSON            []byte
		createdAt               time.Time
		updatedAt               time.Time
		tenantSettingsJSON      []byte
		tokensUsedMonth         int
	)

	err = tx.QueryRowContext(ctx, query, tenantID, resultID).Scan(
		&id, &tenantIDResult, &findingID,
		&triageType, &requestedBy, &requestedAt,
		&status, &startedAt, &completedAt, &errorMessage,
		&llmProvider, &llmModel, &promptTokens, &completionTokens,
		&severityAssessment, &severityJustification, &riskScore,
		&exploitability, &exploitabilityDetails, &businessImpact,
		&priorityRank, &remediationStepsJSON, &falsePositiveLikelihood, &falsePositiveReason,
		&relatedCVEs, &relatedCWEs, &rawResponseJSON, &analysisSummary,
		&metadataJSON, &createdAt, &updatedAt,
		&tenantSettingsJSON,
		&tokensUsedMonth,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lock triage result: %w", err)
	}

	// Check if already processing or completed
	if status != "pending" {
		err = aitriage.ErrAlreadyProcessing
		return nil, err
	}

	// Parse tenant settings to check token limit
	var tenantSettings map[string]any
	if len(tenantSettingsJSON) > 0 {
		_ = json.Unmarshal(tenantSettingsJSON, &tenantSettings)
	}

	// Extract monthly token limit
	var monthlyLimit int
	if aiSettings, ok := tenantSettings["ai"].(map[string]any); ok {
		if limit, ok := aiSettings["monthly_token_limit"].(float64); ok {
			monthlyLimit = int(limit)
		}
	}

	// Check token limit
	if monthlyLimit > 0 && tokensUsedMonth >= monthlyLimit {
		err = aitriage.ErrTokenLimitExceeded
		return nil, err
	}

	// Update status to 'processing' atomically
	now := time.Now().UTC()
	updateQuery := `
		UPDATE ai_triage_results
		SET status = 'processing', started_at = $1, updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`
	_, err = tx.ExecContext(ctx, updateQuery, now, resultID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to update status: %w", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Parse remaining JSON fields for triage result
	var remediationSteps []aitriage.RemediationStep
	if len(remediationStepsJSON) > 0 {
		_ = json.Unmarshal(remediationStepsJSON, &remediationSteps)
	}

	var rawResponse map[string]any
	if len(rawResponseJSON) > 0 {
		_ = json.Unmarshal(rawResponseJSON, &rawResponse)
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &metadata)
	}

	// Convert nullable values
	var requestedByPtr *shared.ID
	if requestedBy.Valid {
		parsedID := shared.MustIDFromString(requestedBy.String)
		requestedByPtr = &parsedID
	}

	// Status was updated to 'processing', reflect that
	result := aitriage.Reconstitute(
		id, tenantIDResult, findingID,
		aitriage.TriageType(triageType),
		requestedByPtr,
		requestedAt,
		aitriage.TriageStatusProcessing, // Updated status
		&now, nil,                       // started_at = now, completed_at = nil
		nullStringValue(errorMessage),
		nullStringValue(llmProvider),
		nullStringValue(llmModel),
		promptTokens, completionTokens,
		nullStringValue(severityAssessment),
		nullStringValue(severityJustification),
		nullFloatValue(riskScore),
		aitriage.Exploitability(nullStringValue(exploitability)),
		nullStringValue(exploitabilityDetails),
		nullStringValue(businessImpact),
		nullIntValue(priorityRank),
		remediationSteps,
		nullFloatValue(falsePositiveLikelihood),
		nullStringValue(falsePositiveReason),
		[]string(relatedCVEs),
		[]string(relatedCWEs),
		rawResponse,
		nullStringValue(analysisSummary),
		metadata,
		createdAt, now,
	)

	return &aitriage.TriageContext{
		Result:            result,
		TenantSettings:    tenantSettings,
		TokensUsedMonth:   tokensUsedMonth,
		MonthlyTokenLimit: monthlyLimit,
	}, nil
}

// FindStuckJobs finds triage jobs that have been in pending/processing state for too long.
// Used by recovery job to mark them as failed.
// stuckDuration: how long a job must be stuck before being considered for recovery.
func (r *AITriageRepository) FindStuckJobs(ctx context.Context, stuckDuration time.Duration, limit int) ([]*aitriage.TriageResult, error) {
	query := `
		SELECT
			id, tenant_id, finding_id,
			triage_type, requested_by, requested_at,
			status, started_at, completed_at, error_message,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			severity_assessment, severity_justification, risk_score,
			exploitability, exploitability_details, business_impact,
			priority_rank, remediation_steps, false_positive_likelihood, false_positive_reason,
			related_cves, related_cwes, raw_response, analysis_summary,
			metadata, created_at, updated_at
		FROM ai_triage_results
		WHERE status IN ('pending', 'processing')
		  AND (
		    (status = 'pending' AND requested_at < NOW() - $1::interval)
		    OR (status = 'processing' AND started_at < NOW() - $1::interval)
		  )
		ORDER BY requested_at ASC
		LIMIT $2
	`

	// Convert duration to PostgreSQL interval string
	intervalStr := fmt.Sprintf("%d seconds", int(stuckDuration.Seconds()))

	rows, err := r.db.QueryContext(ctx, query, intervalStr, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to find stuck jobs: %w", err)
	}
	defer rows.Close()

	return r.scanMany(rows)
}

// MarkStuckAsFailed marks a stuck triage job as failed.
// Returns true if the job was updated, false if it was already in a terminal state.
func (r *AITriageRepository) MarkStuckAsFailed(ctx context.Context, id shared.ID, errorMessage string) (bool, error) {
	now := time.Now().UTC()

	query := `
		UPDATE ai_triage_results
		SET status = 'failed',
		    error_message = $1,
		    completed_at = $2,
		    updated_at = $2
		WHERE id = $3
		  AND status IN ('pending', 'processing')
	`

	result, err := r.db.ExecContext(ctx, query, errorMessage, now, id)
	if err != nil {
		return false, fmt.Errorf("failed to mark job as failed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// GetTriageContext retrieves triage result with tenant settings and token usage in one optimized query.
// Uses UTC timezone for consistent month boundaries across all regions.
func (r *AITriageRepository) GetTriageContext(ctx context.Context, tenantID, resultID shared.ID) (*aitriage.TriageContext, error) {
	query := `
		WITH token_usage AS (
			SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0) as total_tokens
			FROM ai_triage_results
			WHERE tenant_id = $1
			  AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
			  AND status = 'completed'
		)
		SELECT
			tr.id, tr.tenant_id, tr.finding_id,
			tr.triage_type, tr.requested_by, tr.requested_at,
			tr.status, tr.started_at, tr.completed_at, tr.error_message,
			tr.llm_provider, tr.llm_model, tr.prompt_tokens, tr.completion_tokens,
			tr.severity_assessment, tr.severity_justification, tr.risk_score,
			tr.exploitability, tr.exploitability_details, tr.business_impact,
			tr.priority_rank, tr.remediation_steps, tr.false_positive_likelihood, tr.false_positive_reason,
			tr.related_cves, tr.related_cwes, tr.raw_response, tr.analysis_summary,
			tr.metadata, tr.created_at, tr.updated_at,
			t.settings as tenant_settings,
			tu.total_tokens as tokens_used_month
		FROM ai_triage_results tr
		JOIN tenants t ON t.id = tr.tenant_id
		CROSS JOIN token_usage tu
		WHERE tr.id = $2 AND tr.tenant_id = $1
	`

	var (
		id                      shared.ID
		tenantIDResult          shared.ID
		findingID               shared.ID
		triageType              string
		requestedBy             sql.NullString
		requestedAt             time.Time
		status                  string
		startedAt               sql.NullTime
		completedAt             sql.NullTime
		errorMessage            sql.NullString
		llmProvider             sql.NullString
		llmModel                sql.NullString
		promptTokens            int
		completionTokens        int
		severityAssessment      sql.NullString
		severityJustification   sql.NullString
		riskScore               sql.NullFloat64
		exploitability          sql.NullString
		exploitabilityDetails   sql.NullString
		businessImpact          sql.NullString
		priorityRank            sql.NullInt32
		remediationStepsJSON    []byte
		falsePositiveLikelihood sql.NullFloat64
		falsePositiveReason     sql.NullString
		relatedCVEs             pq.StringArray
		relatedCWEs             pq.StringArray
		rawResponseJSON         []byte
		analysisSummary         sql.NullString
		metadataJSON            []byte
		createdAt               time.Time
		updatedAt               time.Time
		tenantSettingsJSON      []byte
		tokensUsedMonth         int
	)

	err := r.db.QueryRowContext(ctx, query, tenantID, resultID).Scan(
		&id, &tenantIDResult, &findingID,
		&triageType, &requestedBy, &requestedAt,
		&status, &startedAt, &completedAt, &errorMessage,
		&llmProvider, &llmModel, &promptTokens, &completionTokens,
		&severityAssessment, &severityJustification, &riskScore,
		&exploitability, &exploitabilityDetails, &businessImpact,
		&priorityRank, &remediationStepsJSON, &falsePositiveLikelihood, &falsePositiveReason,
		&relatedCVEs, &relatedCWEs, &rawResponseJSON, &analysisSummary,
		&metadataJSON, &createdAt, &updatedAt,
		&tenantSettingsJSON,
		&tokensUsedMonth,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get triage context: %w", err)
	}

	// Parse JSON fields for triage result
	var remediationSteps []aitriage.RemediationStep
	if len(remediationStepsJSON) > 0 {
		_ = json.Unmarshal(remediationStepsJSON, &remediationSteps)
	}

	var rawResponse map[string]any
	if len(rawResponseJSON) > 0 {
		_ = json.Unmarshal(rawResponseJSON, &rawResponse)
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &metadata)
	}

	// Parse tenant settings
	var tenantSettings map[string]any
	if len(tenantSettingsJSON) > 0 {
		_ = json.Unmarshal(tenantSettingsJSON, &tenantSettings)
	}

	// Convert nullable values
	var requestedByPtr *shared.ID
	if requestedBy.Valid {
		parsedID := shared.MustIDFromString(requestedBy.String)
		requestedByPtr = &parsedID
	}

	var startedAtPtr *time.Time
	if startedAt.Valid {
		startedAtPtr = &startedAt.Time
	}

	var completedAtPtr *time.Time
	if completedAt.Valid {
		completedAtPtr = &completedAt.Time
	}

	result := aitriage.Reconstitute(
		id, tenantIDResult, findingID,
		aitriage.TriageType(triageType),
		requestedByPtr,
		requestedAt,
		aitriage.TriageStatus(status),
		startedAtPtr, completedAtPtr,
		nullStringValue(errorMessage),
		nullStringValue(llmProvider),
		nullStringValue(llmModel),
		promptTokens, completionTokens,
		nullStringValue(severityAssessment),
		nullStringValue(severityJustification),
		nullFloatValue(riskScore),
		aitriage.Exploitability(nullStringValue(exploitability)),
		nullStringValue(exploitabilityDetails),
		nullStringValue(businessImpact),
		nullIntValue(priorityRank),
		remediationSteps,
		nullFloatValue(falsePositiveLikelihood),
		nullStringValue(falsePositiveReason),
		[]string(relatedCVEs),
		[]string(relatedCWEs),
		rawResponse,
		nullStringValue(analysisSummary),
		metadata,
		createdAt, updatedAt,
	)

	// Extract monthly token limit from tenant settings
	var monthlyLimit int
	if aiSettings, ok := tenantSettings["ai"].(map[string]any); ok {
		if limit, ok := aiSettings["monthly_token_limit"].(float64); ok {
			monthlyLimit = int(limit)
		}
	}

	return &aitriage.TriageContext{
		Result:            result,
		TenantSettings:    tenantSettings,
		TokensUsedMonth:   tokensUsedMonth,
		MonthlyTokenLimit: monthlyLimit,
	}, nil
}
