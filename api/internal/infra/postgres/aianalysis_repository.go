package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIAnalysisRepository implements aianalysis.Repository (docs/architecture/ai-analysis.md).
// Every query filters on tenant_id.
type AIAnalysisRepository struct {
	db *DB
}

// NewAIAnalysisRepository creates the repository.
func NewAIAnalysisRepository(db *DB) *AIAnalysisRepository {
	return &AIAnalysisRepository{db: db}
}

var _ aianalysis.Repository = (*AIAnalysisRepository)(nil)

const aiRunColumns = `id, tenant_id, use_case, kind, subject_type, subject_id, executor, status, data_class,
	fields_sent, fields_withheld, COALESCE(bundle_digest, ''), COALESCE(prompt_template_id, ''),
	COALESCE(prompt_template_digest, ''), COALESCE(output_schema, ''), COALESCE(provider, ''), COALESCE(model, ''),
	tokens_in, tokens_out, cost_micro_usd, duration_ms, COALESCE(error_code, ''), requested_by, trigger,
	started_at, completed_at, created_at`

// CreateRun inserts a run. A second in-flight run for the same use case and
// subject is ErrRunInFlight.
func (r *AIAnalysisRepository) CreateRun(ctx context.Context, run *aianalysis.Run) error {
	if run.ID.IsZero() {
		run.ID = shared.NewID()
	}
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO ai_runs (id, tenant_id, use_case, kind, subject_type, subject_id, executor, status, data_class,
			fields_sent, fields_withheld, bundle_digest, prompt_template_id, prompt_template_digest, output_schema,
			provider, model, tokens_in, tokens_out, cost_micro_usd, duration_ms, error_code, requested_by, trigger,
			started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
			$22, $23, $24, $25, $26)
		RETURNING created_at`,
		run.ID, run.TenantID, run.UseCase, run.Kind, run.SubjectType, run.SubjectID, run.Executor, run.Status,
		run.DataClass, pq.Array(nonNil(run.FieldsSent)), pq.Array(nonNil(run.FieldsWithheld)), nullStr(run.BundleDigest),
		nullStr(run.PromptTemplateID), nullStr(run.PromptTemplateDigest), nullStr(run.OutputSchema),
		nullStr(run.Provider), nullStr(run.Model), run.TokensIn, run.TokensOut, run.CostMicroUSD,
		nullIntPtr(run.DurationMS), nullStr(run.ErrorCode), nullID(run.RequestedBy), run.Trigger,
		nullTime(run.StartedAt), nullTime(run.CompletedAt),
	).Scan(&run.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return aianalysis.ErrRunInFlight
		}
		return fmt.Errorf("insert ai run: %w", err)
	}
	return nil
}

// UpdateRun stores the outcome and provenance of a run.
func (r *AIAnalysisRepository) UpdateRun(ctx context.Context, run *aianalysis.Run) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ai_runs SET status = $3, data_class = $4, fields_sent = $5, fields_withheld = $6,
			bundle_digest = $7, prompt_template_id = $8, prompt_template_digest = $9, output_schema = $10,
			provider = $11, model = $12, tokens_in = $13, tokens_out = $14, cost_micro_usd = $15,
			duration_ms = $16, error_code = $17, started_at = $18, completed_at = $19, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		run.TenantID, run.ID, run.Status, run.DataClass, pq.Array(nonNil(run.FieldsSent)),
		pq.Array(nonNil(run.FieldsWithheld)), nullStr(run.BundleDigest), nullStr(run.PromptTemplateID),
		nullStr(run.PromptTemplateDigest), nullStr(run.OutputSchema), nullStr(run.Provider), nullStr(run.Model),
		run.TokensIn, run.TokensOut, run.CostMicroUSD, nullIntPtr(run.DurationMS), nullStr(run.ErrorCode),
		nullTime(run.StartedAt), nullTime(run.CompletedAt))
	if err != nil {
		return fmt.Errorf("update ai run: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aianalysis.ErrRunNotFound
	}
	return nil
}

// GetRun reads one run of the tenant.
func (r *AIAnalysisRepository) GetRun(ctx context.Context, tenantID, id shared.ID) (*aianalysis.Run, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	run, err := scanAIRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aianalysis.ErrRunNotFound
	}
	return run, err
}

func scanAIRun(row rowScanner) (*aianalysis.Run, error) {
	var (
		run         aianalysis.Run
		duration    sql.NullInt64
		requestedBy sql.NullString
		started     sql.NullTime
		completed   sql.NullTime
		sent        pq.StringArray
		withheld    pq.StringArray
	)
	if err := row.Scan(&run.ID, &run.TenantID, &run.UseCase, &run.Kind, &run.SubjectType, &run.SubjectID,
		&run.Executor, &run.Status, &run.DataClass, &sent, &withheld, &run.BundleDigest, &run.PromptTemplateID,
		&run.PromptTemplateDigest, &run.OutputSchema, &run.Provider, &run.Model, &run.TokensIn, &run.TokensOut,
		&run.CostMicroUSD, &duration, &run.ErrorCode, &requestedBy, &run.Trigger, &started, &completed,
		&run.CreatedAt); err != nil {
		return nil, err
	}
	run.FieldsSent, run.FieldsWithheld = sent, withheld
	if duration.Valid {
		d := int(duration.Int64)
		run.DurationMS = &d
	}
	run.RequestedBy = nullIDFromString(requestedBy)
	run.StartedAt = nullTimeValue(started)
	run.CompletedAt = nullTimeValue(completed)
	return &run, nil
}

func nullIDFromString(ns sql.NullString) *shared.ID {
	if !ns.Valid {
		return nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil
	}
	return &id
}

const aiSuggestionColumns = `id, tenant_id, run_id, use_case, subject_type, subject_id, kind, payload, schema_version,
	direction, confidence, evidence, state, review_reasons, previous_value, applied_by, applied_at,
	COALESCE(approval_kind, ''), approval_id, undone_by, undone_at, decided_by, decided_at, created_at, updated_at`

// CreateSuggestions inserts a run's suggestions and supersedes the earlier
// open suggestions of the same kind for the same subject.
func (r *AIAnalysisRepository) CreateSuggestions(ctx context.Context, tenantID shared.ID, items []*aianalysis.Suggestion) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range items {
		if s.TenantID != tenantID {
			return fmt.Errorf("%w: suggestion of another tenant", shared.ErrValidation)
		}
		if s.ID.IsZero() {
			s.ID = shared.NewID()
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE ai_suggestions SET state = 'superseded', updated_at = now()
			WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND kind = $4
			  AND state IN ('open', 'needs_review') AND run_id <> $5`,
			tenantID, s.SubjectType, s.SubjectID, s.Kind, s.RunID); err != nil {
			return fmt.Errorf("supersede ai suggestions: %w", err)
		}
		evidence, err := json.Marshal(s.Evidence)
		if err != nil {
			return fmt.Errorf("marshal evidence: %w", err)
		}
		if s.Evidence == nil {
			evidence = []byte("[]")
		}
		var conf sql.NullFloat64
		if s.Confidence != nil {
			conf = sql.NullFloat64{Float64: *s.Confidence, Valid: true}
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ai_suggestions (id, tenant_id, run_id, use_case, subject_type, subject_id, kind, payload,
				schema_version, direction, confidence, evidence, state, review_reasons)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			RETURNING created_at, updated_at`,
			s.ID, tenantID, s.RunID, s.UseCase, s.SubjectType, s.SubjectID, s.Kind, []byte(s.Payload),
			s.SchemaVersion, s.Direction, conf, evidence, s.State, pq.Array(nonNil(s.ReviewReasons)),
		).Scan(&s.CreatedAt, &s.UpdatedAt); err != nil {
			return fmt.Errorf("insert ai suggestion: %w", err)
		}
	}
	return tx.Commit()
}

// GetSuggestion reads one suggestion of the tenant.
func (r *AIAnalysisRepository) GetSuggestion(ctx context.Context, tenantID, id shared.ID) (*aianalysis.Suggestion, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+aiSuggestionColumns+` FROM ai_suggestions WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	s, err := scanAISuggestion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aianalysis.ErrSuggestionNotFound
	}
	return s, err
}

// ListSuggestionsBySubject lists a subject's suggestions, newest first.
func (r *AIAnalysisRepository) ListSuggestionsBySubject(ctx context.Context, tenantID shared.ID, subjectType aianalysis.SubjectType, subjectID shared.ID, limit int) ([]*aianalysis.Suggestion, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+aiSuggestionColumns+` FROM ai_suggestions
		WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND state <> 'shadow'
		ORDER BY created_at DESC, id DESC LIMIT $4`, tenantID, subjectType, subjectID, limit)
	if err != nil {
		return nil, fmt.Errorf("list ai suggestions: %w", err)
	}
	return collectAISuggestions(rows)
}

// ListSuggestionsByRun lists a run's suggestions.
func (r *AIAnalysisRepository) ListSuggestionsByRun(ctx context.Context, tenantID, runID shared.ID) ([]*aianalysis.Suggestion, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+aiSuggestionColumns+` FROM ai_suggestions
		WHERE tenant_id = $1 AND run_id = $2 ORDER BY created_at, id LIMIT 200`, tenantID, runID)
	if err != nil {
		return nil, fmt.Errorf("list ai suggestions: %w", err)
	}
	return collectAISuggestions(rows)
}

func collectAISuggestions(rows *sql.Rows) ([]*aianalysis.Suggestion, error) {
	defer rows.Close()
	var out []*aianalysis.Suggestion
	for rows.Next() {
		s, err := scanAISuggestion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanAISuggestion(row rowScanner) (*aianalysis.Suggestion, error) {
	var (
		s                                          aianalysis.Suggestion
		payload, evidence, previous                []byte
		conf                                       sql.NullFloat64
		reasons                                    pq.StringArray
		appliedBy, approvalID, undoneBy, decidedBy sql.NullString
		appliedAt, undoneAt, decidedAt             sql.NullTime
	)
	if err := row.Scan(&s.ID, &s.TenantID, &s.RunID, &s.UseCase, &s.SubjectType, &s.SubjectID, &s.Kind, &payload,
		&s.SchemaVersion, &s.Direction, &conf, &evidence, &s.State, &reasons, &previous, &appliedBy, &appliedAt,
		&s.ApprovalKind, &approvalID, &undoneBy, &undoneAt, &decidedBy, &decidedAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	s.Payload = payload
	if len(previous) > 0 {
		s.PreviousValue = previous
	}
	if conf.Valid {
		c := conf.Float64
		s.Confidence = &c
	}
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &s.Evidence); err != nil {
			return nil, fmt.Errorf("decode evidence: %w", err)
		}
	}
	s.ReviewReasons = reasons
	s.AppliedBy, s.ApprovalID = nullIDFromString(appliedBy), nullIDFromString(approvalID)
	s.UndoneBy, s.DecidedBy = nullIDFromString(undoneBy), nullIDFromString(decidedBy)
	s.AppliedAt, s.UndoneAt, s.DecidedAt = nullTimeValue(appliedAt), nullTimeValue(undoneAt), nullTimeValue(decidedAt)
	return &s, nil
}

// Transition applies a guarded state change.
func (r *AIAnalysisRepository) Transition(ctx context.Context, tenantID, id shared.ID, t aianalysis.Transition) (*aianalysis.Suggestion, error) {
	from := make([]string, len(t.From))
	for i, f := range t.From {
		from[i] = string(f)
	}
	var approvalKind sql.NullString
	if t.ApprovalKind != "" {
		approvalKind = sql.NullString{String: string(t.ApprovalKind), Valid: true}
	}
	var previous any
	if t.PreviousValue != nil {
		previous = t.PreviousValue
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE ai_suggestions SET
			state = $4,
			previous_value = COALESCE($5::jsonb, previous_value),
			approval_kind = COALESCE($6, approval_kind),
			approval_id = COALESCE($7::uuid, approval_id),
			applied_by = CASE WHEN $8 THEN $10::uuid ELSE applied_by END,
			applied_at = CASE WHEN $8 THEN $11::timestamptz ELSE applied_at END,
			undone_by = CASE WHEN $9 THEN $10::uuid ELSE undone_by END,
			undone_at = CASE WHEN $9 THEN $11::timestamptz ELSE undone_at END,
			decided_by = $10::uuid, decided_at = $11::timestamptz, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = ANY($3)
		RETURNING `+aiSuggestionColumns,
		tenantID, id, pq.Array(from), t.To, previous, approvalKind, nullID(t.ApprovalID), t.Applied, t.Undone,
		nullID(t.Actor), t.At)
	s, err := scanAISuggestion(row)
	if errors.Is(err, sql.ErrNoRows) {
		if _, gerr := r.GetSuggestion(ctx, tenantID, id); gerr != nil {
			return nil, gerr
		}
		return nil, aianalysis.ErrStateChanged
	}
	return s, err
}

// ListPolicies lists the stored policies of a tenant.
func (r *AIAnalysisRepository) ListPolicies(ctx context.Context, tenantID shared.ID) ([]aianalysis.UseCasePolicy, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT use_case, mode, executor, data_class_ceiling, min_confidence::float8, triggers, budget_share,
			downgraded_at, COALESCE(downgrade_reason, ''), updated_by, updated_at
		FROM tenant_ai_use_cases WHERE tenant_id = $1 ORDER BY use_case`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list ai use cases: %w", err)
	}
	defer rows.Close()
	var out []aianalysis.UseCasePolicy
	for rows.Next() {
		p := aianalysis.UseCasePolicy{TenantID: tenantID, Stored: true}
		var (
			triggers    pq.StringArray
			downgraded  sql.NullTime
			updatedBy   sql.NullString
			budgetShare int16
		)
		if err := rows.Scan(&p.UseCase, &p.Mode, &p.Executor, &p.DataClassCeiling, &p.MinConfidence, &triggers,
			&budgetShare, &downgraded, &p.DowngradeReason, &updatedBy, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.BudgetShare = int(budgetShare)
		for _, t := range triggers {
			p.Triggers = append(p.Triggers, aianalysis.Trigger(t))
		}
		p.DowngradedAt = nullTimeValue(downgraded)
		p.UpdatedBy = nullIDFromString(updatedBy)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertPolicy writes an administrator's policy. Re-enabling auto-apply
// clears an earlier downgrade.
func (r *AIAnalysisRepository) UpsertPolicy(ctx context.Context, p aianalysis.UseCasePolicy) error {
	triggers := make([]string, len(p.Triggers))
	for i, t := range p.Triggers {
		triggers[i] = string(t)
	}
	if p.BudgetShare < 1 || p.BudgetShare > 100 {
		return fmt.Errorf("%w: budget share out of range", shared.ErrValidation)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_ai_use_cases (tenant_id, use_case, mode, executor, data_class_ceiling, min_confidence,
			triggers, budget_share, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (tenant_id, use_case) DO UPDATE SET
			mode = EXCLUDED.mode, executor = EXCLUDED.executor, data_class_ceiling = EXCLUDED.data_class_ceiling,
			min_confidence = EXCLUDED.min_confidence, triggers = EXCLUDED.triggers,
			budget_share = EXCLUDED.budget_share, updated_by = EXCLUDED.updated_by, updated_at = now(),
			downgraded_at = CASE WHEN EXCLUDED.mode = 'auto_apply' THEN NULL ELSE tenant_ai_use_cases.downgraded_at END,
			downgrade_reason = CASE WHEN EXCLUDED.mode = 'auto_apply' THEN NULL ELSE tenant_ai_use_cases.downgrade_reason END`,
		p.TenantID, p.UseCase, p.Mode, p.Executor, p.DataClassCeiling, p.MinConfidence, pq.Array(triggers),
		int16(p.BudgetShare), nullID(p.UpdatedBy)) //nolint:gosec // bounded 1..100 above
	if err != nil {
		if isCheckViolation(err) {
			return fmt.Errorf("%w: invalid AI use case policy", shared.ErrValidation)
		}
		return fmt.Errorf("upsert ai use case: %w", err)
	}
	return nil
}

// Downgrade moves an auto_apply use case to suggest.
func (r *AIAnalysisRepository) Downgrade(ctx context.Context, tenantID shared.ID, u aianalysis.UseCase, reason string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenant_ai_use_cases SET mode = 'suggest', downgraded_at = $4, downgrade_reason = $3, updated_at = now()
		WHERE tenant_id = $1 AND use_case = $2 AND mode = 'auto_apply'`, tenantID, u, reason, at)
	if err != nil {
		return false, fmt.Errorf("downgrade ai use case: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecentDecisions counts the last window decisions of a use case. A
// suggestion waiting in an approval counts once the approval is decided:
// approved is an acceptance, rejected or canceled an override.
func (r *AIAnalysisRepository) RecentDecisions(ctx context.Context, tenantID shared.ID, u aianalysis.UseCase, window int) (aianalysis.Decisions, error) {
	var d aianalysis.Decisions
	err := r.db.QueryRowContext(ctx, `
		WITH recent AS (
			SELECT s.state,
			       CASE s.approval_kind
			           WHEN 'status' THEN (SELECT a.status FROM finding_status_approvals a
			                               WHERE a.tenant_id = s.tenant_id AND a.id = s.approval_id)
			           WHEN 'severity' THEN (SELECT q.status FROM finding_severity_requests q
			                                 WHERE q.tenant_id = s.tenant_id AND q.id = s.approval_id)
			       END AS approval_status
			FROM ai_suggestions s
			WHERE s.tenant_id = $1 AND s.use_case = $2 AND s.decided_at IS NOT NULL
			  AND s.state IN ('applied', 'auto_applied', 'dismissed', 'undone', 'pending_approval')
			ORDER BY s.decided_at DESC
			LIMIT $3
		)
		SELECT count(*) FILTER (WHERE state <> 'pending_approval' OR approval_status IN ('approved', 'rejected', 'canceled')),
		       count(*) FILTER (WHERE state IN ('dismissed', 'undone')
		                        OR (state = 'pending_approval' AND approval_status IN ('rejected', 'canceled')))
		FROM recent`, tenantID, u, window).Scan(&d.Total, &d.Overrides)
	if err != nil {
		return d, fmt.Errorf("count ai decisions: %w", err)
	}
	return d, nil
}
