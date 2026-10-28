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
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIAnalysisRepository stores AI agents, their owners and their runs
// (docs/architecture/ai-analysis.md). Every query filters on tenant_id,
// except the sweep and the reaper, which are system jobs.
type AIAnalysisRepository struct {
	db *DB
}

// NewAIAnalysisRepository creates the repository.
func NewAIAnalysisRepository(db *DB) *AIAnalysisRepository {
	return &AIAnalysisRepository{db: db}
}

var (
	_ aianalysis.AgentRepository = (*AIAnalysisRepository)(nil)
	_ aianalysis.RunRepository   = (*AIAnalysisRepository)(nil)
)

// ---- AI agents ----

// Create stores the service account, the AI profile and the owners in one
// transaction.
func (r *AIAnalysisRepository) Create(ctx context.Context, in aianalysis.NewAgent) error {
	a := in.Agent
	if len(in.Owners) == 0 {
		return aianalysis.ErrOwnerRequired
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := createServiceAccountTx(ctx, tx, &serviceaccount.ServiceAccount{
		ID: a.ID, TenantID: a.TenantID, Name: a.Name, Description: a.Description, OwnerID: a.CreatedBy,
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ai_agents (user_id, tenant_id, role, preset, status, data_class_ceiling, executor,
			runs_per_hour, actions_per_hour, tokens_month, attested_at, attested_by, attest_due_at, created_by)
		VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12, $11)`,
		a.ID, a.TenantID, a.Role, a.Preset, a.DataClassCeiling, a.Executor, a.RunsPerHour, a.ActionsPerHour,
		a.TokensMonth, a.AttestedAt, nullID(a.CreatedBy), a.AttestDueAt); err != nil {
		return fmt.Errorf("create ai agent: %w", err)
	}
	if err := insertAgentOwners(ctx, tx, a.TenantID, a.ID, in.Owners, a.CreatedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func insertAgentOwners(ctx context.Context, tx *sql.Tx, tenantID, agentID shared.ID, owners []aianalysis.OwnerRef, by *shared.ID) error {
	for _, o := range owners {
		var userID, groupID sql.NullString
		switch o.Kind {
		case aianalysis.OwnerUser:
			userID = sql.NullString{String: o.ID.String(), Valid: true}
		case aianalysis.OwnerTeam:
			groupID = sql.NullString{String: o.ID.String(), Valid: true}
		default:
			return fmt.Errorf("%w: unknown owner kind", shared.ErrValidation)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_agent_owners (tenant_id, ai_agent_id, user_id, group_id, added_by)
			VALUES ($1, $2, $3, $4, $5)`, tenantID, agentID, userID, groupID, nullID(by)); err != nil {
			if isCheckViolation(err) || isUniqueViolation(err) {
				return fmt.Errorf("%w: an owner is not a person or team of this organization, or is listed twice", shared.ErrValidation)
			}
			return fmt.Errorf("add ai agent owner: %w", err)
		}
	}
	return nil
}

const aiAgentSelect = `
	SELECT a.user_id, a.tenant_id, u.name, COALESCE(u.preferences->>'description', ''), a.role, a.preset, a.status,
	       COALESCE(a.pause_reason, ''), a.data_class_ceiling, a.executor, a.runs_per_hour, a.actions_per_hour,
	       a.tokens_month, a.attested_at, a.attested_by, a.attest_due_at, a.created_by, a.created_at, a.updated_at,
	       COALESCE((SELECT json_agg(json_build_object(
	                    'kind', CASE WHEN o.user_id IS NOT NULL THEN 'user' ELSE 'team' END,
	                    'id', COALESCE(o.user_id, o.group_id),
	                    'name', COALESCE(ou.name, ou.email, og.name, ''))
	                  ORDER BY o.added_at, o.id)
	                 FROM ai_agent_owners o
	                 LEFT JOIN users ou ON ou.id = o.user_id
	                 LEFT JOIN groups og ON og.id = o.group_id AND og.tenant_id = o.tenant_id
	                 WHERE o.ai_agent_id = a.user_id AND o.tenant_id = a.tenant_id), '[]')
	FROM ai_agents a
	JOIN users u ON u.id = a.user_id`

func scanAIAgent(row rowScanner) (*aianalysis.Agent, error) {
	var (
		a          aianalysis.Agent
		reason     string
		attestedBy sql.NullString
		createdBy  sql.NullString
		owners     []byte
	)
	if err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Role, &a.Preset, &a.Status, &reason,
		&a.DataClassCeiling, &a.Executor, &a.RunsPerHour, &a.ActionsPerHour, &a.TokensMonth, &a.AttestedAt,
		&attestedBy, &a.AttestDueAt, &createdBy, &a.CreatedAt, &a.UpdatedAt, &owners); err != nil {
		return nil, err
	}
	a.PauseReason = aianalysis.PauseReason(reason)
	a.AttestedBy = nullIDFromString(attestedBy)
	a.CreatedBy = nullIDFromString(createdBy)
	if err := json.Unmarshal(owners, &a.Owners); err != nil {
		return nil, fmt.Errorf("decode ai agent owners: %w", err)
	}
	return &a, nil
}

// Get reads one AI agent of the tenant.
func (r *AIAnalysisRepository) Get(ctx context.Context, tenantID, id shared.ID) (*aianalysis.Agent, error) {
	a, err := scanAIAgent(r.db.QueryRowContext(ctx, aiAgentSelect+` WHERE a.tenant_id = $1 AND a.user_id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aianalysis.ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get ai agent: %w", err)
	}
	return a, nil
}

// List returns the tenant's AI agents by name.
func (r *AIAnalysisRepository) List(ctx context.Context, tenantID shared.ID) ([]*aianalysis.Agent, error) {
	return r.listAgents(ctx, aiAgentSelect+` WHERE a.tenant_id = $1 ORDER BY u.name, a.user_id LIMIT 200`, tenantID)
}

// ListActive returns active AI agents of every organization (the sweep).
func (r *AIAnalysisRepository) ListActive(ctx context.Context, limit int) ([]*aianalysis.Agent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	return r.listAgents(ctx, aiAgentSelect+` WHERE a.status = 'active' ORDER BY a.user_id LIMIT $1`, limit)
}

func (r *AIAnalysisRepository) listAgents(ctx context.Context, q string, args ...any) ([]*aianalysis.Agent, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list ai agents: %w", err)
	}
	defer rows.Close()
	var out []*aianalysis.Agent
	for rows.Next() {
		a, err := scanAIAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ai agent: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetOwners replaces the owners in one transaction.
func (r *AIAnalysisRepository) SetOwners(ctx context.Context, tenantID, id shared.ID, owners []aianalysis.OwnerRef, by shared.ID) error {
	if len(owners) == 0 {
		return aianalysis.ErrOwnerRequired
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM ai_agents WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE)`,
		tenantID, id).Scan(&exists); err != nil {
		return fmt.Errorf("lock ai agent: %w", err)
	}
	if !exists {
		return aianalysis.ErrAgentNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ai_agent_owners WHERE tenant_id = $1 AND ai_agent_id = $2`, tenantID, id); err != nil {
		return fmt.Errorf("clear ai agent owners: %w", err)
	}
	if err := insertAgentOwners(ctx, tx, tenantID, id, owners, &by); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ai_agents SET updated_at = now() WHERE tenant_id = $1 AND user_id = $2`, tenantID, id); err != nil {
		return fmt.Errorf("touch ai agent: %w", err)
	}
	return tx.Commit()
}

// SetStatus moves an AI agent between statuses, guarded by from.
func (r *AIAnalysisRepository) SetStatus(ctx context.Context, tenantID, id shared.ID, from []aianalysis.Status, to aianalysis.Status, reason aianalysis.PauseReason) (bool, error) {
	allowed := make([]string, 0, len(from))
	for _, s := range from {
		allowed = append(allowed, string(s))
	}
	var pause sql.NullString
	if to != aianalysis.StatusActive {
		pause = sql.NullString{String: string(reason), Valid: true}
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE ai_agents SET status = $3, pause_reason = $4, updated_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND (cardinality($5::text[]) = 0 OR status = ANY($5::text[]))`,
		tenantID, id, to, pause, pq.Array(allowed))
	if err != nil {
		return false, fmt.Errorf("set ai agent status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("set ai agent status: %w", err)
	}
	if n == 0 {
		if _, gerr := r.Get(ctx, tenantID, id); gerr != nil {
			return false, gerr
		}
		return false, nil
	}
	return true, nil
}

// SetPreset records the preset the AI agent's role came from.
func (r *AIAnalysisRepository) SetPreset(ctx context.Context, tenantID, id shared.ID, p aianalysis.Preset) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE ai_agents SET preset = $3, updated_at = now() WHERE tenant_id = $1 AND user_id = $2`, tenantID, id, p)
	if err != nil {
		return fmt.Errorf("set ai agent preset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aianalysis.ErrAgentNotFound
	}
	return nil
}

// Attest records an owner's attestation.
func (r *AIAnalysisRepository) Attest(ctx context.Context, tenantID, id, by shared.ID, at, due time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ai_agents SET attested_at = $3, attested_by = $4, attest_due_at = $5, updated_at = now()
		WHERE tenant_id = $1 AND user_id = $2`, tenantID, id, at, by, due)
	if err != nil {
		return fmt.Errorf("attest ai agent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aianalysis.ErrAgentNotFound
	}
	return nil
}

// PeopleOf lists the people who answer for an owner list now.
func (r *AIAnalysisRepository) PeopleOf(ctx context.Context, tenantID shared.ID, owners []aianalysis.OwnerRef, now time.Time) ([]shared.ID, error) {
	var users, groups []string
	for _, o := range owners {
		switch o.Kind {
		case aianalysis.OwnerUser:
			users = append(users, o.ID.String())
		case aianalysis.OwnerTeam:
			groups = append(groups, o.ID.String())
		}
	}
	if len(users)+len(groups) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT p.user_id FROM (
		    SELECT unnest($2::uuid[]) AS user_id
		    UNION
		    SELECT gm.user_id FROM groups g
		    JOIN group_members gm ON gm.group_id = g.id AND (gm.expires_at IS NULL OR gm.expires_at > $4)
		    WHERE g.tenant_id = $1 AND g.is_active AND g.id = ANY($3::uuid[])
		) p
		JOIN users u ON u.id = p.user_id AND u.kind = 'person' AND u.status = 'active'
		JOIN tenant_members m ON m.user_id = p.user_id AND m.tenant_id = $1 AND m.status = 'active'
		     AND (m.expires_at IS NULL OR m.expires_at > $4)
		ORDER BY p.user_id
		LIMIT 500`, tenantID, pq.Array(users), pq.Array(groups), now)
	if err != nil {
		return nil, fmt.Errorf("list accountable people: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var uid shared.ID
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("scan accountable person: %w", err)
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// Delete removes the AI agent's service account (the profile, owners, roles,
// team memberships and keys go with it; runs keep their rows).
func (r *AIAnalysisRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM users u USING ai_agents a
		WHERE a.user_id = u.id AND a.tenant_id = $1 AND u.id = $2 AND u.kind = 'service' AND u.service_tenant_id = $1`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("delete ai agent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aianalysis.ErrAgentNotFound
	}
	return nil
}

// IsAgent reports whether the user is one of the tenant's AI agents.
func (r *AIAnalysisRepository) IsAgent(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM ai_agents WHERE tenant_id = $1 AND user_id = $2)`, tenantID, userID).Scan(&ok); err != nil {
		return false, fmt.Errorf("check ai agent: %w", err)
	}
	return ok, nil
}

// ---- runs ----

const aiRunColumns = `id, tenant_id, ai_agent_id, use_case, kind, subject_type, subject_id, executor, status, data_class,
	fields_sent, fields_withheld, COALESCE(bundle_digest, ''), COALESCE(prompt_template_id, ''),
	COALESCE(prompt_template_digest, ''), COALESCE(output_schema, ''), COALESCE(provider, ''), COALESCE(model, ''),
	steps, tool_calls, actions, tokens_in, tokens_out, cost_micro_usd, duration_ms, COALESCE(error_code, ''),
	triggered_by, trigger, accountable, legacy_output, deadline_at, started_at, completed_at, created_at`

// CreateRun inserts a run. A second live run for the same use case and
// subject is ErrRunInFlight.
func (r *AIAnalysisRepository) CreateRun(ctx context.Context, run *aianalysis.Run) error {
	if run.ID.IsZero() {
		run.ID = shared.NewID()
	}
	acc, err := json.Marshal(nonNilOwners(run.Accountable))
	if err != nil {
		return fmt.Errorf("encode accountable: %w", err)
	}
	// A live run of this subject and use case past its deadline (its
	// executor died) gives up the slot first, in the same statement.
	err = r.db.QueryRowContext(ctx, `
		WITH expired AS (
		    UPDATE ai_runs SET status = 'failed', error_code = '`+aianalysis.ErrorTimeout+`', completed_at = now(), updated_at = now()
		    WHERE tenant_id = $2 AND use_case = $4 AND subject_id = $7 AND NOT shadow
		      AND status IN ('queued', 'running', 'waiting_tool', 'waiting_approval') AND deadline_at < now()
		    RETURNING id
		)
		INSERT INTO ai_runs (id, tenant_id, ai_agent_id, use_case, kind, subject_type, subject_id, executor, status,
			data_class, triggered_by, trigger, accountable, deadline_at, started_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		FROM (SELECT count(*) FROM expired) e
		RETURNING created_at`,
		run.ID, run.TenantID, nullID(run.AgentID), run.UseCase, run.Kind, run.SubjectType, run.SubjectID,
		run.Executor, run.Status, run.DataClass, nullID(run.TriggeredBy), run.Trigger, acc,
		nullTime(run.DeadlineAt), nullTime(run.StartedAt),
	).Scan(&run.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return aianalysis.ErrRunInFlight
		}
		return fmt.Errorf("insert ai run: %w", err)
	}
	return nil
}

func nonNilOwners(o []aianalysis.OwnerRef) []aianalysis.OwnerRef {
	if o == nil {
		return []aianalysis.OwnerRef{}
	}
	return o
}

// UpdateRun stores the outcome and provenance of a run.
func (r *AIAnalysisRepository) UpdateRun(ctx context.Context, run *aianalysis.Run) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ai_runs SET status = $3, data_class = $4, fields_sent = $5, fields_withheld = $6,
			bundle_digest = $7, prompt_template_id = $8, prompt_template_digest = $9, output_schema = $10,
			provider = $11, model = $12, steps = $13, tool_calls = $14, actions = $15, tokens_in = $16,
			tokens_out = $17, cost_micro_usd = $18, duration_ms = $19, error_code = $20,
			started_at = $21, completed_at = $22, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		run.TenantID, run.ID, run.Status, run.DataClass, pq.Array(nonNil(run.FieldsSent)),
		pq.Array(nonNil(run.FieldsWithheld)), nullStr(run.BundleDigest), nullStr(run.PromptTemplateID),
		nullStr(run.PromptTemplateDigest), nullStr(run.OutputSchema), nullStr(run.Provider), nullStr(run.Model),
		run.Steps, run.ToolCalls, run.Actions, run.TokensIn, run.TokensOut, run.CostMicroUSD,
		nullIntPtr(run.DurationMS), nullStr(run.ErrorCode),
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
	run, err := scanAIRun(r.db.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aianalysis.ErrRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get ai run: %w", err)
	}
	return run, nil
}

// ListRunsBySubject lists a subject's runs, newest first.
func (r *AIAnalysisRepository) ListRunsBySubject(ctx context.Context, tenantID shared.ID, subjectType aianalysis.SubjectType, subjectID shared.ID, limit int) ([]*aianalysis.Run, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs
		WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND NOT shadow
		ORDER BY created_at DESC, id DESC LIMIT $4`, tenantID, subjectType, subjectID, limit)
	if err != nil {
		return nil, fmt.Errorf("list ai runs: %w", err)
	}
	defer rows.Close()
	var out []*aianalysis.Run
	for rows.Next() {
		run, err := scanAIRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ai run: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// Usage counts an AI agent's runs and tokens since a moment.
func (r *AIAnalysisRepository) Usage(ctx context.Context, tenantID, agentID shared.ID, since time.Time) (int, int, error) {
	var runs, tokens int
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*), COALESCE(sum(tokens_in + tokens_out), 0)
		FROM ai_runs WHERE tenant_id = $1 AND ai_agent_id = $2 AND created_at >= $3`,
		tenantID, agentID, since).Scan(&runs, &tokens); err != nil {
		return 0, 0, fmt.Errorf("ai agent usage: %w", err)
	}
	return runs, tokens, nil
}

func scanAIRun(row rowScanner) (*aianalysis.Run, error) {
	var (
		run         aianalysis.Run
		agent       sql.NullString
		duration    sql.NullInt64
		triggeredBy sql.NullString
		deadline    sql.NullTime
		started     sql.NullTime
		completed   sql.NullTime
		sent        pq.StringArray
		withheld    pq.StringArray
		acc         []byte
		legacy      []byte
	)
	if err := row.Scan(&run.ID, &run.TenantID, &agent, &run.UseCase, &run.Kind, &run.SubjectType, &run.SubjectID,
		&run.Executor, &run.Status, &run.DataClass, &sent, &withheld, &run.BundleDigest, &run.PromptTemplateID,
		&run.PromptTemplateDigest, &run.OutputSchema, &run.Provider, &run.Model, &run.Steps, &run.ToolCalls,
		&run.Actions, &run.TokensIn, &run.TokensOut, &run.CostMicroUSD, &duration, &run.ErrorCode, &triggeredBy,
		&run.Trigger, &acc, &legacy, &deadline, &started, &completed, &run.CreatedAt); err != nil {
		return nil, err
	}
	run.AgentID = nullIDFromString(agent)
	run.FieldsSent, run.FieldsWithheld = sent, withheld
	if duration.Valid {
		d := int(duration.Int64)
		run.DurationMS = &d
	}
	run.TriggeredBy = nullIDFromString(triggeredBy)
	if len(acc) > 0 {
		if err := json.Unmarshal(acc, &run.Accountable); err != nil {
			return nil, fmt.Errorf("decode accountable: %w", err)
		}
	}
	if len(legacy) > 0 {
		if err := json.Unmarshal(legacy, &run.LegacyOutput); err != nil {
			return nil, fmt.Errorf("decode legacy output: %w", err)
		}
	}
	run.DeadlineAt = nullTimeValue(deadline)
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
