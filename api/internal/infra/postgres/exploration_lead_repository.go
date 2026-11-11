package postgres

// Explorations, leads, links and verdicts (docs/architecture/exploration.md).
// Every statement carries the tenant; every end of a link is a typed column
// with a composite foreign key, so the database refuses a reference to
// another tenant's row even if a caller got it wrong.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ExplorationRepository implements exploration.Repository.
type ExplorationRepository struct{ db *DB }

var _ exploration.Repository = (*ExplorationRepository)(nil)

// NewExplorationRepository creates the repository.
func NewExplorationRepository(db *DB) *ExplorationRepository { return &ExplorationRepository{db: db} }

// EnsureContinuous implements exploration.Repository.
func (r *ExplorationRepository) EnsureContinuous(ctx context.Context, tenantID shared.ID) (shared.ID, error) {
	var id shared.ID
	err := r.db.QueryRowContext(ctx, `
		WITH ins AS (
			INSERT INTO explorations (tenant_id, kind, title) VALUES ($1, 'continuous', 'Continuous exploration')
			ON CONFLICT (tenant_id) WHERE kind = 'continuous' DO NOTHING
			RETURNING id)
		SELECT id FROM ins
		UNION ALL
		SELECT id FROM explorations WHERE tenant_id = $1 AND kind = 'continuous'
		LIMIT 1`, tenantID.String()).Scan(&id)
	if err != nil {
		return id, fmt.Errorf("ensure continuous exploration: %w", err)
	}
	return id, nil
}

// leadColumns are read by scanLead in this order.
const leadColumns = `l.id, l.tenant_id, l.exploration_id, l.lead_type, l.state, l.capability, l.params, l.action_hash, l.tier,
	l.subject_asset_id, l.subject_finding_id, l.reason_code, l.rationale, l.origin, l.origin_ref, l.likelihood,
	l.score, l.score_inputs, l.dedup_key, l.blocked_reason, l.attempts, l.next_attempt_at,
	l.approved_by, l.approved_at, l.created_by, l.created_at, l.updated_at, l.closed_at, l.row_version`

// leadScopeAsset is the asset a lead's data scope follows: its subject
// asset, else the subject finding's asset (tenant-bound).
const leadScopeAsset = `COALESCE(l.subject_asset_id,
	(SELECT f.asset_id FROM findings f WHERE f.tenant_id = l.tenant_id AND f.id = l.subject_finding_id))`

func scanNullID(ns sql.NullString) (*shared.ID, error) {
	if !ns.Valid {
		return nil, nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// OpenLead implements exploration.Repository.
func (r *ExplorationRepository) OpenLead(ctx context.Context, l *exploration.Lead, parents []exploration.Link) (created bool, err error) {
	params, err := json.Marshal(l.Action.Params)
	if err != nil {
		return false, fmt.Errorf("encode params: %w", err)
	}
	inputs, err := json.Marshal(l.ScoreInputs)
	if err != nil {
		return false, fmt.Errorf("encode score inputs: %w", err)
	}
	for i := range parents {
		parents[i].TenantID, parents[i].LeadID, parents[i].Rel = l.TenantID, l.ID, exploration.RelDerivedFrom
		if err := parents[i].Validate(); err != nil {
			return false, err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin open lead: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var closed any
	if l.ClosedAt != nil {
		closed = *l.ClosedAt
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO exploration_leads (tenant_id, id, exploration_id, lead_type, state, capability, params, action_hash, tier,
			subject_asset_id, subject_finding_id, reason_code, rationale, origin, origin_ref, likelihood,
			score, score_inputs, dedup_key, created_by, closed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
		ON CONFLICT (tenant_id, exploration_id, dedup_key)
			WHERE state IN ('proposed', 'awaiting_approval', 'open', 'running', 'blocked') DO NOTHING`,
		l.TenantID.String(), l.ID.String(), l.ExplorationID.String(), l.Type, string(l.State), l.Action.Capability,
		params, l.ActionHash, int(l.Tier), nullID(l.SubjectAssetID), nullID(l.SubjectFindingID), l.ReasonCode,
		l.Rationale, string(l.Origin), l.OriginRef, string(l.Likelihood), l.Score, inputs, l.DedupKey,
		nullID(l.CreatedBy), closed)
	if err != nil {
		return false, fmt.Errorf("insert lead: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := addLinks(ctx, tx, parents); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit open lead: %w", err)
	}
	return true, nil
}

func scanLead(sc interface{ Scan(...any) error }) (*exploration.Lead, error) {
	var (
		l                                         exploration.Lead
		capability, actionHash                    sql.NullString
		tier                                      sql.NullInt64
		params, inputs                            []byte
		subjAsset, subjFinding, approver, creator sql.NullString
		state, origin, likelihood                 string
		nextAttempt, approvedAt, closedAt         sql.NullTime
	)
	if err := sc.Scan(&l.ID, &l.TenantID, &l.ExplorationID, &l.Type, &state, &capability, &params, &actionHash, &tier,
		&subjAsset, &subjFinding, &l.ReasonCode, &l.Rationale, &origin, &l.OriginRef, &likelihood,
		&l.Score, &inputs, &l.DedupKey, &l.BlockedReason, &l.Attempts, &nextAttempt,
		&approver, &approvedAt, &creator, &l.CreatedAt, &l.UpdatedAt, &closedAt, &l.RowVersion); err != nil {
		return nil, err
	}
	l.State, l.Origin, l.Likelihood = exploration.LeadState(state), exploration.Origin(origin), exploration.Likelihood(likelihood)
	l.Action.Capability, l.ActionHash, l.Tier = capability.String, actionHash.String, stage.Tier(tier.Int64)
	if err := json.Unmarshal(params, &l.Action.Params); err != nil {
		return nil, fmt.Errorf("decode params: %w", err)
	}
	if err := json.Unmarshal(inputs, &l.ScoreInputs); err != nil {
		return nil, fmt.Errorf("decode score inputs: %w", err)
	}
	var err error
	if l.SubjectAssetID, err = scanNullID(subjAsset); err != nil {
		return nil, err
	}
	if l.SubjectFindingID, err = scanNullID(subjFinding); err != nil {
		return nil, err
	}
	if l.ApprovedBy, err = scanNullID(approver); err != nil {
		return nil, err
	}
	if l.CreatedBy, err = scanNullID(creator); err != nil {
		return nil, err
	}
	if nextAttempt.Valid {
		l.NextAttemptAt = &nextAttempt.Time
	}
	if approvedAt.Valid {
		l.ApprovedAt = &approvedAt.Time
	}
	if closedAt.Valid {
		l.ClosedAt = &closedAt.Time
	}
	return &l, nil
}

// GetLead implements exploration.Repository.
func (r *ExplorationRepository) GetLead(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (*exploration.Lead, error) {
	cond, args := dataScopeCond(leadScopeAsset, scope, []any{tenantID.String(), id.String()})
	l, err := scanLead(r.db.QueryRowContext(ctx, `SELECT `+leadColumns+` FROM exploration_leads l
		WHERE l.tenant_id = $1 AND l.id = $2 AND `+cond, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get lead: %w", err)
	}
	return l, nil
}

// ListLeads implements exploration.Repository.
func (r *ExplorationRepository) ListLeads(ctx context.Context, tenantID shared.ID, f exploration.LeadFilter) ([]*exploration.Lead, error) {
	if f.Limit <= 0 || f.Limit > exploration.MaxListLimit {
		f.Limit = exploration.MaxListLimit
	}
	args := []any{tenantID.String()}
	where := []string{"l.tenant_id = $1"}
	if len(f.States) > 0 {
		states := make([]string, len(f.States))
		for i, s := range f.States {
			states[i] = string(s)
		}
		args = append(args, pq.Array(states))
		where = append(where, fmt.Sprintf("l.state = ANY($%d::text[])", len(args)))
	}
	if f.SubjectAssetID != nil {
		args = append(args, f.SubjectAssetID.String())
		where = append(where, fmt.Sprintf("l.subject_asset_id = $%d", len(args)))
	}
	if f.Before != nil {
		args = append(args, *f.Before)
		where = append(where, fmt.Sprintf("l.updated_at < $%d", len(args)))
	}
	cond, args := dataScopeCond(leadScopeAsset, f.Scope, args)
	where = append(where, cond)
	args = append(args, f.Limit)
	rows, err := r.db.QueryContext(ctx, `SELECT `+leadColumns+` FROM exploration_leads l
		WHERE `+strings.Join(where, " AND ")+fmt.Sprintf(` ORDER BY l.updated_at DESC, l.id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list leads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*exploration.Lead
	for rows.Next() {
		l, err := scanLead(rows)
		if err != nil {
			return nil, fmt.Errorf("scan lead: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SaveLead implements exploration.Repository.
func (r *ExplorationRepository) SaveLead(ctx context.Context, l *exploration.Lead) error {
	inputs, err := json.Marshal(l.ScoreInputs)
	if err != nil {
		return fmt.Errorf("encode score inputs: %w", err)
	}
	var next, approvedAt, closed any
	if l.NextAttemptAt != nil {
		next = *l.NextAttemptAt
	}
	if l.ApprovedAt != nil {
		approvedAt = *l.ApprovedAt
	}
	if l.ClosedAt != nil {
		closed = *l.ClosedAt
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE exploration_leads SET state = $3, score = $4, score_inputs = $5, blocked_reason = $6, attempts = $7,
			next_attempt_at = $8, approved_by = $9, approved_at = $10, closed_at = $11,
			updated_at = now(), row_version = row_version + 1
		WHERE tenant_id = $1 AND id = $2 AND row_version = $12`,
		l.TenantID.String(), l.ID.String(), string(l.State), l.Score, inputs, l.BlockedReason, l.Attempts,
		next, nullID(l.ApprovedBy), approvedAt, closed, l.RowVersion)
	if err != nil {
		return fmt.Errorf("save lead: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return exploration.ErrStale
	}
	l.RowVersion++
	return nil
}

// linkColFinding is the finding end column of a link.
const linkColFinding = "finding_id"

// linkEndColumn is the typed column of a link end.
func linkEndColumn(k exploration.EndKind) (string, error) {
	switch k {
	case exploration.EndAsset:
		return locKeyAssetID, nil
	case exploration.EndFinding:
		return linkColFinding, nil
	case exploration.EndScanRun:
		return "scan_run_id", nil
	case exploration.EndLead:
		return "ref_lead_id", nil
	}
	return "", fmt.Errorf("%w: invalid link end", shared.ErrValidation)
}

func addLinks(ctx context.Context, ex execer, links []exploration.Link) (int, error) {
	added := 0
	for _, k := range links {
		if err := k.Validate(); err != nil {
			return added, err
		}
		col, err := linkEndColumn(k.EndKind)
		if err != nil {
			return added, err
		}
		var effect any
		if k.Effect != "" {
			effect = string(k.Effect)
		}
		// col comes from the closed switch above, never from input.
		res, err := ex.ExecContext(ctx, `INSERT INTO exploration_links (tenant_id, lead_id, rel, end_kind, `+col+`, effect, outcome_reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
			k.TenantID.String(), k.LeadID.String(), string(k.Rel), string(k.EndKind), k.EndID.String(), effect, k.OutcomeReason)
		if err != nil {
			return added, fmt.Errorf("insert link: %w", err)
		}
		n, _ := res.RowsAffected()
		added += int(n)
	}
	return added, nil
}

// AddLinks implements exploration.Repository.
func (r *ExplorationRepository) AddLinks(ctx context.Context, links []exploration.Link) (int, error) {
	return addLinks(ctx, r.db, links)
}

// AddVerdict implements exploration.Repository.
func (r *ExplorationRepository) AddVerdict(ctx context.Context, v exploration.Verdict) error {
	if err := v.Validate(); err != nil {
		return err
	}
	ev := v.Evidence
	if ev == nil {
		ev = []exploration.EvidenceRef{}
	}
	evidence, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	if v.ID.IsZero() {
		v.ID = shared.NewID()
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO exploration_verdicts (tenant_id, id, lead_id, verdict, tier, checker, evidence, reason, decided_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		v.TenantID.String(), v.ID.String(), v.LeadID.String(), string(v.Verdict), string(v.Tier), v.Checker,
		evidence, v.Reason, nullID(v.DecidedBy)); err != nil {
		return fmt.Errorf("insert verdict: %w", err)
	}
	return nil
}

// Links implements exploration.Repository.
func (r *ExplorationRepository) Links(ctx context.Context, tenantID, leadID shared.ID) ([]exploration.Link, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, lead_id, rel, end_kind, COALESCE(asset_id, finding_id, scan_run_id, ref_lead_id),
		       COALESCE(effect, ''), outcome_reason, created_at
		FROM exploration_links WHERE tenant_id = $1 AND lead_id = $2 ORDER BY id LIMIT 1000`,
		tenantID.String(), leadID.String())
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []exploration.Link
	for rows.Next() {
		k := exploration.Link{TenantID: tenantID}
		var rel, kind, effect string
		var end sql.NullString
		if err := rows.Scan(&k.ID, &k.LeadID, &rel, &kind, &end, &effect, &k.OutcomeReason, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan link: %w", err)
		}
		k.Rel, k.EndKind, k.Effect = exploration.LinkRel(rel), exploration.EndKind(kind), exploration.Effect(effect)
		if k.EndID, err = scanNullID(end); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CountLive implements exploration.Repository.
func (r *ExplorationRepository) CountLive(ctx context.Context, tenantID, explorationID shared.ID, subject *shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM exploration_leads
		WHERE tenant_id = $1 AND exploration_id = $2
		  AND state IN ('proposed', 'awaiting_approval', 'open', 'running', 'blocked')
		  AND ($3::uuid IS NULL OR subject_asset_id = $3::uuid)`,
		tenantID.String(), explorationID.String(), nullID(subject)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count live leads: %w", err)
	}
	return n, nil
}

// Verdicts implements exploration.Repository.
func (r *ExplorationRepository) Verdicts(ctx context.Context, tenantID, leadID shared.ID) ([]exploration.Verdict, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, verdict, tier, checker, evidence, reason, decided_by, created_at
		FROM exploration_verdicts WHERE tenant_id = $1 AND lead_id = $2 ORDER BY created_at, id LIMIT 200`,
		tenantID.String(), leadID.String())
	if err != nil {
		return nil, fmt.Errorf("list verdicts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []exploration.Verdict
	for rows.Next() {
		v := exploration.Verdict{TenantID: tenantID, LeadID: leadID}
		var verdict, tier string
		var evidence []byte
		var by sql.NullString
		if err := rows.Scan(&v.ID, &verdict, &tier, &v.Checker, &evidence, &v.Reason, &by, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan verdict: %w", err)
		}
		v.Verdict, v.Tier = exploration.VerdictKind(verdict), exploration.VerdictTier(tier)
		if err := json.Unmarshal(evidence, &v.Evidence); err != nil {
			return nil, fmt.Errorf("decode evidence: %w", err)
		}
		if v.DecidedBy, err = scanNullID(by); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
