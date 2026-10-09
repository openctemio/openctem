package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ScopeTargetRepository implements scope.TargetRepository using PostgreSQL.
type ScopeTargetRepository struct {
	db *DB
}

// NewScopeTargetRepository creates a new ScopeTargetRepository.
func NewScopeTargetRepository(db *DB) *ScopeTargetRepository {
	return &ScopeTargetRepository{db: db}
}

const scopeTargetSelectQuery = `
	SELECT id, tenant_id, target_type, pattern, description, priority, status, tags,
	       created_by, created_at, updated_at,
	       expires_at, reason, max_tier, approvals_required, approved_at, rejected_by, rejected_at, origin, discovery,
	       approval_reminded_at, attested_at, attested_by, attestation_requested_at
	FROM scope_targets
`

func (r *ScopeTargetRepository) scanTarget(row interface{ Scan(...any) error }) (*scope.Target, error) {
	var (
		id          string
		tenantID    string
		targetType  string
		pattern     string
		description sql.NullString
		priority    int
		status      string
		tags        pq.StringArray
		createdBy   sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
		expiresAt   sql.NullTime
		reason      string
		maxTier     int
		approvals   int
		approvedAt  sql.NullTime
		rejectedBy  sql.NullString
		rejectedAt  sql.NullTime
		origin      string
		discovery   bool
		remindedAt  sql.NullTime
		attestedAt  sql.NullTime
		attestedBy  sql.NullString
		attestReqAt sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &targetType, &pattern, &description, &priority, &status, &tags,
		&createdBy, &createdAt, &updatedAt,
		&expiresAt, &reason, &maxTier, &approvals, &approvedAt, &rejectedBy, &rejectedAt, &origin, &discovery,
		&remindedAt, &attestedAt, &attestedBy, &attestReqAt,
	)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(id)
	tntID, _ := shared.IDFromString(tenantID)

	t := scope.ReconstituteTarget(
		tid,
		tntID,
		scope.TargetType(targetType),
		pattern,
		description.String,
		priority,
		scope.Status(status),
		[]string(tags),
		createdBy.String,
		createdAt.Time,
		updatedAt.Time,
	)
	t.RestoreEntry(scope.EntryState{
		Reason: reason, ExpiresAt: scopeTimePtr(expiresAt), MaxTier: scope.Tier(maxTier),
		ApprovalsRequired: approvals, ApprovedAt: scopeTimePtr(approvedAt),
		RejectedBy: rejectedBy.String, RejectedAt: scopeTimePtr(rejectedAt),
	})
	t.SetOrigin(scope.Origin(origin))
	t.SetDiscovery(discovery)
	t.RestoreRemindedAt(scopeTimePtr(remindedAt))
	t.RestoreAttestation(scope.AttestationState{
		AttestedAt: scopeTimePtr(attestedAt), AttestedBy: attestedBy.String, RequestedAt: scopeTimePtr(attestReqAt),
	})
	return t, nil
}

func scopeTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// loadApprovals fills the approvals of the given targets (one query).
func (r *ScopeTargetRepository) loadApprovals(ctx context.Context, tenantID string, targets []*scope.Target) error {
	if len(targets) == 0 {
		return nil
	}
	ids := make([]string, 0, len(targets))
	byID := make(map[string]*scope.Target, len(targets))
	for _, t := range targets {
		ids = append(ids, t.ID().String())
		byID[t.ID().String()] = t
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT target_id, approver_id, approved_at, self_approved, reason FROM scope_target_approvals
		WHERE tenant_id = $1 AND target_id = ANY($2::uuid[])
		ORDER BY approved_at, approver_id`, tenantID, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("list scope target approvals: %w", err)
	}
	defer rows.Close()
	got := map[string][]scope.Approval{}
	for rows.Next() {
		var tid string
		var a scope.Approval
		if err := rows.Scan(&tid, &a.UserID, &a.ApprovedAt, &a.Self, &a.Reason); err != nil {
			return err
		}
		got[tid] = append(got[tid], a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for id, list := range got {
		t := byID[id]
		t.RestoreEntry(scope.EntryState{
			Reason: t.Reason(), ExpiresAt: t.ExpiresAt(), MaxTier: t.MaxTier(), ApprovalsRequired: t.ApprovalsRequired(),
			Approvals: list, ApprovedAt: t.ApprovedAt(), RejectedBy: t.RejectedBy(), RejectedAt: t.RejectedAt(),
		})
	}
	return nil
}

// saveApprovals replaces the target's approval rows with its current list.
func (r *ScopeTargetRepository) saveApprovals(ctx context.Context, tx *sql.Tx, t *scope.Target) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM scope_target_approvals WHERE tenant_id = $1 AND target_id = $2`,
		t.TenantID().String(), t.ID().String()); err != nil {
		return fmt.Errorf("clear scope target approvals: %w", err)
	}
	for _, a := range t.Approvals() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO scope_target_approvals (tenant_id, target_id, approver_id, approved_at, self_approved, reason)
			VALUES ($1, $2, $3, $4, $5, $6)`, t.TenantID().String(), t.ID().String(), a.UserID, a.ApprovedAt, a.Self, a.Reason); err != nil {
			return fmt.Errorf("save scope target approval: %w", err)
		}
	}
	return nil
}

// Create persists a new scope target.
func (r *ScopeTargetRepository) Create(ctx context.Context, target *scope.Target) error {
	query := `
		INSERT INTO scope_targets (
			id, tenant_id, target_type, pattern, description, priority, status, tags,
			created_by, created_at, updated_at,
			expires_at, reason, max_tier, approvals_required, approved_at, origin, discovery
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err := r.db.ExecContext(ctx, query,
		target.ID().String(),
		target.TenantID().String(),
		target.TargetType().String(),
		target.Pattern(),
		nullString(target.Description()),
		target.Priority(),
		target.Status().String(),
		pq.StringArray(target.Tags()),
		nullString(target.CreatedBy()),
		target.CreatedAt(),
		target.UpdatedAt(),
		target.ExpiresAt(),
		target.Reason(),
		int(target.MaxTier()),
		target.ApprovalsRequired(),
		target.ApprovedAt(),
		string(target.Origin()),
		target.DiscoverySetting(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return scope.ErrTargetAlreadyExists
		}
		return fmt.Errorf("failed to create scope target: %w", err)
	}

	return nil
}

// GetByID retrieves a scope target by its tenant ID and ID.
func (r *ScopeTargetRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scope.Target, error) {
	query := scopeTargetSelectQuery + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())

	target, err := r.scanTarget(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, scope.ErrTargetNotFound
		}
		return nil, fmt.Errorf("failed to get scope target: %w", err)
	}
	if err := r.loadApprovals(ctx, tenantID.String(), []*scope.Target{target}); err != nil {
		return nil, err
	}
	return target, nil
}

// Update updates an existing scope target and replaces its approvals, in
// one transaction.
func (r *ScopeTargetRepository) Update(ctx context.Context, target *scope.Target) error {
	query := `
		UPDATE scope_targets SET
			description = $2,
			priority = $3,
			status = $4,
			tags = $5,
			updated_at = $6,
			created_by = $8,
			expires_at = $9,
			reason = $10,
			max_tier = $11,
			approvals_required = $12,
			approved_at = $13,
			rejected_by = $14,
			rejected_at = $15,
			discovery = $16,
			attested_at = $17,
			attested_by = $18,
			attestation_requested_at = $19
		WHERE id = $1 AND tenant_id = $7
	`
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scope target update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, query,
		target.ID().String(),
		nullString(target.Description()),
		target.Priority(),
		target.Status().String(),
		pq.StringArray(target.Tags()),
		target.UpdatedAt(),
		target.TenantID().String(),
		nullString(target.CreatedBy()),
		target.ExpiresAt(),
		target.Reason(),
		int(target.MaxTier()),
		target.ApprovalsRequired(),
		target.ApprovedAt(),
		nullString(target.RejectedBy()),
		target.RejectedAt(),
		target.DiscoverySetting(),
		target.AttestedAt(),
		nullString(target.AttestedBy()),
		target.AttestationRequestedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update scope target: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return scope.ErrTargetNotFound
	}
	if err := r.saveApprovals(ctx, tx, target); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkReminded records a reminder of the approvers of a pending entry when
// none was sent within minInterval, atomically (two clicks, two replicas:
// one reminder). It reports false when the last reminder is too recent or
// the entry is not pending in this tenant.
func (r *ScopeTargetRepository) MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, minInterval time.Duration) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scope_targets SET approval_reminded_at = $3
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		  AND (approval_reminded_at IS NULL OR approval_reminded_at <= $4)`,
		tenantID.String(), id.String(), now, now.Add(-minInterval))
	if err != nil {
		return false, fmt.Errorf("mark scope target reminded: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}

// ExpireOld marks every active or pending entry past its expiry as expired
// (the sweep; the reads already ignore them). A system write across tenants
// that only ever narrows. It returns how many rows changed.
func (r *ScopeTargetRepository) ExpireOld(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scope_targets SET status = 'expired', updated_at = now()
		WHERE status IN ('active', 'pending') AND expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("expire scope targets: %w", err)
	}
	return res.RowsAffected()
}

// Delete removes a scope target by its tenant ID and ID.
func (r *ScopeTargetRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := "DELETE FROM scope_targets WHERE tenant_id = $1 AND id = $2"
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scope target: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return scope.ErrTargetNotFound
	}

	return nil
}

// List retrieves scope targets with filtering and pagination.
func (r *ScopeTargetRepository) List(ctx context.Context, filter scope.TargetFilter, page pagination.Pagination) (pagination.Result[*scope.Target], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if len(filter.TargetTypes) > 0 {
		types := make([]string, len(filter.TargetTypes))
		for i, t := range filter.TargetTypes {
			types[i] = t.String()
		}
		conditions = append(conditions, fmt.Sprintf("target_type = ANY($%d)", argNum))
		args = append(args, pq.StringArray(types))
		argNum++
	}

	if len(filter.Statuses) > 0 {
		statuses := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statuses[i] = s.String()
		}
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argNum))
		args = append(args, pq.StringArray(statuses))
		argNum++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argNum))
		args = append(args, pq.StringArray(filter.Tags))
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(pattern ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM scope_targets" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to count scope targets: %w", err)
	}

	// Query with pagination
	query := scopeTargetSelectQuery + whereClause + " ORDER BY priority DESC, created_at DESC" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to list scope targets: %w", err)
	}
	defer rows.Close()

	var targets []*scope.Target
	for rows.Next() {
		target, err := r.scanTarget(rows)
		if err != nil {
			return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to scan scope target: %w", err)
		}
		targets = append(targets, target)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("iterate scope targets: %w", err)
	}
	if filter.TenantID != nil {
		if err := r.loadApprovals(ctx, *filter.TenantID, targets); err != nil {
			return pagination.Result[*scope.Target]{}, err
		}
	}

	return pagination.NewResult(targets, total, page), nil
}

// ListActive retrieves the tenant's scope targets in effect: active and not
// past their expiry. An expired entry stops authorizing at once, before the
// sweep marks it (RFC-054 §6.1).
func (r *ScopeTargetRepository) ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	query := scopeTargetSelectQuery + " WHERE tenant_id = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > now()) ORDER BY priority DESC"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope targets: %w", err)
	}
	defer rows.Close()

	var targets []*scope.Target
	for rows.Next() {
		target, err := r.scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scope target: %w", err)
		}
		targets = append(targets, target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active scope targets: %w", err)
	}

	return targets, nil
}

// Count returns the total number of scope targets matching the filter.
func (r *ScopeTargetRepository) Count(ctx context.Context, filter scope.TargetFilter) (int64, error) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, *filter.TenantID)
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if len(filter.Statuses) > 0 {
		statuses := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statuses[i] = s.String()
		}
		args = append(args, pq.StringArray(statuses))
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", len(args)))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM scope_targets" + whereClause
	var count int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count scope targets: %w", err)
	}

	return count, nil
}

// ExistsByPattern checks if a target with the given pattern exists.
func (r *ScopeTargetRepository) ExistsByPattern(ctx context.Context, tenantID shared.ID, targetType scope.TargetType, pattern string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM scope_targets WHERE tenant_id = $1 AND target_type = $2 AND pattern = $3)"
	var exists bool
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), targetType.String(), pattern).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check scope target existence: %w", err)
	}
	return exists, nil
}
