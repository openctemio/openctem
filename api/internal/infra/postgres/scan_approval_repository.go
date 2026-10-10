package postgres

// Scan approval requests and the scan approver directory (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md). Every query carries the
// tenant: a request of one organization is never read or written through
// another.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanApprovalRepository implements scangov.Repository.
type ScanApprovalRepository struct{ db *DB }

// NewScanApprovalRepository creates the repository.
func NewScanApprovalRepository(db *DB) *ScanApprovalRepository {
	return &ScanApprovalRepository{db: db}
}

var _ scangov.Repository = (*ScanApprovalRepository)(nil)

const scanApprovalPermission = "scans:approve"

const (
	approverFallbackName   = "Member"
	scanApproverRoleMember = "member"
)

// maxScanApprovers bounds the directory read.
const maxScanApprovers = 500

// ScanApprovers lists the organization's active members who may approve
// scans: owners, administrators and holders of scans:approve through a role.
func (r *ScanApprovalRepository) ScanApprovers(ctx context.Context, tenantID shared.ID) ([]scangov.Approver, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id::text, u.name, u.email, COALESCE(ver.role, '')
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id AND u.status = 'active'
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())
		  AND (ver.role IN ('owner', 'admin') OR EXISTS (
		        SELECT 1 FROM user_roles ur
		        JOIN role_permissions rp ON rp.role_id = ur.role_id
		        JOIN permissions p ON p.id = rp.permission_id AND p.is_active = TRUE
		        WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id
		          AND rp.permission_id = $2))
		ORDER BY COALESCE(ver.role = 'owner', false) DESC, u.name, u.id
		LIMIT $3`,
		tenantID.String(), scanApprovalPermission, maxScanApprovers)
	if err != nil {
		return nil, fmt.Errorf("list scan approvers: %w", err)
	}
	defer rows.Close()
	var out []scangov.Approver
	for rows.Next() {
		var a scangov.Approver
		if err := rows.Scan(&a.UserID, &a.Name, &a.Email, &a.Role); err != nil {
			return nil, fmt.Errorf("scan scan approver: %w", err)
		}
		if a.Name = strings.TrimSpace(a.Name); a.Name == "" {
			a.Name = approverFallbackName
		}
		if a.Role != scangov.RoleOwner && a.Role != scangov.RoleAdmin {
			a.Role = scanApproverRoleMember
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RequesterProfile answers what the requester conditions of the approval
// rules read about a member of the tenant: the effective role and every
// role id held there, the tenant's active groups they belong to, and
// whether they are one of the tenant's service accounts. Not a member:
// an empty profile.
func (r *ScanApprovalRepository) RequesterProfile(ctx context.Context, tenantID shared.ID, userID string) (scangov.Requester, error) {
	out := scangov.Requester{UserID: userID}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return out, nil //nolint:nilerr // not a user id: nobody, an empty profile
	}
	var role string
	var roles, groups pq.StringArray
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(ver.role, ''),
		       COALESCE(u.kind = 'service' AND u.service_tenant_id = m.tenant_id, false),
		       COALESCE(ARRAY(SELECT ur.role_id::text FROM user_roles ur
		                      WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id ORDER BY 1), '{}'),
		       COALESCE(ARRAY(SELECT g.id::text FROM group_members gm JOIN groups g ON g.id = gm.group_id
		                      WHERE g.tenant_id = m.tenant_id AND g.is_active AND gm.user_id = m.user_id ORDER BY 1 LIMIT 200), '{}')
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active'`,
		tenantID.String(), uid.String()).Scan(&role, &out.ServiceAccount, &roles, &groups)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("read scan requester: %w", err)
	}
	if role != "" {
		out.Roles = append(out.Roles, role)
	}
	out.Roles = append(out.Roles, roles...)
	out.GroupIDs = groups
	return out, nil
}

const scanApprovalColumns = `r.id, r.tenant_id, r.scan_id, COALESCE(s.name, ''), r.status, r.definition_digest, r.definition,
	r.changes, r.evaluation, r.justification, r.ticket, r.run_on_approval, r.requested_by, r.requested_at, r.expires_at,
	r.approvals, r.valid_until, r.consumed_at, r.decided_at, r.decided_by, r.decision_note, r.reminded_at, r.emergency,
	r.created_at, r.updated_at`

const scanApprovalFrom = `FROM scan_approval_requests r
	LEFT JOIN scans s ON s.id = r.scan_id AND s.tenant_id = r.tenant_id`

func nullUUID(s string) any {
	if _, err := shared.IDFromString(s); err != nil {
		return nil
	}
	return s
}

// Create inserts a request.
func (r *ScanApprovalRepository) Create(ctx context.Context, q *scangov.Request) error {
	def, ch, ev, ap, err := encodeRequest(q)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_approval_requests (id, tenant_id, scan_id, status, definition_digest, definition, changes, evaluation,
			justification, ticket, run_on_approval, requested_by, requested_at, expires_at, approvals, valid_until,
			consumed_at, decided_at, decided_by, decision_note, reminded_at, emergency, created_at, updated_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
		WHERE EXISTS (SELECT 1 FROM scans WHERE id = $3 AND tenant_id = $2)`,
		q.ID.String(), q.TenantID.String(), q.ScanID.String(), string(q.Status), q.Digest, def, ch, ev,
		q.Justification, q.Ticket, q.RunOnApproval, nullUUID(q.RequestedBy), q.RequestedAt, q.ExpiresAt, ap, q.ValidUntil,
		q.ConsumedAt, q.DecidedAt, nullUUID(q.DecidedBy), q.DecisionNote, q.RemindedAt, q.Emergency, q.CreatedAt, q.UpdatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return scangov.ErrNotPending
		}
		return fmt.Errorf("create scan approval request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound // not the tenant's scan
	}
	return nil
}

func encodeRequest(q *scangov.Request) (def, ch, ev, ap []byte, err error) {
	if def, err = json.Marshal(q.Definition); err != nil {
		return
	}
	changes := q.Changes
	if changes == nil {
		changes = []scangov.Change{}
	}
	if ch, err = json.Marshal(changes); err != nil {
		return
	}
	if ev, err = json.Marshal(q.Evaluation); err != nil {
		return
	}
	approvals := q.Approvals
	if approvals == nil {
		approvals = []scangov.Approval{}
	}
	ap, err = json.Marshal(approvals)
	return
}

// Update saves q when its stored status is still expect.
func (r *ScanApprovalRepository) Update(ctx context.Context, q *scangov.Request, expect scangov.Status) (bool, error) {
	_, _, _, ap, err := encodeRequest(q)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_approval_requests
		   SET status = $3, approvals = $4, valid_until = $5, decided_at = $6, decided_by = $7, decision_note = $8, updated_at = $9
		 WHERE tenant_id = $1 AND id = $2 AND status = $10`,
		q.TenantID.String(), q.ID.String(), string(q.Status), ap, q.ValidUntil, q.DecidedAt, nullUUID(q.DecidedBy),
		q.DecisionNote, q.UpdatedAt, string(expect))
	if err != nil {
		return false, fmt.Errorf("update scan approval request: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (r *ScanApprovalRepository) one(ctx context.Context, where string, args ...any) (*scangov.Request, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+scanApprovalColumns+` `+scanApprovalFrom+` WHERE `+where+` LIMIT 1`, args...)
	q, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return q, err
}

// Get returns the tenant's request id.
func (r *ScanApprovalRepository) Get(ctx context.Context, tenantID, id shared.ID) (*scangov.Request, error) {
	q, err := r.one(ctx, `r.tenant_id = $1 AND r.id = $2`, tenantID.String(), id.String())
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, shared.ErrNotFound
	}
	return q, nil
}

// Pending returns the scan's pending request.
func (r *ScanApprovalRepository) Pending(ctx context.Context, tenantID, scanID shared.ID) (*scangov.Request, error) {
	return r.one(ctx, `r.tenant_id = $1 AND r.scan_id = $2 AND r.status = 'pending'`, tenantID.String(), scanID.String())
}

// ApprovedFor returns the scan's newest approved request for digest.
func (r *ScanApprovalRepository) ApprovedFor(ctx context.Context, tenantID, scanID shared.ID, digest string) (*scangov.Request, error) {
	return r.one(ctx, `r.tenant_id = $1 AND r.scan_id = $2 AND r.status = 'approved' AND r.definition_digest = $3
		ORDER BY r.decided_at DESC NULLS LAST, r.created_at DESC`, tenantID.String(), scanID.String(), digest)
}

// LastApproved returns the scan's newest approved request that was not an
// emergency (the definition people last reviewed).
func (r *ScanApprovalRepository) LastApproved(ctx context.Context, tenantID, scanID shared.ID) (*scangov.Request, error) {
	return r.one(ctx, `r.tenant_id = $1 AND r.scan_id = $2 AND r.status = 'approved' AND NOT r.emergency
		ORDER BY r.decided_at DESC NULLS LAST, r.created_at DESC`, tenantID.String(), scanID.String())
}

// SupersedePending closes the scan's pending requests whose digest is not keep.
func (r *ScanApprovalRepository) SupersedePending(ctx context.Context, tenantID, scanID shared.ID, keep string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE scan_approval_requests SET status = 'superseded', decided_at = $4, updated_at = $4
		 WHERE tenant_id = $1 AND scan_id = $2 AND status = 'pending' AND definition_digest <> $3`,
		tenantID.String(), scanID.String(), keep, now.UTC())
	if err != nil {
		return fmt.Errorf("supersede scan approval requests: %w", err)
	}
	return nil
}

// Consume marks a run-only approval used.
func (r *ScanApprovalRepository) Consume(ctx context.Context, tenantID, id shared.ID, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_approval_requests SET consumed_at = $3, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND status = 'approved' AND consumed_at IS NULL`,
		tenantID.String(), id.String(), now.UTC())
	if err != nil {
		return false, fmt.Errorf("consume scan approval: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// MarkReminded records a reminder at most once per interval.
func (r *ScanApprovalRepository) MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, interval time.Duration) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_approval_requests SET reminded_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		   AND (reminded_at IS NULL OR reminded_at <= $3::timestamptz - ($4::float8 * interval '1 second'))`,
		tenantID.String(), id.String(), now.UTC(), interval.Seconds())
	if err != nil {
		return false, fmt.Errorf("mark scan approval reminded: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ExpireOverdue marks the tenant's overdue pending requests expired.
func (r *ScanApprovalRepository) ExpireOverdue(ctx context.Context, tenantID shared.ID, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_approval_requests SET status = 'expired', updated_at = $2
		 WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2`, tenantID.String(), now.UTC())
	if err != nil {
		return 0, fmt.Errorf("expire scan approval requests: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// scanApprovalPageCap is the largest page List returns.
const scanApprovalPageCap = 100

// List returns a page of the tenant's requests, newest first.
func (r *ScanApprovalRepository) List(ctx context.Context, f scangov.ListFilter) ([]*scangov.Request, int, error) {
	if f.Limit <= 0 || f.Limit > scanApprovalPageCap {
		f.Limit = scanApprovalPageCap
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"r.tenant_id = $1"}
	args := []any{f.TenantID.String()}
	if len(f.Statuses) > 0 {
		st := make([]string, 0, len(f.Statuses))
		for _, s := range f.Statuses {
			st = append(st, string(s))
		}
		args = append(args, pq.Array(st))
		where = append(where, fmt.Sprintf("r.status = ANY($%d)", len(args)))
	}
	if f.ScanID != nil {
		args = append(args, f.ScanID.String())
		where = append(where, fmt.Sprintf("r.scan_id = $%d", len(args)))
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_approval_requests r WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scan approval requests: %w", err)
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+scanApprovalColumns+` `+scanApprovalFrom+` WHERE `+cond+
		fmt.Sprintf(` ORDER BY r.requested_at DESC, r.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scan approval requests: %w", err)
	}
	defer rows.Close()
	out := make([]*scangov.Request, 0, scanApprovalPageCap)
	for rows.Next() {
		q, err := scanRequest(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, q)
	}
	return out, total, rows.Err()
}

// LatestByScans returns the newest request of each scan.
func (r *ScanApprovalRepository) LatestByScans(ctx context.Context, tenantID shared.ID, scanIDs []shared.ID) (map[shared.ID]*scangov.Request, error) {
	ids := make([]string, 0, len(scanIDs))
	for _, id := range scanIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ON (r.scan_id) `+scanApprovalColumns+` `+scanApprovalFrom+`
		WHERE r.tenant_id = $1 AND r.scan_id = ANY($2)
		ORDER BY r.scan_id, r.created_at DESC`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("latest scan approval requests: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]*scangov.Request{}
	for rows.Next() {
		q, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out[q.ScanID] = q
	}
	return out, rows.Err()
}

func scanRequest(row rowScanner) (*scangov.Request, error) {
	var (
		q                                   scangov.Request
		id, tid, sid, status                string
		def, ch, ev, ap                     []byte
		requestedBy, decidedBy              sql.NullString
		validUntil, consumed, decided, remd sql.NullTime
	)
	if err := row.Scan(&id, &tid, &sid, &q.ScanName, &status, &q.Digest, &def, &ch, &ev, &q.Justification, &q.Ticket,
		&q.RunOnApproval, &requestedBy, &q.RequestedAt, &q.ExpiresAt, &ap, &validUntil, &consumed, &decided, &decidedBy,
		&q.DecisionNote, &remd, &q.Emergency, &q.CreatedAt, &q.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan scan approval request: %w", err)
	}
	var err error
	if q.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if q.TenantID, err = shared.IDFromString(tid); err != nil {
		return nil, err
	}
	if q.ScanID, err = shared.IDFromString(sid); err != nil {
		return nil, err
	}
	q.Status = scangov.Status(status)
	for _, d := range []struct {
		raw []byte
		dst any
	}{{def, &q.Definition}, {ch, &q.Changes}, {ev, &q.Evaluation}, {ap, &q.Approvals}} {
		if err := json.Unmarshal(d.raw, d.dst); err != nil {
			return nil, fmt.Errorf("decode scan approval request: %w", err)
		}
	}
	q.RequestedBy, q.DecidedBy = requestedBy.String, decidedBy.String
	q.ValidUntil, q.ConsumedAt, q.DecidedAt, q.RemindedAt = approvalTime(validUntil), approvalTime(consumed), approvalTime(decided), approvalTime(remd)
	return &q, nil
}

func approvalTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

// maxFactTags bounds the distinct tags read for the rules.
const maxFactTags = 500

// TargetAssetFacts reads the tenant's assets a scan targets: by name among
// the direct targets, as members of its asset groups, and at or under the
// roots of its wildcard selectors.
func (r *ScanApprovalRepository) TargetAssetFacts(ctx context.Context, tenantID shared.ID, names []string, groupIDs []shared.ID, wildcardRoots []string) (scangov.AssetFacts, error) {
	groups := make([]string, 0, len(groupIDs))
	for _, g := range groupIDs {
		groups = append(groups, g.String())
	}
	roots := make([]string, 0, len(wildcardRoots))
	likes := make([]string, 0, len(wildcardRoots))
	for _, w := range wildcardRoots {
		w = strings.ToLower(w)
		roots = append(roots, w)
		likes = append(likes, "%."+escapeApprovalLike(w))
	}
	var (
		f    scangov.AssetFacts
		tags pq.StringArray
		rank int
	)
	err := r.db.QueryRowContext(ctx, `
		WITH a AS (
			SELECT a.id, a.tags, a.criticality, a.is_crown_jewel,
			       NOT (a.name = ANY($2)) AS expanded
			FROM assets a
			WHERE a.tenant_id = $1 AND (
			      a.name = ANY($2)
			   OR a.id IN (SELECT m.asset_id FROM asset_group_members m
			               JOIN asset_groups g ON g.id = m.asset_group_id AND g.tenant_id = $1
			               WHERE m.asset_group_id = ANY($3))
			   OR lower(a.name) = ANY($4)
			   OR lower(a.name) LIKE ANY($5))
		)
		SELECT count(*) FILTER (WHERE expanded),
		       COALESCE((SELECT array_agg(t) FROM (SELECT DISTINCT t FROM a, unnest(a.tags) t LIMIT $6) x), '{}'),
		       COALESCE(max(CASE lower(criticality) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
		                    WHEN 'low' THEN 1 ELSE 0 END), 0),
		       COALESCE(bool_or(is_crown_jewel), false)
		FROM a`,
		tenantID.String(), pq.Array(names), pq.Array(groups), pq.Array(roots), pq.Array(likes), maxFactTags,
	).Scan(&f.Expanded, &tags, &rank, &f.CrownJewel)
	if err != nil {
		return f, fmt.Errorf("read target asset facts: %w", err)
	}
	f.Tags = tags
	f.MaxCriticality = [...]string{"none", "low", "medium", "high", "critical"}[min(max(rank, 0), 4)]
	return f, nil
}

// escapeApprovalLike escapes the LIKE wildcards of s (backslash is the
// default escape character).
func escapeApprovalLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
