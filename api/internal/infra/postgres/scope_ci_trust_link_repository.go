package postgres

// The links between CI trust configurations and the repository scope entries
// they claim (scope_target_ci_trusts). Every query is tenant-scoped; the
// composite foreign keys keep a link inside one tenant.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeCITrustLinkRepository implements scopedom.CITrustLinkRepository.
type ScopeCITrustLinkRepository struct {
	db *DB
}

// NewScopeCITrustLinkRepository creates the repository.
func NewScopeCITrustLinkRepository(db *DB) *ScopeCITrustLinkRepository {
	return &ScopeCITrustLinkRepository{db: db}
}

var _ scopedom.CITrustLinkRepository = (*ScopeCITrustLinkRepository)(nil)

const ciTrustLinkColumns = `l.tenant_id, l.trust_config_id, c.name, l.pattern, l.target_id, l.created_at,
	l.seen_at, l.seen_run_id, COALESCE(l.seen_repository, ''), COALESCE(l.seen_owner_id, ''), l.target_removed_at`

func (r *ScopeCITrustLinkRepository) query(ctx context.Context, q string, args ...any) ([]scopedom.CITrustLink, error) {
	return r.scan(ctx, false, q, args...)
}

// scan reads links; withVisible: the query ends with a boolean column that
// says whether the caller may see the evidence's repository, and the
// evidence's repository, run and owner are left out when they may not.
func (r *ScopeCITrustLinkRepository) scan(ctx context.Context, withVisible bool, q string, args ...any) ([]scopedom.CITrustLink, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list ci trust scope links: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scopedom.CITrustLink
	for rows.Next() {
		var (
			l                   scopedom.CITrustLink
			tid, cid            string
			target, seenRun     sql.NullString
			seenAt, removedAt   sql.NullTime
			seenRepo, seenOwner string
		)
		visible := true
		dest := []any{&tid, &cid, &l.TrustName, &l.Pattern, &target, &l.CreatedAt, &seenAt, &seenRun,
			&seenRepo, &seenOwner, &removedAt}
		if withVisible {
			dest = append(dest, &visible)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan ci trust scope link: %w", err)
		}
		l.TenantID, _ = shared.IDFromString(tid)
		l.TrustConfigID, _ = shared.IDFromString(cid)
		l.TargetID = parseOptID(target)
		l.SeenAt = optTime(seenAt)
		l.SeenRunID = parseOptID(seenRun)
		l.SeenRepository, l.SeenOwnerID = seenRepo, seenOwner
		l.TargetRemovedAt = optTime(removedAt)
		if !visible {
			l.SeenRunID, l.SeenRepository, l.SeenOwnerID = nil, "", ""
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListByTrust lists a trust's links.
func (r *ScopeCITrustLinkRepository) ListByTrust(ctx context.Context, tenantID, trustID shared.ID) ([]scopedom.CITrustLink, error) {
	return r.query(ctx, `SELECT `+ciTrustLinkColumns+`
		FROM scope_target_ci_trusts l
		JOIN ci_trust_configs c ON c.tenant_id = l.tenant_id AND c.id = l.trust_config_id
		WHERE l.tenant_id = $1 AND l.trust_config_id = $2
		ORDER BY l.pattern`, tenantID.String(), trustID.String())
}

// ListVisible lists the links of one trust, or of every trust of the tenant
// (trustID nil), in one query, for a reader with this data scope: the
// evidence's repository, run and owner are kept only when the reader may
// see the run's repository asset (nil scope: everything). A restricted
// reader sees none of it once the run is gone (fail closed).
func (r *ScopeCITrustLinkRepository) ListVisible(ctx context.Context, tenantID shared.ID, trustID *shared.ID, scope *shared.DataScope) ([]scopedom.CITrustLink, error) {
	args := []any{tenantID.String()}
	where := `l.tenant_id = $1`
	if trustID != nil {
		args = append(args, trustID.String())
		where += ` AND l.trust_config_id = $2`
	}
	visible := sqlTrue
	if scope != nil {
		var cond string
		cond, args = dataScopeCond("cr.repository_asset_id", scope, args)
		visible = `EXISTS (SELECT 1 FROM ci_runs cr WHERE cr.tenant_id = l.tenant_id AND cr.id = l.seen_run_id AND ` + cond + `)`
	}
	return r.scan(ctx, true, `SELECT `+ciTrustLinkColumns+`, `+visible+`
		FROM scope_target_ci_trusts l
		JOIN ci_trust_configs c ON c.tenant_id = l.tenant_id AND c.id = l.trust_config_id
		WHERE `+where+`
		ORDER BY l.trust_config_id, l.pattern`, args...)
}

// ListByTargets lists the links of these entries, with the trust names.
func (r *ScopeCITrustLinkRepository) ListByTargets(ctx context.Context, tenantID shared.ID, targetIDs []shared.ID) ([]scopedom.CITrustLink, error) {
	if len(targetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(targetIDs))
	for _, id := range targetIDs {
		ids = append(ids, id.String())
	}
	return r.query(ctx, `SELECT `+ciTrustLinkColumns+`
		FROM scope_target_ci_trusts l
		JOIN ci_trust_configs c ON c.tenant_id = l.tenant_id AND c.id = l.trust_config_id
		WHERE l.tenant_id = $1 AND l.target_id = ANY($2::uuid[])
		ORDER BY c.name, l.pattern`, tenantID.String(), pq.Array(ids))
}

// Put inserts a link or points an existing one at targetID.
func (r *ScopeCITrustLinkRepository) Put(ctx context.Context, tenantID, trustID shared.ID, pattern string, targetID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO scope_target_ci_trusts (tenant_id, trust_config_id, pattern, target_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, trust_config_id, pattern) DO UPDATE SET target_id = EXCLUDED.target_id`,
		tenantID.String(), trustID.String(), pattern, targetID.String())
	if err != nil {
		return fmt.Errorf("put ci trust scope link: %w", err)
	}
	return nil
}

// Delete removes a link.
func (r *ScopeCITrustLinkRepository) Delete(ctx context.Context, tenantID, trustID shared.ID, pattern string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM scope_target_ci_trusts
		WHERE tenant_id = $1 AND trust_config_id = $2 AND pattern = $3`, tenantID.String(), trustID.String(), pattern)
	if err != nil {
		return fmt.Errorf("delete ci trust scope link: %w", err)
	}
	return nil
}

// CountForTarget counts the links that point at an entry.
func (r *ScopeCITrustLinkRepository) CountForTarget(ctx context.Context, tenantID, targetID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scope_target_ci_trusts
		WHERE tenant_id = $1 AND target_id = $2`, tenantID.String(), targetID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count ci trust scope links: %w", err)
	}
	return n, nil
}

// MarkTargetRemoved records on every link to the entry that a person
// deleted it.
func (r *ScopeCITrustLinkRepository) MarkTargetRemoved(ctx context.Context, tenantID, targetID shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE scope_target_ci_trusts SET target_removed_at = $3
		WHERE tenant_id = $1 AND target_id = $2`, tenantID.String(), targetID.String(), at)
	if err != nil {
		return fmt.Errorf("mark ci trust scope links removed: %w", err)
	}
	return nil
}

// MarkSeen records the evidence on a link that has none.
func (r *ScopeCITrustLinkRepository) MarkSeen(ctx context.Context, tenantID, trustID shared.ID, pattern string, ev scopedom.CITrustEvidence) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE scope_target_ci_trusts
		SET seen_at = $4, seen_run_id = $5, seen_repository = $6, seen_owner_id = NULLIF($7, '')
		WHERE tenant_id = $1 AND trust_config_id = $2 AND pattern = $3 AND seen_at IS NULL`,
		tenantID.String(), trustID.String(), pattern, ev.At, nullID(&ev.RunID), truncate(ev.Repository, 500),
		truncate(ev.OwnerID, 64))
	if err != nil {
		return false, fmt.Errorf("mark ci trust scope link seen: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
