package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Audit retention: prefix pruning of a tenant hash chain with an anchor
// (pkg/domain/audit/retention.go). These are platform-privileged operations
// driven by the data-expiration controller, never by a tenant request; every
// statement is still scoped to the one chain (tenant) being pruned.

var _ audit.ChainRetentionRepository = (*AuditRepository)(nil)

// chainLockKey is the advisory lock AppendNextChainEntry takes, so a prune and
// an append of the same chain never interleave.
const chainLockQuery = `SELECT pg_advisory_xact_lock(hashtext('audit_log_chain'), hashtext($1))`

// ChainAnchorHash returns the newest anchor hash of a tenant chain, or "".
func (r *AuditRepository) ChainAnchorHash(ctx context.Context, tenantID shared.ID) (string, error) {
	return chainAnchorHash(ctx, r.db, tenantID)
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func chainAnchorHash(ctx context.Context, q queryRower, tenantID shared.ID) (string, error) {
	var hash string
	err := q.QueryRowContext(ctx, `
		SELECT anchor_hash FROM audit_chain_anchors
		 WHERE tenant_id = $1
		 ORDER BY last_chain_position DESC
		 LIMIT 1`, tenantID.String()).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("chain anchor: %w", err)
	}
	return hash, nil
}

// ChainTenantsWithEntriesBefore lists the chains with an entry logged before
// the cutoff.
func (r *AuditRepository) ChainTenantsWithEntriesBefore(ctx context.Context, before time.Time) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT c.tenant_id
		  FROM audit_log_chain c
		  JOIN audit_logs l ON l.id = c.audit_log_id
		 WHERE l.logged_at < $1`, before)
	if err != nil {
		return nil, fmt.Errorf("list chains to prune: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan chain tenant: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ChainPrefixOlderThan returns the oldest entries of a chain up to (not
// including) the first entry logged at or after before.
func (r *AuditRepository) ChainPrefixOlderThan(ctx context.Context, tenantID shared.ID, before time.Time, limit int) ([]audit.PrunableEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH stop AS (
			SELECT MIN(c.chain_position) AS pos
			  FROM audit_log_chain c
			  JOIN audit_logs l ON l.id = c.audit_log_id
			 WHERE c.tenant_id = $1 AND l.logged_at >= $2
		)
		SELECT c.audit_log_id, c.tenant_id, c.prev_hash, c.hash, c.chain_position, c.created_at,
		       l.logged_at, row_to_json(l)::text
		  FROM audit_log_chain c
		  JOIN audit_logs l ON l.id = c.audit_log_id
		 CROSS JOIN stop
		 WHERE c.tenant_id = $1
		   AND (stop.pos IS NULL OR c.chain_position < stop.pos)
		 ORDER BY c.chain_position
		 LIMIT $3`, tenantID.String(), before, limit)
	if err != nil {
		return nil, fmt.Errorf("read chain prefix: %w", err)
	}
	defer rows.Close()
	var out []audit.PrunableEntry
	for rows.Next() {
		var (
			e                   audit.PrunableEntry
			logID, tid, rowJSON string
		)
		if err := rows.Scan(&logID, &tid, &e.Entry.PrevHash, &e.Entry.Hash, &e.Entry.ChainPosition,
			&e.Entry.CreatedAt, &e.LoggedAt, &rowJSON); err != nil {
			return nil, fmt.Errorf("scan chain prefix: %w", err)
		}
		e.Entry.AuditLogID, _ = shared.IDFromString(logID)
		e.Entry.TenantID, _ = shared.IDFromString(tid)
		e.Row = []byte(rowJSON)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneChainPrefix records the anchor and deletes the pruned prefix, all in
// one transaction under the chain's advisory lock.
func (r *AuditRepository) PruneChainPrefix(ctx context.Context, anchor audit.ChainAnchor, auditLogIDs []shared.ID) error {
	if len(auditLogIDs) == 0 || len(auditLogIDs) != anchor.PrunedCount {
		return fmt.Errorf("%w: pruned count %d does not match %d ids", shared.ErrValidation, anchor.PrunedCount, len(auditLogIDs))
	}
	tenant := anchor.TenantID.String()
	ids := make([]string, len(auditLogIDs))
	for i, id := range auditLogIDs {
		ids[i] = id.String()
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, chainLockQuery, tenant); err != nil {
		return fmt.Errorf("lock chain: %w", err)
	}

	// The ids must be exactly the entries at or before the last position,
	// and the last one must still carry the anchor hash. Otherwise the chain
	// changed (a rebaseline rewrote it, or the read raced an append).
	var atOrBefore, matching int
	var lastHash sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE chain_position <= $2),
		       COUNT(*) FILTER (WHERE chain_position <= $2 AND audit_log_id = ANY($3::uuid[])),
		       MAX(hash) FILTER (WHERE chain_position = $2)
		  FROM audit_log_chain
		 WHERE tenant_id = $1`, tenant, anchor.LastChainPosition, pq.Array(ids)).
		Scan(&atOrBefore, &matching, &lastHash); err != nil {
		return fmt.Errorf("check prefix: %w", err)
	}
	if atOrBefore != len(ids) || matching != len(ids) || !lastHash.Valid || lastHash.String != anchor.AnchorHash {
		return audit.ErrChainPruneConflict
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_chain_anchors (tenant_id, anchor_hash, last_chain_position, pruned_count,
			oldest_logged_at, newest_logged_at, archive_path, archive_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tenant, anchor.AnchorHash, anchor.LastChainPosition, anchor.PrunedCount,
		anchor.OldestLoggedAt, anchor.NewestLoggedAt, anchor.ArchivePath, anchor.ArchiveSHA256); err != nil {
		return fmt.Errorf("record anchor: %w", err)
	}
	// Rebaseline evidence for these rows is in the archive too.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM audit_chain_rebaseline_entries
		 WHERE tenant_id = $1 AND audit_log_id = ANY($2::uuid[])`, tenant, pq.Array(ids)); err != nil {
		return fmt.Errorf("prune rebaseline entries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM audit_log_chain
		 WHERE tenant_id = $1 AND audit_log_id = ANY($2::uuid[])`, tenant, pq.Array(ids)); err != nil {
		return fmt.Errorf("prune chain entries: %w", err)
	}
	// System-chain rows have no tenant; tenant rows must belong to the chain.
	res, err := tx.ExecContext(ctx, `
		DELETE FROM audit_logs
		 WHERE id = ANY($2::uuid[])
		   AND (tenant_id = $1::uuid OR ($1::uuid = $3::uuid AND tenant_id IS NULL))`,
		tenant, pq.Array(ids), audit.SystemChainTenantID.String())
	if err != nil {
		return fmt.Errorf("prune audit logs: %w", err)
	}
	if n, _ := res.RowsAffected(); n != int64(len(ids)) {
		return audit.ErrChainPruneConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit prune: %w", err)
	}
	return nil
}
