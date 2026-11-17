package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Audit retention: prefix pruning of a tenant hash chain with an anchor
// (pkg/domain/audit/retention.go). These are platform-privileged operations
// driven by the data-expiration controller, never by a tenant request; every
// statement is still scoped to the one chain (tenant) being pruned.

var _ audit.ChainRetentionRepository = (*AuditRepository)(nil)

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
// the cutoff. A chain of an organization that is not active (suspended, which
// is how a legal hold is applied, or pending deletion) is left alone; the
// system chain and the chains of organizations that no longer exist are not.
func (r *AuditRepository) ChainTenantsWithEntriesBefore(ctx context.Context, before time.Time) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT c.tenant_id
		  FROM audit_log_chain c
		  JOIN audit_logs l ON l.id = c.audit_log_id
		  LEFT JOIN tenants t ON t.id = c.tenant_id
		 WHERE l.logged_at < $1 AND (t.id IS NULL OR t.status = 'active')`, before)
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
		       l.logged_at, row_to_json(l)::text, c.hash_version,
		       CASE WHEN c.hash_version = 2 THEN audit_log_row_payload(l) END
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
			payload             sql.NullString
		)
		if err := rows.Scan(&logID, &tid, &e.Entry.PrevHash, &e.Entry.Hash, &e.Entry.ChainPosition,
			&e.Entry.CreatedAt, &e.LoggedAt, &rowJSON, &e.Entry.HashVersion, &payload); err != nil {
			return nil, fmt.Errorf("scan chain prefix: %w", err)
		}
		e.Entry.AuditLogID, _ = shared.IDFromString(logID)
		e.Entry.TenantID, _ = shared.IDFromString(tid)
		e.Row = []byte(rowJSON)
		e.Entry.RowPayload = payload.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneChainPrefix archives nothing itself: the archive is already stored. It
// calls audit_chain_prune_prefix, which under the chain's advisory lock checks
// that the ids are exactly the chain's entries up to the anchor position, that
// the last one still carries the anchor hash and that every row is older than
// 365 days, then records the anchor and deletes the prefix. The function runs
// as the schema owner; the API role holds no DELETE on the audit tables
// (migration audit_chain_owner_only).
func (r *AuditRepository) PruneChainPrefix(ctx context.Context, anchor audit.ChainAnchor, auditLogIDs []shared.ID) error {
	if len(auditLogIDs) == 0 || len(auditLogIDs) != anchor.PrunedCount {
		return fmt.Errorf("%w: pruned count %d does not match %d ids", shared.ErrValidation, anchor.PrunedCount, len(auditLogIDs))
	}
	ids := make([]string, len(auditLogIDs))
	for i, id := range auditLogIDs {
		ids[i] = id.String()
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
		return err
	}
	var pruned int
	if err := tx.QueryRowContext(ctx, `SELECT audit_chain_prune_prefix($1, $2, $3, $4::uuid[], $5, $6)`,
		anchor.TenantID.String(), anchor.LastChainPosition, anchor.AnchorHash, pq.Array(ids),
		anchor.ArchivePath, anchor.ArchiveSHA256).Scan(&pruned); err != nil {
		if isAuditChainConflict(err) {
			return audit.ErrChainPruneConflict
		}
		return fmt.Errorf("prune chain prefix: %w", err)
	}
	if pruned != len(ids) {
		return audit.ErrChainPruneConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit prune: %w", err)
	}
	return nil
}

// sqlStateAuditChainChanged is the SQLSTATE the audit chain functions raise
// when the chain is no longer what the caller read.
const sqlStateAuditChainChanged = "OC409"

func isAuditChainConflict(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && string(pqErr.Code) == sqlStateAuditChainChanged
}
