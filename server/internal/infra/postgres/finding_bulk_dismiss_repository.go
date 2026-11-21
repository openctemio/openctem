package postgres

// Bulk dismissals of findings (docs/architecture/findings-bulk-by-filter.md,
// "Bulk dismiss"): the idempotency record, the per-person 24-hour budget of
// findings decided alone, and what an undo reopens. Every query is scoped to
// one tenant and the row's creator.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// FindingBulkDismissRepository stores bulk dismissals.
type FindingBulkDismissRepository struct {
	db *DB
}

// NewFindingBulkDismissRepository creates a FindingBulkDismissRepository.
func NewFindingBulkDismissRepository(db *DB) *FindingBulkDismissRepository {
	return &FindingBulkDismissRepository{db: db}
}

var _ finding.BulkDismissStore = (*FindingBulkDismissRepository)(nil)

const bulkDismissColumns = `id::text, tenant_id::text, created_by::text, COALESCE(idempotency_key, ''), request_hash,
	requested_status, closure_reason, source_label, COALESCE(filter_hash, ''), decided_ids::text[], batch_id::text,
	result, decided_count, grouped_count, skipped_count, status, created_at`

// bulkDismissBudgetLock serializes one person's reservations in a tenant.
const bulkDismissBudgetLock = `SELECT pg_advisory_xact_lock(hashtextextended('finding_bulk_dismiss|' || $1 || '|' || $2, 0))`

func scanBulkDismissal(row rowScanner) (*finding.BulkDismissal, error) {
	var (
		d                       finding.BulkDismissal
		id, tenantID, createdBy string
		decided                 pq.StringArray
		batch                   sql.NullString
		result                  []byte
	)
	if err := row.Scan(&id, &tenantID, &createdBy, &d.IdempotencyKey, &d.RequestHash, &d.RequestedStatus, &d.ClosureReason,
		&d.SourceLabel, &d.FilterHash, &decided, &batch, &result, &d.DecidedCount, &d.GroupedCount, &d.SkippedCount,
		&d.Status, &d.CreatedAt); err != nil {
		return nil, err
	}
	var err error
	if d.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("bulk dismissal id: %w", err)
	}
	if d.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("bulk dismissal tenant: %w", err)
	}
	if d.CreatedBy, err = shared.IDFromString(createdBy); err != nil {
		return nil, fmt.Errorf("bulk dismissal creator: %w", err)
	}
	for _, s := range decided {
		if fid, err := shared.IDFromString(s); err == nil {
			d.DecidedIDs = append(d.DecidedIDs, fid)
		}
	}
	if batch.Valid {
		if bid, err := shared.IDFromString(batch.String); err == nil {
			d.BatchID = &bid
		}
	}
	d.Result = result
	return &d, nil
}

// ByKey reads the creator's bulk dismissal with this idempotency key.
func (r *FindingBulkDismissRepository) ByKey(ctx context.Context, tenantID, createdBy shared.ID, key string) (*finding.BulkDismissal, error) {
	d, err := scanBulkDismissal(r.db.QueryRowContext(ctx, `SELECT `+bulkDismissColumns+` FROM finding_bulk_dismissals
		WHERE tenant_id = $1 AND created_by = $2 AND idempotency_key = $3`,
		tenantID.String(), createdBy.String(), key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, finding.ErrBulkDismissNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get bulk dismissal by key: %w", err)
	}
	return d, nil
}

// Get reads the creator's bulk dismissal; anything else is not found.
func (r *FindingBulkDismissRepository) Get(ctx context.Context, tenantID, createdBy, id shared.ID) (*finding.BulkDismissal, error) {
	d, err := scanBulkDismissal(r.db.QueryRowContext(ctx, `SELECT `+bulkDismissColumns+` FROM finding_bulk_dismissals
		WHERE tenant_id = $1 AND created_by = $2 AND id = $3`,
		tenantID.String(), createdBy.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, finding.ErrBulkDismissNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get bulk dismissal: %w", err)
	}
	return d, nil
}

func decidedSince(ctx context.Context, q queryRower, tenantID, createdBy shared.ID, since time.Time) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(SUM(decided_count), 0) FROM finding_bulk_dismissals
		WHERE tenant_id = $1 AND created_by = $2 AND created_at > $3`,
		tenantID.String(), createdBy.String(), since).Scan(&n); err != nil {
		return 0, fmt.Errorf("read the bulk dismiss budget: %w", err)
	}
	return n, nil
}

// DecidedSince sums the findings the creator decided alone since since
// (an undone bulk still counts: undoing does not give the budget back).
func (r *FindingBulkDismissRepository) DecidedSince(ctx context.Context, tenantID, createdBy shared.ID, since time.Time) (int, error) {
	return decidedSince(ctx, r.db, tenantID, createdBy, since)
}

// Reserve inserts d, reserving the part of want that fits the creator's
// budget, under a per-(tenant, creator) advisory lock held for the
// transaction: two concurrent calls cannot both spend the same room.
func (r *FindingBulkDismissRepository) Reserve(ctx context.Context, d *finding.BulkDismissal, want, budget int, since time.Time) (*finding.BulkDismissal, int, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, false, fmt.Errorf("begin bulk dismissal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, bulkDismissBudgetLock, d.TenantID.String(), d.CreatedBy.String()); err != nil {
		return nil, 0, false, fmt.Errorf("lock the bulk dismiss budget: %w", err)
	}
	if d.IdempotencyKey != "" {
		prev, err := scanBulkDismissal(tx.QueryRowContext(ctx, `SELECT `+bulkDismissColumns+` FROM finding_bulk_dismissals
			WHERE tenant_id = $1 AND created_by = $2 AND idempotency_key = $3`,
			d.TenantID.String(), d.CreatedBy.String(), d.IdempotencyKey))
		if err == nil {
			return prev, 0, true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, 0, false, fmt.Errorf("get bulk dismissal by key: %w", err)
		}
	}
	used, err := decidedSince(ctx, tx, d.TenantID, d.CreatedBy, since)
	if err != nil {
		return nil, 0, false, err
	}
	granted := min(max(budget-used, 0), want)
	var key, filterHash any
	if d.IdempotencyKey != "" {
		key = d.IdempotencyKey
	}
	if d.FilterHash != "" {
		filterHash = d.FilterHash
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_bulk_dismissals
		(id, tenant_id, created_by, idempotency_key, request_hash, requested_status, closure_reason, source_label,
		 filter_hash, decided_count, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'applied')`,
		d.ID.String(), d.TenantID.String(), d.CreatedBy.String(), key, d.RequestHash, d.RequestedStatus, d.ClosureReason,
		d.SourceLabel, filterHash, granted); err != nil {
		return nil, 0, false, fmt.Errorf("insert bulk dismissal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, false, fmt.Errorf("commit bulk dismissal: %w", err)
	}
	d.DecidedCount = granted
	return d, granted, false, nil
}

// Finish records the outcome of the apply.
func (r *FindingBulkDismissRepository) Finish(ctx context.Context, d *finding.BulkDismissal) error {
	ids := make([]string, 0, len(d.DecidedIDs))
	for _, id := range d.DecidedIDs {
		ids = append(ids, id.String())
	}
	var batch any
	if d.BatchID != nil {
		batch = d.BatchID.String()
	}
	result := d.Result
	if len(result) == 0 {
		result = []byte("{}")
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE finding_bulk_dismissals
		SET decided_ids = $4::uuid[], batch_id = $5, result = $6::jsonb,
		    decided_count = $7, grouped_count = $8, skipped_count = $9
		WHERE tenant_id = $1 AND created_by = $2 AND id = $3`,
		d.TenantID.String(), d.CreatedBy.String(), d.ID.String(), pq.Array(ids), batch, string(result),
		d.DecidedCount, d.GroupedCount, d.SkippedCount); err != nil {
		return fmt.Errorf("record bulk dismissal: %w", err)
	}
	return nil
}

// MarkUndone moves the creator's applied row created after since to
// undone; false when no row moved (undone already, too old, not theirs, or the
// apply has not recorded its outcome yet).
func (r *FindingBulkDismissRepository) MarkUndone(ctx context.Context, tenantID, createdBy, id shared.ID, since time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE finding_bulk_dismissals
		SET status = 'undone', undone_at = now(), undone_by = $2
		WHERE tenant_id = $1 AND created_by = $2 AND id = $3 AND status = 'applied' AND result <> '{}'::jsonb AND created_at > $4`,
		tenantID.String(), createdBy.String(), id.String(), since)
	if err != nil {
		return false, fmt.Errorf("undo bulk dismissal: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("undo bulk dismissal: %w", err)
	}
	return n == 1, nil
}
