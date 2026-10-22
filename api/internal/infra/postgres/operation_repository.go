package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/operation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OperationRepository stores operations (docs/architecture/operations.md).
// Every statement is bound to the tenant, and reads to the creator.
type OperationRepository struct {
	db *DB
}

// NewOperationRepository creates the repository.
func NewOperationRepository(db *DB) *OperationRepository {
	return &OperationRepository{db: db}
}

var _ operation.Store = (*OperationRepository)(nil)

// operationStaleSQL is operation.StaleAfter (TestOperationStaleSQLMatches).
const operationStaleSQL = "interval '5 minutes'"

const operationColumns = `id, tenant_id, created_by, kind,
	CASE WHEN status = 'running' AND updated_at < now() - ` + operationStaleSQL + ` THEN 'interrupted' ELSE status END,
	COALESCE(idempotency_key, ''), request_hash, total, processed, succeeded, skipped, failed, result, error,
	created_at, updated_at, finished_at`

const operationSelect = "SELECT " + operationColumns + " FROM operations"

// operationBudgetLockSQL serializes budgeted creates of one tenant ($1) until
// the creating transaction ends.
const operationBudgetLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('operations:budget:' || $1, 0))`

func scanOperation(row interface{ Scan(...any) error }) (*operation.Operation, error) {
	var op operation.Operation
	var id, tenantID, createdBy, kind, status string
	var result []byte
	var finished sql.NullTime
	if err := row.Scan(&id, &tenantID, &createdBy, &kind, &status, &op.IdempotencyKey, &op.RequestHash,
		&op.Total, &op.Processed, &op.Succeeded, &op.Skipped, &op.Failed, &result, &op.Error,
		&op.CreatedAt, &op.UpdatedAt, &finished); err != nil {
		return nil, err
	}
	var err error
	if op.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if op.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if op.CreatedBy, err = shared.IDFromString(createdBy); err != nil {
		return nil, err
	}
	op.Kind, op.Status = operation.Kind(kind), operation.Status(status)
	var doc struct {
		Items []operation.ItemResult `json:"items"`
	}
	if len(result) > 0 && json.Unmarshal(result, &doc) == nil {
		op.Items = doc.Items
	}
	if finished.Valid {
		t := finished.Time
		op.FinishedAt = &t
	}
	return &op, nil
}

// Create inserts a running operation (see operation.Store).
func (r *OperationRepository) Create(ctx context.Context, op *operation.Operation, budget operation.Budget) (*operation.Operation, bool, error) {
	if op.IdempotencyKey != "" {
		prev, err := r.ByKey(ctx, op.TenantID, op.CreatedBy, op.IdempotencyKey)
		if err == nil {
			if prev.RequestHash != op.RequestHash {
				return nil, false, operation.ErrIdempotencyMismatch
			}
			return prev, true, nil
		}
		if !errors.Is(err, operation.ErrNotFound) {
			return nil, false, err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin create operation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// A running operation that stopped moving was interrupted: it no longer
	// blocks its creator.
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET status = 'interrupted', finished_at = now()
		WHERE tenant_id = $1 AND created_by = $2 AND status = 'running'
		  AND updated_at < now() - `+operationStaleSQL,
		op.TenantID.String(), op.CreatedBy.String()); err != nil {
		return nil, false, fmt.Errorf("expire stale operations: %w", err)
	}
	if budget.Max > 0 {
		// One creator at a time per tenant reads the total and inserts, so
		// two people (or two replicas) cannot both fit under the budget.
		if _, err := tx.ExecContext(ctx, operationBudgetLockSQL, op.TenantID.String()); err != nil {
			return nil, false, fmt.Errorf("lock operation budget: %w", err)
		}
		used, err := rowsSince(ctx, tx, op.TenantID, budget.Kinds, budget.Since)
		if err != nil {
			return nil, false, err
		}
		if used+op.Total > budget.Max {
			return nil, false, operation.ErrBudget
		}
	}
	var key any
	if op.IdempotencyKey != "" {
		key = op.IdempotencyKey
	}
	row := tx.QueryRowContext(ctx, `INSERT INTO operations (tenant_id, created_by, kind, status, idempotency_key, request_hash, total)
		VALUES ($1, $2, $3, 'running', $4, $5, $6) RETURNING `+operationColumns,
		op.TenantID.String(), op.CreatedBy.String(), string(op.Kind), key, op.RequestHash, op.Total)
	stored, err := scanOperation(row)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			_ = tx.Rollback()
			if pqErr.Constraint == "uq_operations_idempotency" && op.IdempotencyKey != "" {
				// A concurrent replay won the insert.
				prev, gerr := r.ByKey(ctx, op.TenantID, op.CreatedBy, op.IdempotencyKey)
				if gerr != nil {
					return nil, false, gerr
				}
				if prev.RequestHash != op.RequestHash {
					return nil, false, operation.ErrIdempotencyMismatch
				}
				return prev, true, nil
			}
			return nil, false, operation.ErrBusy
		}
		return nil, false, fmt.Errorf("create operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit create operation: %w", err)
	}
	return stored, false, nil
}

// ByKey reads the creator's operation with this idempotency key.
func (r *OperationRepository) ByKey(ctx context.Context, tenantID, createdBy shared.ID, key string) (*operation.Operation, error) {
	op, err := scanOperation(r.db.QueryRowContext(ctx, operationSelect+
		` WHERE tenant_id = $1 AND created_by = $2 AND idempotency_key = $3`,
		tenantID.String(), createdBy.String(), key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, operation.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operation by key: %w", err)
	}
	return op, nil
}

// Get reads one operation of its creator; anything else is ErrNotFound.
func (r *OperationRepository) Get(ctx context.Context, tenantID, createdBy, id shared.ID) (*operation.Operation, error) {
	op, err := scanOperation(r.db.QueryRowContext(ctx, operationSelect+
		` WHERE tenant_id = $1 AND created_by = $2 AND id = $3`,
		tenantID.String(), createdBy.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, operation.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operation: %w", err)
	}
	return op, nil
}

// Advance records progress of a running operation.
func (r *OperationRepository) Advance(ctx context.Context, tenantID, id shared.ID, p operation.Progress) error {
	_, err := r.db.ExecContext(ctx, `UPDATE operations
		SET processed = $3, succeeded = $4, skipped = $5, failed = $6, result = $7, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND status = 'running'`,
		tenantID.String(), id.String(), p.Processed, p.Succeeded, p.Skipped, p.Failed, p.ResultJSON())
	if err != nil {
		return fmt.Errorf("advance operation: %w", err)
	}
	return nil
}

// Finish ends an operation with its final status and counters.
func (r *OperationRepository) Finish(ctx context.Context, tenantID, id shared.ID, status operation.Status, p operation.Progress, errMsg string) error {
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	_, err := r.db.ExecContext(ctx, `UPDATE operations
		SET status = $3, processed = $4, succeeded = $5, skipped = $6, failed = $7, result = $8, error = $9,
		    updated_at = now(), finished_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), string(status), p.Processed, p.Succeeded, p.Skipped, p.Failed, p.ResultJSON(), errMsg)
	if err != nil {
		return fmt.Errorf("finish operation: %w", err)
	}
	return nil
}

// rowsSince sums the items of the tenant's operations of these kinds
// created after since.
func rowsSince(ctx context.Context, tx *sql.Tx, tenantID shared.ID, kinds []operation.Kind, since time.Time) (int, error) {
	ks := make([]string, len(kinds))
	for i, k := range kinds {
		ks[i] = string(k)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(total), 0) FROM operations
		WHERE tenant_id = $1 AND kind = ANY($2) AND created_at > $3`,
		tenantID.String(), pq.Array(ks), since).Scan(&n); err != nil {
		return 0, fmt.Errorf("sum operation rows: %w", err)
	}
	return n, nil
}
