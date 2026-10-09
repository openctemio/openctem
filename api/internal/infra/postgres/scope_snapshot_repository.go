package postgres

// Scope snapshots per scan run (RFC-065 §9): one stored body per distinct
// hash and tenant, and one link per run. Tenant-composite keys keep a run's
// link inside its tenant.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrScopeSnapshotNotFound: the run has no snapshot (or is not the tenant's).
var ErrScopeSnapshotNotFound = fmt.Errorf("%w: scope snapshot not found", shared.ErrNotFound)

// ScopeSnapshotRepository stores scope snapshots.
type ScopeSnapshotRepository struct{ db *DB }

// NewScopeSnapshotRepository creates the repository.
func NewScopeSnapshotRepository(db *DB) *ScopeSnapshotRepository { return &ScopeSnapshotRepository{db: db} }

// Record stores the body once per (tenant, hash) and links the run to it.
func (r *ScopeSnapshotRepository) Record(ctx context.Context, tenantID, runID shared.ID, sha256 string, body []byte, takenAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scope_snapshots (tenant_id, sha256, body) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, sha256) DO NOTHING`, tenantID.String(), sha256, body); err != nil {
		return fmt.Errorf("store scope snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scan_run_scope_snapshots (tenant_id, run_id, sha256, taken_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (run_id) DO NOTHING`, tenantID.String(), runID.String(), sha256, takenAt); err != nil {
		return fmt.Errorf("link scope snapshot: %w", err)
	}
	return tx.Commit()
}

// RunSnapshot is a run's snapshot.
type RunSnapshot struct {
	SHA256  string
	TakenAt time.Time
	Body    []byte
}

// GetForRun returns the snapshot of one run of the tenant.
func (r *ScopeSnapshotRepository) GetForRun(ctx context.Context, tenantID, runID shared.ID) (*RunSnapshot, error) {
	var out RunSnapshot
	err := r.db.QueryRowContext(ctx, `
		SELECT l.sha256, l.taken_at, s.body
		FROM scan_run_scope_snapshots l
		JOIN scope_snapshots s ON s.tenant_id = l.tenant_id AND s.sha256 = l.sha256
		WHERE l.tenant_id = $1 AND l.run_id = $2`, tenantID.String(), runID.String()).Scan(&out.SHA256, &out.TakenAt, &out.Body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrScopeSnapshotNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read scope snapshot: %w", err)
	}
	return &out, nil
}
