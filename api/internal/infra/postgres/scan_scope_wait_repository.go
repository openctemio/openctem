package postgres

// Scans saved to start when their scope is approved (RFC-054 §7,
// migration 001701). Every query carries the tenant.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanScopeWaitRepository implements scan.ScopeWaitRepository.
type ScanScopeWaitRepository struct {
	db *DB
}

// NewScanScopeWaitRepository creates a ScanScopeWaitRepository.
func NewScanScopeWaitRepository(db *DB) *ScanScopeWaitRepository {
	return &ScanScopeWaitRepository{db: db}
}

var _ scan.ScopeWaitRepository = (*ScanScopeWaitRepository)(nil)

// Create stores a wait; the scan must be the tenant's (shared.ErrNotFound
// otherwise).
func (r *ScanScopeWaitRepository) Create(ctx context.Context, w scan.ScopeWait) error {
	var by any
	if w.RequestedBy != nil {
		by = w.RequestedBy.String()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_scope_waits (scan_id, tenant_id, requested_by, created_at, expires_at)
		SELECT s.id, s.tenant_id, $3, $4, $5 FROM scans s WHERE s.id = $1 AND s.tenant_id = $2
		ON CONFLICT (scan_id) DO UPDATE SET requested_by = EXCLUDED.requested_by,
			created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at
		WHERE scan_scope_waits.tenant_id = EXCLUDED.tenant_id`,
		w.ScanID.String(), w.TenantID.String(), by, w.CreatedAt, w.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create scan scope wait: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("create scan scope wait: %w", shared.ErrNotFound)
	}
	return nil
}

// ListByTenant returns the unexpired waits, oldest first, after removing
// the tenant's expired ones.
func (r *ScanScopeWaitRepository) ListByTenant(ctx context.Context, tenantID shared.ID, limit int) ([]scan.ScopeWait, error) {
	if _, err := r.db.ExecContext(ctx,
		`DELETE FROM scan_scope_waits WHERE tenant_id = $1 AND expires_at <= now()`, tenantID.String()); err != nil {
		return nil, fmt.Errorf("expire scan scope waits: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT scan_id, requested_by, created_at, expires_at FROM scan_scope_waits
		WHERE tenant_id = $1 AND expires_at > now()
		ORDER BY created_at LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list scan scope waits: %w", err)
	}
	defer rows.Close()
	var out []scan.ScopeWait
	for rows.Next() {
		var scanID string
		var by *string
		w := scan.ScopeWait{TenantID: tenantID}
		if err := rows.Scan(&scanID, &by, &w.CreatedAt, &w.ExpiresAt); err != nil {
			return nil, fmt.Errorf("list scan scope waits: %w", err)
		}
		w.ScanID = shared.MustIDFromString(scanID)
		if by != nil {
			id := shared.MustIDFromString(*by)
			w.RequestedBy = &id
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Exists reports whether the scan waits (an expired wait does not count).
func (r *ScanScopeWaitRepository) Exists(ctx context.Context, tenantID, scanID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM scan_scope_waits
		WHERE tenant_id = $1 AND scan_id = $2 AND expires_at > now())`,
		tenantID.String(), scanID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("scan scope wait exists: %w", err)
	}
	return ok, nil
}

// Claim deletes the wait; true only for the caller whose delete removed it.
func (r *ScanScopeWaitRepository) Claim(ctx context.Context, tenantID, scanID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM scan_scope_waits WHERE tenant_id = $1 AND scan_id = $2`, tenantID.String(), scanID.String())
	if err != nil {
		return false, fmt.Errorf("claim scan scope wait: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
