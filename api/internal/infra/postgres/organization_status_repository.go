package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// OrganizationStatusRepository stores an organization's platform status
// (tenants.status and the suspended_* columns,
// docs/architecture/organization-suspension.md). It is a platform-level
// store: the access gate reads it for every credential, and only the admin
// console writes it.
type OrganizationStatusRepository struct {
	db *DB
}

// NewOrganizationStatusRepository creates the repository.
func NewOrganizationStatusRepository(db *DB) *OrganizationStatusRepository {
	return &OrganizationStatusRepository{db: db}
}

// organizationActiveSQL holds when the organization whose id is the column
// col is active. Background jobs and job claims add it so a suspended
// organization's scheduled work is skipped; the few organizations that are
// not active are found through idx_tenants_not_active.
func organizationActiveSQL(col string) string {
	return "NOT EXISTS (SELECT 1 FROM tenants org_status WHERE org_status.id = " + col +
		" AND org_status.status <> 'active')"
}

// OrganizationStatus returns the organization's status; shared.ErrNotFound
// when it does not exist.
func (r *OrganizationStatusRepository) OrganizationStatus(ctx context.Context, tenantID shared.ID) (tenantdom.OrganizationStatus, error) {
	var status string
	err := r.db.QueryRowContext(ctx, `SELECT status FROM tenants WHERE id = $1`, tenantID.String()).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("read organization status: %w", err)
	}
	return tenantdom.OrganizationStatus(status), nil
}

// Suspension returns the organization's status, who set it and why, and its
// name.
func (r *OrganizationStatusRepository) Suspension(ctx context.Context, tenantID shared.ID) (*tenantdom.Suspension, string, error) {
	var (
		name, status string
		at           sql.NullTime
		by           sql.NullString
		reason       sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT name, status, suspended_at, suspended_by, suspended_reason
		FROM tenants WHERE id = $1`, tenantID.String()).Scan(&name, &status, &at, &by, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	if err != nil {
		return nil, "", fmt.Errorf("read organization suspension: %w", err)
	}
	s := &tenantdom.Suspension{Status: tenantdom.OrganizationStatus(status), Reason: reason.String}
	if at.Valid {
		t := at.Time
		s.At = &t
	}
	if by.Valid {
		if id, err := shared.IDFromString(by.String); err == nil {
			s.By = &id
		}
	}
	return s, name, nil
}

// Suspend sets the organization suspended; false when it was not active.
// The conditional update makes two concurrent suspensions write one row.
func (r *OrganizationStatusRepository) Suspend(ctx context.Context, tenantID shared.ID, by *shared.ID, reason string, at time.Time) (bool, error) {
	var byArg any
	if by != nil {
		byArg = by.String()
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET status = 'suspended', suspended_at = $2, suspended_by = $3, suspended_reason = $4, updated_at = $2
		WHERE id = $1 AND status = 'active'`, tenantID.String(), at, byArg, reason)
	if err != nil {
		return false, fmt.Errorf("suspend organization: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Unsuspend sets a suspended organization active again and clears the
// suspended_* columns; false when it was not suspended.
func (r *OrganizationStatusRepository) Unsuspend(ctx context.Context, tenantID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL, updated_at = now()
		WHERE id = $1 AND status = 'suspended'`, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("lift organization suspension: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// IsActiveOwner reports whether userID is an active owner of tenantID (the
// effective role, as the membership gates read it) with an active account.
func (r *OrganizationStatusRepository) IsActiveOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_members m
			JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
			JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active'
			  AND ver.role = 'owner' AND u.status = 'active')`, tenantID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check organization owner: %w", err)
	}
	return ok, nil
}

// OrganizationName returns the organization's name.
func (r *OrganizationStatusRepository) OrganizationName(ctx context.Context, tenantID shared.ID) (string, error) {
	var name string
	err := r.db.QueryRowContext(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID.String()).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("read organization: %w", err)
	}
	return name, nil
}

// Schedule moves an active organization to pending_deletion, due at due;
// false when it was not active (already scheduled, or suspended).
func (r *OrganizationStatusRepository) Schedule(ctx context.Context, tenantID, by shared.ID, at, due time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET status = 'pending_deletion', deletion_requested_at = $2, deletion_requested_by = $3,
		    deletion_due_at = $4, updated_at = $2
		WHERE id = $1 AND status = 'active'`, tenantID.String(), at, by.String(), due)
	if err != nil {
		return false, fmt.Errorf("schedule organization deletion: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Cancel moves a pending organization back to active and clears the
// deletion_* columns; false when it was not pending.
func (r *OrganizationStatusRepository) Cancel(ctx context.Context, tenantID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET status = 'active', deletion_requested_at = NULL, deletion_requested_by = NULL,
		    deletion_due_at = NULL, updated_at = now()
		WHERE id = $1 AND status = 'pending_deletion'`, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("cancel organization deletion: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ListDue returns up to limit organizations whose deletion grace ended,
// oldest due first.
func (r *OrganizationStatusRepository) ListDue(ctx context.Context, now time.Time, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id FROM tenants
		WHERE status = 'pending_deletion' AND deletion_due_at <= $1
		ORDER BY deletion_due_at
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due organization deletions: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, 8)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
