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
