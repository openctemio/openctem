package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ServiceAccountRepository persists service accounts (users of kind
// 'service', migration service_accounts). Every statement is scoped to the
// tenant the account belongs to.
type ServiceAccountRepository struct {
	db *DB
}

// NewServiceAccountRepository creates the repository.
func NewServiceAccountRepository(db *DB) *ServiceAccountRepository {
	return &ServiceAccountRepository{db: db}
}

var _ serviceaccount.Repository = (*ServiceAccountRepository)(nil)

// Create stores the account and its membership (no role) in one transaction.
func (r *ServiceAccountRepository) Create(ctx context.Context, a *serviceaccount.ServiceAccount) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var owner sql.NullString
	if a.OwnerID != nil {
		owner = sql.NullString{String: a.OwnerID.String(), Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, email, name, status, auth_provider, email_verified, kind, service_tenant_id, service_owner_id, preferences)
		VALUES ($1, $2, $3, 'active', 'local', false, 'service', $4, $5, jsonb_build_object('description', $6::text))`,
		a.ID.String(), serviceaccount.Email(a.ID), a.Name, a.TenantID.String(), owner, a.Description); err != nil {
		return fmt.Errorf("create service account: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer')`,
		a.ID.String(), a.TenantID.String()); err != nil {
		return fmt.Errorf("add service account membership: %w", err)
	}
	// A service account starts with no role at all: the membership trigger
	// grants the label role, which is taken back here.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`,
		a.ID.String(), a.TenantID.String()); err != nil {
		return fmt.Errorf("clear service account roles: %w", err)
	}
	return tx.Commit()
}

const serviceAccountSelect = `
	SELECT u.id, u.service_tenant_id, u.name, COALESCE(u.preferences->>'description', ''),
	       u.service_owner_id, COALESCE(o.name, o.email, ''), COALESCE(tm.status, 'active'), u.created_at,
	       (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id AND k.tenant_id = u.service_tenant_id AND k.status = 'active')
	FROM users u
	LEFT JOIN users o ON o.id = u.service_owner_id
	LEFT JOIN tenant_members tm ON tm.user_id = u.id AND tm.tenant_id = u.service_tenant_id
	WHERE u.kind = 'service' AND u.service_tenant_id = $1`

func scanServiceAccount(row interface{ Scan(...any) error }) (*serviceaccount.ServiceAccount, error) {
	var id, tid string
	var owner sql.NullString
	var at time.Time
	a := &serviceaccount.ServiceAccount{}
	if err := row.Scan(&id, &tid, &a.Name, &a.Description, &owner, &a.OwnerName, &a.Status, &at, &a.APIKeys); err != nil {
		return nil, err
	}
	a.ID, _ = shared.IDFromString(id)
	a.TenantID, _ = shared.IDFromString(tid)
	if owner.Valid {
		if oid, err := shared.IDFromString(owner.String); err == nil {
			a.OwnerID = &oid
		}
	}
	a.CreatedAt = at
	return a, nil
}

// List returns the tenant's service accounts.
func (r *ServiceAccountRepository) List(ctx context.Context, tenantID shared.ID) ([]*serviceaccount.ServiceAccount, error) {
	rows, err := r.db.QueryContext(ctx, serviceAccountSelect+` ORDER BY u.name`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()
	var out []*serviceaccount.ServiceAccount
	for rows.Next() {
		a, err := scanServiceAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one service account of the tenant.
func (r *ServiceAccountRepository) Get(ctx context.Context, tenantID, id shared.ID) (*serviceaccount.ServiceAccount, error) {
	a, err := scanServiceAccount(r.db.QueryRowContext(ctx, serviceAccountSelect+` AND u.id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, serviceaccount.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get service account: %w", err)
	}
	return a, nil
}

// Delete removes the account (cascading its membership, roles, team
// memberships and API keys).
func (r *ServiceAccountRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM users WHERE id = $1 AND kind = 'service' AND service_tenant_id = $2`,
		id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("delete service account: %w", err)
	} else if n == 0 {
		return serviceaccount.ErrNotFound
	}
	return nil
}

// IsServiceAccount reports whether the user is a service account.
func (r *ServiceAccountRepository) IsServiceAccount(ctx context.Context, userID shared.ID) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND kind = 'service')`, userID.String()).Scan(&ok); err != nil {
		return false, fmt.Errorf("check service account: %w", err)
	}
	return ok, nil
}
