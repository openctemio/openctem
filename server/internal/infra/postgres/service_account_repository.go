package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
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
	if err := createServiceAccountTx(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

// createServiceAccountTx stores a service account and its membership (no
// role) inside the caller's transaction.
func createServiceAccountTx(ctx context.Context, tx *sql.Tx, a *serviceaccount.ServiceAccount) error {
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
	return nil
}

const serviceAccountSelect = `
	SELECT u.id, u.service_tenant_id, u.name, COALESCE(u.preferences->>'description', ''),
	       u.service_owner_id, COALESCE(o.name, o.email, ''), COALESCE(tm.status, 'active'), u.created_at,
	       (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id AND k.tenant_id = u.service_tenant_id AND k.status = 'active'
		       AND (k.expires_at IS NULL OR k.expires_at > now())),
	       EXISTS (SELECT 1 FROM ai_agents a WHERE a.user_id = u.id)
	FROM users u
	LEFT JOIN users o ON o.id = u.service_owner_id
	LEFT JOIN tenant_members tm ON tm.user_id = u.id AND tm.tenant_id = u.service_tenant_id
	WHERE u.kind = 'service' AND u.service_tenant_id = $1`

func scanServiceAccount(row interface{ Scan(...any) error }) (*serviceaccount.ServiceAccount, error) {
	var id, tid string
	var owner sql.NullString
	var at time.Time
	a := &serviceaccount.ServiceAccount{}
	if err := row.Scan(&id, &tid, &a.Name, &a.Description, &owner, &a.OwnerName, &a.Status, &at, &a.APIKeys, &a.AIAgent); err != nil {
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := r.loadMemberships(ctx, tenantID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// loadMemberships fills Roles and Teams of the accounts with two queries
// whatever the number of accounts. Both are scoped to the tenant.
func (r *ServiceAccountRepository) loadMemberships(ctx context.Context, tenantID shared.ID, accounts []*serviceaccount.ServiceAccount) error {
	byID := make(map[string]*serviceaccount.ServiceAccount, len(accounts))
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		a.Roles, a.Teams = []serviceaccount.Ref{}, []serviceaccount.Ref{}
		byID[a.ID.String()] = a
		ids = append(ids, a.ID.String())
	}
	if len(ids) == 0 {
		return nil
	}
	for _, q := range []struct {
		sql  string
		into func(a *serviceaccount.ServiceAccount, ref serviceaccount.Ref)
	}{
		{`SELECT ur.user_id, r.id, r.name
		    FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		   WHERE ur.tenant_id = $1 AND ur.user_id = ANY($2::uuid[])
		   ORDER BY r.name`, func(a *serviceaccount.ServiceAccount, ref serviceaccount.Ref) { a.Roles = append(a.Roles, ref) }},
		{`SELECT gm.user_id, g.id, g.name
		    FROM group_members gm JOIN groups g ON g.id = gm.group_id
		   WHERE g.tenant_id = $1 AND g.is_active AND gm.user_id = ANY($2::uuid[])
		     AND (gm.expires_at IS NULL OR gm.expires_at > now())
		   ORDER BY g.name`, func(a *serviceaccount.ServiceAccount, ref serviceaccount.Ref) { a.Teams = append(a.Teams, ref) }},
	} {
		if err := r.scanMemberships(ctx, q.sql, tenantID.String(), ids, byID, q.into); err != nil {
			return err
		}
	}
	return nil
}

// scanMemberships runs one (user_id, id, name) query and hands each row to
// into for the account it belongs to.
func (r *ServiceAccountRepository) scanMemberships(ctx context.Context, query, tenantID string, ids []string,
	byID map[string]*serviceaccount.ServiceAccount, into func(*serviceaccount.ServiceAccount, serviceaccount.Ref)) error {
	rows, err := r.db.QueryContext(ctx, query, tenantID, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("load service account memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var uid, rid, name string
		if err := rows.Scan(&uid, &rid, &name); err != nil {
			return fmt.Errorf("scan service account membership: %w", err)
		}
		if a := byID[uid]; a != nil {
			id, _ := shared.IDFromString(rid)
			into(a, serviceaccount.Ref{ID: id, Name: name})
		}
	}
	return rows.Err()
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
	if err := r.loadMemberships(ctx, tenantID, []*serviceaccount.ServiceAccount{a}); err != nil {
		return nil, err
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

// RoleHasServiceAccountHolder reports whether a service account of the tenant
// holds the role, directly or through a team binding. Inactive teams and
// expired team memberships count (unlike v_user_role_grants): re-activating
// the team would otherwise hand the account a full-data role.
func (r *ServiceAccountRepository) RoleHasServiceAccountHolder(ctx context.Context, tenantID, roleID shared.ID) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_roles ur JOIN users u ON u.id = ur.user_id
			WHERE ur.tenant_id = $1 AND ur.role_id = $2 AND u.kind = 'service'
		) OR EXISTS (
			SELECT 1 FROM group_role_bindings b
			JOIN group_members gm ON gm.group_id = b.group_id
			JOIN users u ON u.id = gm.user_id
			WHERE b.tenant_id = $1 AND b.role_id = $2 AND u.kind = 'service')`,
		tenantID.String(), roleID.String()).Scan(&ok); err != nil {
		return false, fmt.Errorf("check service account role holders: %w", err)
	}
	return ok, nil
}

// ListServiceKeyCreators returns each (tenant, person) that created active or
// suspended service-account keys, plus the keys with no recorded creator
// (UserID zero). It feeds the sweep that revokes keys whose creator lost
// service_accounts:manage; the per-key check at use time does not depend on it.
func (r *ServiceAccountRepository) ListServiceKeyCreators(ctx context.Context) ([]serviceaccount.KeyCreator, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT k.tenant_id, k.created_by
		FROM api_keys k JOIN users u ON u.id = k.user_id
		WHERE u.kind = 'service' AND u.service_tenant_id = k.tenant_id
		  AND k.status IN ('active', 'suspended')`)
	if err != nil {
		return nil, fmt.Errorf("list service key creators: %w", err)
	}
	defer rows.Close()
	var out []serviceaccount.KeyCreator
	for rows.Next() {
		var t string
		var c sql.NullString
		if err := rows.Scan(&t, &c); err != nil {
			return nil, fmt.Errorf("scan service key creator: %w", err)
		}
		tid, err := shared.IDFromString(t)
		if err != nil {
			continue
		}
		sc := serviceaccount.KeyCreator{TenantID: tid}
		if c.Valid {
			if cid, err := shared.IDFromString(c.String); err == nil {
				sc.UserID = cid
			}
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// RevokeKeysWithoutCreator revokes the live service-account keys of a tenant
// that record no creator (nobody answers for them). Returns how many.
func (r *ServiceAccountRepository) RevokeKeysWithoutCreator(ctx context.Context, tenantID shared.ID) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE api_keys k SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		FROM users u
		WHERE u.id = k.user_id AND u.kind = 'service' AND u.service_tenant_id = k.tenant_id
		  AND k.tenant_id = $1 AND k.created_by IS NULL AND k.status IN ('active', 'suspended')`,
		tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("revoke service keys without creator: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
