package postgres

// Ownership transfer store. Design:
// docs/rfcs/RFC-095-role-templates-and-invitations.md.
//
// Every statement carries the tenant. Accepting runs in one transaction that
// locks the request, then the organization's owner and the two memberships
// involved (ordered by id), so two acceptances, or an acceptance racing a
// cancellation, run one after the other and the loser sees a closed request.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ownerRoleID is the owner system role.
const ownerRoleID = "00000000-0000-0000-0000-000000000001"

// OwnershipTransferRepository implements tenant.OwnershipTransferRepository.
type OwnershipTransferRepository struct {
	db *DB
}

// NewOwnershipTransferRepository creates the store.
func NewOwnershipTransferRepository(db *DB) *OwnershipTransferRepository {
	return &OwnershipTransferRepository{db: db}
}

var _ tenant.OwnershipTransferRepository = (*OwnershipTransferRepository)(nil)

type otQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const otColumns = `id, tenant_id, from_user_id, to_user_id, previous_owner_role, make_internal,
	status, created_at, expires_at, decided_at, decided_by`

func scanOwnershipTransfer(row interface{ Scan(...any) error }) (*tenant.OwnershipTransfer, error) {
	var (
		t                       tenant.OwnershipTransfer
		id, tid, from, to, role string
		status                  string
		decidedAt               sql.NullTime
		decidedBy               sql.NullString
	)
	if err := row.Scan(&id, &tid, &from, &to, &role, &t.MakeInternal, &status,
		&t.CreatedAt, &t.ExpiresAt, &decidedAt, &decidedBy); err != nil {
		return nil, err
	}
	t.ID, _ = shared.IDFromString(id)
	t.TenantID, _ = shared.IDFromString(tid)
	t.FromUserID, _ = shared.IDFromString(from)
	t.ToUserID, _ = shared.IDFromString(to)
	t.PreviousOwnerRole = tenant.Role(role)
	t.Status = tenant.OwnershipTransferStatus(status)
	if decidedAt.Valid {
		v := decidedAt.Time
		t.DecidedAt = &v
	}
	if decidedBy.Valid {
		if v, err := shared.IDFromString(decidedBy.String); err == nil {
			t.DecidedBy = &v
		}
	}
	return &t, nil
}

// candidateQuery reads a membership with what decides ownership eligibility.
const candidateQuery = `
	SELECT m.id, m.user_id, m.status = 'active', u.kind = 'service',
	       COALESCE(f.enabled, false), m.kind = 'external', m.home_tenant_id IS NOT NULL
	FROM tenant_members m
	JOIN users u ON u.id = m.user_id
	LEFT JOIN user_mfa f ON f.user_id = m.user_id
	WHERE m.tenant_id = $1 AND %s`

func scanCandidate(row *sql.Row) (*tenant.OwnershipCandidate, error) {
	var (
		c        tenant.OwnershipCandidate
		mid, uid string
	)
	if err := row.Scan(&mid, &uid, &c.Active, &c.Service, &c.MFAEnabled, &c.External, &c.Managed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("read ownership candidate: %w", err)
	}
	c.MembershipID, _ = shared.IDFromString(mid)
	c.UserID, _ = shared.IDFromString(uid)
	return &c, nil
}

// OwnershipCandidate implements tenant.OwnershipTransferRepository.
func (r *OwnershipTransferRepository) OwnershipCandidate(ctx context.Context, tenantID, membershipID shared.ID) (*tenant.OwnershipCandidate, error) {
	return scanCandidate(r.db.QueryRowContext(ctx,
		fmt.Sprintf(candidateQuery, "m.id = $2"), tenantID.String(), membershipID.String()))
}

// lockActiveOwner locks the membership of userID when it is the tenant's
// active owner. False when it is not.
func lockActiveOwner(ctx context.Context, q otQueryer, tenantID, userID shared.ID) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx, `
		SELECT 1 FROM tenant_members m
		JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND ver.role = 'owner' AND m.status = 'active'
		FOR UPDATE OF m`, tenantID.String(), userID.String()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock owner membership: %w", err)
	}
	return true, nil
}

// CreateOwnershipTransfer implements tenant.OwnershipTransferRepository.
func (r *OwnershipTransferRepository) CreateOwnershipTransfer(ctx context.Context, t *tenant.OwnershipTransfer) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin ownership transfer: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	owner, err := lockActiveOwner(ctx, tx, t.TenantID, t.FromUserID)
	if err != nil {
		return err
	}
	if !owner {
		return tenant.ErrOwnershipTransferNotOwner
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE tenant_ownership_transfers SET status = 'expired', decided_at = expires_at
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2`,
		t.TenantID.String(), t.CreatedAt); err != nil {
		return fmt.Errorf("expire lapsed ownership transfer: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tenant_ownership_transfers
			(id, tenant_id, from_user_id, to_user_id, previous_owner_role, make_internal, status, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)`,
		t.ID.String(), t.TenantID.String(), t.FromUserID.String(), t.ToUserID.String(),
		t.PreviousOwnerRole.String(), t.MakeInternal, t.CreatedAt, t.ExpiresAt); err != nil {
		if isUniqueViolation(err) {
			return tenant.ErrOwnershipTransferPending
		}
		return fmt.Errorf("insert ownership transfer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return tenant.ErrOwnershipTransferPending
		}
		return fmt.Errorf("commit ownership transfer: %w", err)
	}
	return nil
}

// PendingOwnershipTransfer implements tenant.OwnershipTransferRepository.
func (r *OwnershipTransferRepository) PendingOwnershipTransfer(ctx context.Context, tenantID shared.ID, now time.Time) (*tenant.OwnershipTransfer, error) {
	t, err := scanOwnershipTransfer(r.db.QueryRowContext(ctx, `
		SELECT `+otColumns+` FROM tenant_ownership_transfers
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at > $2`, tenantID.String(), now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnershipTransferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read pending ownership transfer: %w", err)
	}
	return t, nil
}

// ExpireLapsedOwnershipTransfers implements tenant.OwnershipTransferRepository.
func (r *OwnershipTransferRepository) ExpireLapsedOwnershipTransfers(ctx context.Context, tenantID shared.ID, now time.Time) ([]*tenant.OwnershipTransfer, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE tenant_ownership_transfers SET status = 'expired', decided_at = expires_at
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2
		RETURNING `+otColumns, tenantID.String(), now)
	if err != nil {
		return nil, fmt.Errorf("expire lapsed ownership transfers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*tenant.OwnershipTransfer
	for rows.Next() {
		t, err := scanOwnershipTransfer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan expired ownership transfer: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CloseOwnershipTransfer implements tenant.OwnershipTransferRepository.
func (r *OwnershipTransferRepository) CloseOwnershipTransfer(ctx context.Context, tenantID, id shared.ID, status tenant.OwnershipTransferStatus, by shared.ID, now time.Time) (*tenant.OwnershipTransfer, error) {
	if status != tenant.OwnershipTransferCanceled && status != tenant.OwnershipTransferDeclined {
		return nil, fmt.Errorf("%w: invalid closing status", shared.ErrValidation)
	}
	t, err := scanOwnershipTransfer(r.db.QueryRowContext(ctx, `
		UPDATE tenant_ownership_transfers SET status = $3, decided_at = $4, decided_by = $5
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		RETURNING `+otColumns, tenantID.String(), id.String(), string(status), now, by.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnershipTransferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("close ownership transfer: %w", err)
	}
	return t, nil
}

// AcceptOwnershipTransfer implements tenant.OwnershipTransferRepository.
//
//nolint:cyclop // one transaction, each step a guard
func (r *OwnershipTransferRepository) AcceptOwnershipTransfer(ctx context.Context, tenantID, id, acceptor shared.ID, now time.Time) (*tenant.OwnershipTransferResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin ownership acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	tid := tenantID.String()

	t, err := scanOwnershipTransfer(tx.QueryRowContext(ctx, `
		SELECT `+otColumns+` FROM tenant_ownership_transfers
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tid, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnershipTransferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock ownership transfer: %w", err)
	}
	// Only the person asked can accept; anyone else learns nothing.
	if t.Status != tenant.OwnershipTransferPending || t.ToUserID != acceptor {
		return nil, tenant.ErrOwnershipTransferNotFound
	}
	if t.IsExpired(now) {
		if _, err := tx.ExecContext(ctx, `
			UPDATE tenant_ownership_transfers SET status = 'expired', decided_at = $3
			WHERE tenant_id = $1 AND id = $2`, tid, id.String(), now); err != nil {
			return nil, fmt.Errorf("expire ownership transfer: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit expiry: %w", err)
		}
		return nil, tenant.ErrOwnershipTransferExpired
	}

	// Lock every membership the change touches, in one statement ordered by
	// id: the current owner(s) and the new owner.
	if _, err := tx.ExecContext(ctx, `
		SELECT m.id FROM tenant_members m
		WHERE m.tenant_id = $1 AND (m.user_id = $2 OR m.user_id = $3 OR EXISTS (
		      SELECT 1 FROM v_user_effective_role ver
		       WHERE ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id AND ver.role = 'owner'))
		ORDER BY m.id FOR UPDATE OF m`, tid, t.FromUserID.String(), t.ToUserID.String()); err != nil {
		return nil, fmt.Errorf("lock memberships: %w", err)
	}
	owner, err := lockActiveOwner(ctx, tx, tenantID, t.FromUserID)
	if err != nil {
		return nil, err
	}
	if !owner {
		if _, err := tx.ExecContext(ctx, `
			UPDATE tenant_ownership_transfers SET status = 'canceled', decided_at = $3
			WHERE tenant_id = $1 AND id = $2`, tid, id.String(), now); err != nil {
			return nil, fmt.Errorf("void ownership transfer: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit void: %w", err)
		}
		return nil, tenant.ErrOwnershipTransferStale
	}
	cand, err := scanCandidate(tx.QueryRowContext(ctx,
		fmt.Sprintf(candidateQuery, "m.user_id = $2"), tid, t.ToUserID.String()))
	if errors.Is(err, shared.ErrNotFound) {
		return nil, tenant.ErrOwnershipTargetInactive
	}
	if err != nil {
		return nil, err
	}
	if err := tenant.CheckOwnershipCandidate(*cand, t.MakeInternal); err != nil {
		return nil, err
	}
	var fromMembership string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`,
		tid, t.FromUserID.String()).Scan(&fromMembership); err != nil {
		return nil, fmt.Errorf("read previous owner membership: %w", err)
	}

	// An unmanaged outside member becomes internal: no home organization and
	// no end of access (an owner's access never lapses).
	if cand.External {
		if _, err := tx.ExecContext(ctx, `
			UPDATE tenant_members
			SET kind = 'internal', home_tenant_id = NULL, expires_at = NULL, expiry_reason = NULL
			WHERE tenant_id = $1 AND user_id = $2`, tid, t.ToUserID.String()); err != nil {
			return nil, fmt.Errorf("make new owner internal: %w", err)
		}
	}
	// The previous owner first, so the owner role is never held twice.
	if err := setSystemRole(ctx, tx, tid, t.FromUserID.String(), t.PreviousOwnerRole.String()); err != nil {
		return nil, err
	}
	if err := setSystemRole(ctx, tx, tid, t.ToUserID.String(), tenant.RoleOwner.String()); err != nil {
		return nil, err
	}
	if err := checkSingleOwner(ctx, tx, tid, t.ToUserID.String()); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE tenant_ownership_transfers SET status = 'accepted', decided_at = $3, decided_by = $4
		WHERE tenant_id = $1 AND id = $2`, tid, id.String(), now, acceptor.String()); err != nil {
		return nil, fmt.Errorf("mark ownership transfer accepted: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit ownership transfer: %w", err)
	}
	t.Status = tenant.OwnershipTransferAccepted
	t.DecidedAt = &now
	t.DecidedBy = &acceptor
	fromID, _ := shared.IDFromString(fromMembership)
	return &tenant.OwnershipTransferResult{
		Transfer:          t,
		FromMembershipID:  fromID,
		ToMembershipID:    cand.MembershipID,
		BecameInternal:    cand.External,
		PreviousOwnerRole: t.PreviousOwnerRole,
	}, nil
}

// setSystemRole sets the membership role and leaves exactly that system role
// in user_roles (custom roles stay). The membership trigger swaps the old
// system role; the explicit DELETE also clears any other system role the
// person held, so the membership and the role set agree.
func setSystemRole(ctx context.Context, tx *sql.Tx, tenantID, userID, role string) error {
	res, err := tx.ExecContext(ctx,
		`UPDATE tenant_members SET role = $3 WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, role)
	if err != nil {
		return fmt.Errorf("set membership role: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return shared.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM user_roles
		WHERE tenant_id = $1 AND user_id = $2
		  AND role_id IN (SELECT id FROM roles WHERE is_system AND tenant_id IS NULL AND slug <> $3)`,
		tenantID, userID, role); err != nil {
		return fmt.Errorf("clear other system roles: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at)
		SELECT $2, $1, r.id, NOW() FROM roles r
		WHERE r.slug = $3 AND r.is_system AND r.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING`, tenantID, userID, role); err != nil {
		return fmt.Errorf("add system role: %w", err)
	}
	return nil
}

// checkSingleOwner verifies the organization ends with exactly one owner,
// newOwner, by membership and by role.
func checkSingleOwner(ctx context.Context, tx *sql.Tx, tenantID, newOwner string) error {
	var members, roles, mine int
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'),
		       (SELECT count(*) FROM user_roles WHERE tenant_id = $1 AND role_id = $3),
		       (SELECT count(*) FROM tenant_members m JOIN user_roles ur
		          ON ur.user_id = m.user_id AND ur.tenant_id = m.tenant_id AND ur.role_id = $3
		        WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.role = 'owner' AND m.status = 'active')`,
		tenantID, newOwner, ownerRoleID).Scan(&members, &roles, &mine); err != nil {
		return fmt.Errorf("check owner invariant: %w", err)
	}
	if members != 1 || roles != 1 || mine != 1 {
		return fmt.Errorf("%w: the organization would not have exactly one owner", shared.ErrConflict)
	}
	return nil
}
