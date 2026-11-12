package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/joinrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// JoinRequestRepository persists organization join requests. Every query is
// scoped to an organization (tenant_id) or to the requester (user_id).
type JoinRequestRepository struct{ db *DB }

// NewJoinRequestRepository creates the repository.
func NewJoinRequestRepository(db *DB) *JoinRequestRepository { return &JoinRequestRepository{db: db} }

var _ joinrequest.Repository = (*JoinRequestRepository)(nil)

const joinRequestFields = `r.id, r.tenant_id, r.user_id, r.domain_id, r.status, r.requested_role,
	COALESCE(r.decided_role, ''), r.decided_by, r.decided_at, r.expires_at, r.created_at`

// Create stores a pending request.
func (r *JoinRequestRepository) Create(ctx context.Context, jr *joinrequest.Request) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO organization_join_requests (id, tenant_id, user_id, domain_id, status, requested_role, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		jr.ID.String(), jr.TenantID.String(), jr.UserID.String(), nullIDPtr(jr.DomainID),
		string(jr.Status), jr.RequestedRole, jr.ExpiresAt, jr.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return joinrequest.ErrAlreadyPending
		}
		return fmt.Errorf("create join request: %w", err)
	}
	return nil
}

// GetForTenant returns a request of the organization.
func (r *JoinRequestRepository) GetForTenant(ctx context.Context, tenantID, id shared.ID) (*joinrequest.Request, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+joinRequestFields+`, u.email, COALESCE(u.name, ''), u.email_verified
		  FROM organization_join_requests r JOIN users u ON u.id = r.user_id
		 WHERE r.tenant_id = $1 AND r.id = $2`, tenantID.String(), id.String())
	jr, err := scanJoinRequest(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, joinrequest.ErrNotFound
	}
	return jr, err
}

// ListPending lists the organization's waiting requests.
func (r *JoinRequestRepository) ListPending(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]*joinrequest.Request, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+joinRequestFields+`, u.email, COALESCE(u.name, ''), u.email_verified
		  FROM organization_join_requests r JOIN users u ON u.id = r.user_id
		 WHERE r.tenant_id = $1 AND r.status = 'pending' AND r.expires_at > $2
		 ORDER BY r.created_at DESC
		 LIMIT $3`, tenantID.String(), now, limit)
	if err != nil {
		return nil, fmt.Errorf("list join requests: %w", err)
	}
	defer rows.Close()
	return scanJoinRequests(rows, true)
}

// ListByUser lists the requester's own requests.
func (r *JoinRequestRepository) ListByUser(ctx context.Context, userID shared.ID, limit int) ([]*joinrequest.Request, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+joinRequestFields+`
		  FROM organization_join_requests r
		 WHERE r.user_id = $1
		 ORDER BY r.created_at DESC
		 LIMIT $2`, userID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list own join requests: %w", err)
	}
	defer rows.Close()
	return scanJoinRequests(rows, false)
}

// CountSince counts the requester's requests created after t.
func (r *JoinRequestRepository) CountSince(ctx context.Context, userID shared.ID, t time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM organization_join_requests WHERE user_id = $1 AND created_at > $2`,
		userID.String(), t).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count join requests: %w", err)
	}
	return n, nil
}

// Decide moves a waiting request of the organization to status.
func (r *JoinRequestRepository) Decide(ctx context.Context, tenantID, id shared.ID, status joinrequest.Status, role string, by shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE organization_join_requests
		   SET status = $3, decided_role = NULLIF($4, ''), decided_by = $5, decided_at = $6
		 WHERE tenant_id = $1 AND id = $2 AND status = 'pending' AND expires_at > $6`,
		tenantID.String(), id.String(), string(status), role, nullIDPtr(&by), at)
	if err != nil {
		return fmt.Errorf("decide join request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return joinrequest.ErrNotPending
	}
	return nil
}

// Purge deletes decided requests and expired ones older than before.
func (r *JoinRequestRepository) Purge(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM organization_join_requests
		 WHERE (status <> 'pending' AND decided_at < $1)
		    OR (status = 'pending' AND expires_at < $1)`, before)
	if err != nil {
		return 0, fmt.Errorf("purge join requests: %w", err)
	}
	return res.RowsAffected()
}

func scanJoinRequests(rows *sql.Rows, withUser bool) ([]*joinrequest.Request, error) {
	var out []*joinrequest.Request
	for rows.Next() {
		jr, err := scanJoinRequest(rows, withUser)
		if err != nil {
			return nil, err
		}
		out = append(out, jr)
	}
	return out, rows.Err()
}

func scanJoinRequest(s rowScanner, withUser bool) (*joinrequest.Request, error) {
	var (
		jr                   joinrequest.Request
		id, tenantID, userID string
		domainID, decidedBy  sql.NullString
		status               string
		decidedAt            sql.NullTime
	)
	dest := []any{&id, &tenantID, &userID, &domainID, &status, &jr.RequestedRole, &jr.DecidedRole,
		&decidedBy, &decidedAt, &jr.ExpiresAt, &jr.CreatedAt}
	if withUser {
		dest = append(dest, &jr.Email, &jr.Name, &jr.EmailVerified)
	}
	if err := s.Scan(dest...); err != nil {
		return nil, err
	}
	jr.ID, jr.TenantID, jr.UserID = shared.MustIDFromString(id), shared.MustIDFromString(tenantID), shared.MustIDFromString(userID)
	jr.Status = joinrequest.Status(status)
	if domainID.Valid {
		d := shared.MustIDFromString(domainID.String)
		jr.DomainID = &d
	}
	if decidedBy.Valid {
		d := shared.MustIDFromString(decidedBy.String)
		jr.DecidedBy = &d
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		jr.DecidedAt = &t
	}
	return &jr, nil
}
