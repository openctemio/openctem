package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AccessRequestRepository stores access requests (migration 001308). Platform
// data: requests belong to no organization.
type AccessRequestRepository struct {
	db *DB
}

// NewAccessRequestRepository creates the repository.
func NewAccessRequestRepository(db *DB) *AccessRequestRepository {
	return &AccessRequestRepository{db: db}
}

var _ accessrequest.Repository = (*AccessRequestRepository)(nil)

const accessRequestColumns = `id, company, email, domain, note, status, ip_hash, confirm_hash,
	confirmed_at, created_at, decided_at, decided_by, created_tenant_id`

// Create inserts a request.
func (r *AccessRequestRepository) Create(ctx context.Context, a *accessrequest.Request) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO access_requests (`+accessRequestColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		a.ID.String(), a.Company, a.Email, a.Domain, a.Note, string(a.Status), a.IPHash, nullString(a.ConfirmHash),
		nullTimePtr(a.ConfirmedAt), a.CreatedAt, nullTimePtr(a.DecidedAt), nullID(a.DecidedBy), nullID(a.TenantID),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return accessrequest.ErrAlreadyExists
		}
		return fmt.Errorf("create access request: %w", err)
	}
	return nil
}

func (r *AccessRequestRepository) scan(row rowScanner) (*accessrequest.Request, error) {
	var (
		a                     accessrequest.Request
		id, status            string
		confirmHash           sql.NullString
		confirmedAt, decided  sql.NullTime
		decidedBy, createdTen sql.NullString
	)
	if err := row.Scan(&id, &a.Company, &a.Email, &a.Domain, &a.Note, &status, &a.IPHash, &confirmHash,
		&confirmedAt, &a.CreatedAt, &decided, &decidedBy, &createdTen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accessrequest.ErrNotFound
		}
		return nil, fmt.Errorf("scan access request: %w", err)
	}
	pid, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("parse id: %w", err)
	}
	a.ID = pid
	a.Status = accessrequest.Status(status)
	a.ConfirmHash = confirmHash.String
	a.ConfirmedAt = nullTimeValue(confirmedAt)
	a.DecidedAt = nullTimeValue(decided)
	if decidedBy.Valid {
		if v, perr := shared.IDFromString(decidedBy.String); perr == nil {
			a.DecidedBy = &v
		}
	}
	if createdTen.Valid {
		if v, perr := shared.IDFromString(createdTen.String); perr == nil {
			a.TenantID = &v
		}
	}
	return &a, nil
}

// GetByID returns a request.
func (r *AccessRequestRepository) GetByID(ctx context.Context, id shared.ID) (*accessrequest.Request, error) {
	return r.scan(r.db.QueryRowContext(ctx, `SELECT `+accessRequestColumns+` FROM access_requests WHERE id = $1`, id.String()))
}

// GetByConfirmHash returns the request with this confirmation token hash.
func (r *AccessRequestRepository) GetByConfirmHash(ctx context.Context, hash string) (*accessrequest.Request, error) {
	if hash == "" {
		return nil, accessrequest.ErrNotFound
	}
	return r.scan(r.db.QueryRowContext(ctx, `SELECT `+accessRequestColumns+` FROM access_requests WHERE confirm_hash = $1`, hash))
}

// Update writes status, confirmation and decision.
func (r *AccessRequestRepository) Update(ctx context.Context, a *accessrequest.Request, expected accessrequest.Status) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE access_requests
		   SET status = $2, confirm_hash = $3, confirmed_at = $4, decided_at = $5, decided_by = $6, created_tenant_id = $7
		 WHERE id = $1 AND status = $8`,
		a.ID.String(), string(a.Status), nullString(a.ConfirmHash), nullTimePtr(a.ConfirmedAt),
		nullTimePtr(a.DecidedAt), nullID(a.DecidedBy), nullID(a.TenantID), string(expected),
	)
	if err != nil {
		return fmt.Errorf("update access request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return accessrequest.ErrNotDecidable
	}
	return nil
}

// List returns requests newest first. An empty status lists the open ones
// (pending and unconfirmed).
func (r *AccessRequestRepository) List(ctx context.Context, f accessrequest.Filter) ([]*accessrequest.Request, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	where := `status IN ('pending', 'unconfirmed')`
	args := []any{}
	if f.Status != "" {
		where = `status = $1`
		args = append(args, string(f.Status))
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM access_requests WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count access requests: %w", err)
	}
	q := fmt.Sprintf(`SELECT %s FROM access_requests WHERE %s ORDER BY created_at DESC LIMIT %d OFFSET %d`,
		accessRequestColumns, where, limit, offset)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list access requests: %w", err)
	}
	defer rows.Close()
	out := make([]*accessrequest.Request, 0, limit)
	for rows.Next() {
		a, err := r.scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// CountByIPSince counts requests from one IP hash since t.
func (r *AccessRequestRepository) CountByIPSince(ctx context.Context, ipHash string, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM access_requests WHERE ip_hash = $1 AND created_at >= $2`, ipHash, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count access requests by ip: %w", err)
	}
	return n, nil
}

// CountByDomainSince counts requests for one email domain since t.
func (r *AccessRequestRepository) CountByDomainSince(ctx context.Context, domain string, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM access_requests WHERE domain = $1 AND created_at >= $2`, domain, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count access requests by domain: %w", err)
	}
	return n, nil
}

// Purge deletes expired unconfirmed requests and old decided ones.
func (r *AccessRequestRepository) Purge(ctx context.Context, unconfirmedBefore, decidedBefore time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM access_requests
		 WHERE (status = 'unconfirmed' AND created_at < $1)
		    OR (status IN ('approved', 'rejected') AND decided_at < $2)`,
		unconfirmedBefore, decidedBefore)
	if err != nil {
		return 0, fmt.Errorf("purge access requests: %w", err)
	}
	return res.RowsAffected()
}
