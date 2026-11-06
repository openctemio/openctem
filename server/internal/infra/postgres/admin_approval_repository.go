package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AdminApprovalRepository stores four-eyes approvals (admin_approvals). Every
// state change is one conditional UPDATE, so two concurrent decisions or uses
// can never both apply.
type AdminApprovalRepository struct {
	db *DB
}

// NewAdminApprovalRepository creates the repository.
func NewAdminApprovalRepository(db *DB) *AdminApprovalRepository {
	return &AdminApprovalRepository{db: db}
}

var _ admin.ApprovalRepository = (*AdminApprovalRepository)(nil)

const adminApprovalColumns = `a.id, a.action, a.target, a.target_label, a.reason, a.requested_by, a.requested_at,
	a.expires_at, a.decided_by, a.decided_at, COALESCE(a.decision, ''), a.decision_note, a.consumed_at`

// Create inserts a new request.
func (r *AdminApprovalRepository) Create(ctx context.Context, a *admin.Approval) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_approvals (id, action, target, target_label, reason, requested_by, requested_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		a.ID.String(), string(a.Action), a.Target, a.TargetLabel, a.Reason, a.RequestedBy.String(),
		a.RequestedAt, a.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create approval: %w", err)
	}
	return nil
}

// Get returns one approval.
func (r *AdminApprovalRepository) Get(ctx context.Context, id shared.ID) (*admin.Approval, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+adminApprovalColumns+` FROM admin_approvals a WHERE a.id = $1`, id.String())
	return scanApproval(row)
}

// List returns open requests and those made after since, newest first.
func (r *AdminApprovalRepository) List(ctx context.Context, since time.Time, limit int) ([]*admin.Approval, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+adminApprovalColumns+`, COALESCE(req.email, ''), COALESCE(dec.email, '')
		FROM admin_approvals a
		LEFT JOIN admin_users req ON req.id = a.requested_by
		LEFT JOIN admin_users dec ON dec.id = a.decided_by
		WHERE a.requested_at >= $1 OR (a.decision IS NULL AND a.expires_at > NOW())
		ORDER BY a.requested_at DESC
		LIMIT $2`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*admin.Approval, 0)
	for rows.Next() {
		a, err := scanApprovalFields(rows, true)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FindPending returns the requester's open request for action and target.
func (r *AdminApprovalRepository) FindPending(ctx context.Context, requestedBy shared.ID, action admin.ApprovalAction, target string, now time.Time) (*admin.Approval, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+adminApprovalColumns+` FROM admin_approvals a
		WHERE a.requested_by = $1 AND a.action = $2 AND a.target = $3
		  AND a.decision IS NULL AND a.expires_at > $4
		ORDER BY a.requested_at DESC LIMIT 1`,
		requestedBy.String(), string(action), target, now)
	return scanApproval(row)
}

// Decide records a decision on a pending, unexpired request.
func (r *AdminApprovalRepository) Decide(ctx context.Context, id, decidedBy shared.ID, decision, note string, now time.Time) (*admin.Approval, error) {
	if decision != admin.DecisionCanceled {
		// Checked before the update so the caller gets the precise error;
		// the table constraint refuses it as well.
		cur, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if cur.RequestedBy == decidedBy {
			return nil, admin.ErrSelfApproval
		}
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE admin_approvals a
		SET decision = $3, decided_by = $2, decided_at = $4, decision_note = $5
		WHERE a.id = $1 AND a.decision IS NULL AND a.expires_at > $4
		RETURNING `+adminApprovalColumns,
		id.String(), decidedBy.String(), decision, now, note)
	a, err := scanApproval(row)
	if errors.Is(err, admin.ErrApprovalNotFound) {
		if _, gerr := r.Get(ctx, id); gerr != nil {
			return nil, gerr
		}
		return nil, admin.ErrApprovalNotPending
	}
	return a, err
}

// Consume spends the requester's oldest usable approval for action and target.
func (r *AdminApprovalRepository) Consume(ctx context.Context, requestedBy shared.ID, action admin.ApprovalAction, target string, now time.Time) (*admin.Approval, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE admin_approvals a SET consumed_at = $4
		WHERE a.id = (
			SELECT id FROM admin_approvals
			WHERE requested_by = $1 AND action = $2 AND target = $3
			  AND decision = 'approved' AND consumed_at IS NULL AND expires_at > $4
			ORDER BY decided_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		) AND a.consumed_at IS NULL
		RETURNING `+adminApprovalColumns,
		requestedBy.String(), string(action), target, now)
	return scanApproval(row)
}

// Release makes a consumed approval usable again.
func (r *AdminApprovalRepository) Release(ctx context.Context, id shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE admin_approvals SET consumed_at = NULL WHERE id = $1`, id.String()); err != nil {
		return fmt.Errorf("release approval: %w", err)
	}
	return nil
}

func scanApproval(row *sql.Row) (*admin.Approval, error) {
	a, err := scanApprovalFields(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrApprovalNotFound
	}
	return a, err
}

func scanApprovalFields(s rowScanner, withEmails bool) (*admin.Approval, error) {
	var (
		a                   admin.Approval
		id, by              string
		action              string
		decidedBy           sql.NullString
		decidedAt, consumed sql.NullTime
	)
	dest := []any{&id, &action, &a.Target, &a.TargetLabel, &a.Reason, &by, &a.RequestedAt,
		&a.ExpiresAt, &decidedBy, &decidedAt, &a.Decision, &a.Note, &consumed}
	if withEmails {
		dest = append(dest, &a.RequestedByEmail, &a.DecidedByEmail)
	}
	if err := s.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan approval: %w", err)
	}
	var err error
	if a.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if a.RequestedBy, err = shared.IDFromString(by); err != nil {
		return nil, err
	}
	a.Action = admin.ApprovalAction(action)
	if decidedBy.Valid {
		did, err := shared.IDFromString(decidedBy.String)
		if err != nil {
			return nil, err
		}
		a.DecidedBy = &did
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		a.DecidedAt = &t
	}
	if consumed.Valid {
		t := consumed.Time
		a.ConsumedAt = &t
	}
	return &a, nil
}
