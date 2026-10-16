package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExposureDispositionRepository stores four-eyes disposition requests for
// exposures (exposure_disposition_requests). Every query is tenant-scoped.
type ExposureDispositionRepository struct {
	db *DB
}

// NewExposureDispositionRepository creates the repository.
func NewExposureDispositionRepository(db *DB) *ExposureDispositionRepository {
	return &ExposureDispositionRepository{db: db}
}

var _ exposure.DispositionRepository = (*ExposureDispositionRepository)(nil)

const dispositionColumns = `id, tenant_id, exposure_event_id, requested_state, requested_by, reason, status,
	decided_by, decided_at, decision_reason, self_approved, created_at`

// Create stores a pending request. The exposure must belong to the request's
// tenant (the INSERT selects it under the tenant), so a request can never
// point at another organization's exposure.
func (r *ExposureDispositionRepository) Create(ctx context.Context, req *exposure.DispositionRequest) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO exposure_disposition_requests
			(id, tenant_id, exposure_event_id, requested_state, requested_by, reason, status, created_at)
		SELECT $1, e.tenant_id, e.id, $4, $5, $6, 'pending', $7
		FROM exposure_events e
		WHERE e.tenant_id = $2 AND e.id = $3`,
		req.ID.String(), req.TenantID.String(), req.ExposureID.String(), string(req.RequestedState),
		nullID(req.RequestedBy), req.Reason, req.CreatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return exposure.ErrDispositionConflict
		}
		return fmt.Errorf("create disposition request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// GetPending returns the exposure's pending request, or nil.
func (r *ExposureDispositionRepository) GetPending(ctx context.Context, tenantID, exposureID shared.ID) (*exposure.DispositionRequest, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+dispositionColumns+`
		FROM exposure_disposition_requests
		WHERE tenant_id = $1 AND exposure_event_id = $2 AND status = 'pending'`,
		tenantID.String(), exposureID.String())
	req, err := scanDisposition(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return req, err
}

// ListPending returns the pending requests of the given exposures.
func (r *ExposureDispositionRepository) ListPending(ctx context.Context, tenantID shared.ID, exposureIDs []shared.ID) (map[shared.ID]*exposure.DispositionRequest, error) {
	out := make(map[shared.ID]*exposure.DispositionRequest)
	if len(exposureIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(exposureIDs))
	for _, id := range exposureIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+dispositionColumns+`
		FROM exposure_disposition_requests
		WHERE tenant_id = $1 AND exposure_event_id = ANY($2::uuid[]) AND status = 'pending'`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list pending disposition requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		req, err := scanDisposition(rows)
		if err != nil {
			return nil, err
		}
		out[req.ExposureID] = req
	}
	return out, rows.Err()
}

// Decide moves a pending request to status. False when it is no longer
// pending.
func (r *ExposureDispositionRepository) Decide(ctx context.Context, tenantID, id shared.ID, status exposure.DispositionStatus, by shared.ID, reason string, selfApproved bool) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE exposure_disposition_requests
		SET status = $3, decided_by = $4, decided_at = NOW(), decision_reason = $5, self_approved = $6
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
		tenantID.String(), id.String(), string(status), by.String(), reason, selfApproved)
	if err != nil {
		return false, fmt.Errorf("decide disposition request: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Reopen puts an approved request back to pending.
func (r *ExposureDispositionRepository) Reopen(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE exposure_disposition_requests
		SET status = 'pending', decided_by = NULL, decided_at = NULL, decision_reason = '', self_approved = false
		WHERE tenant_id = $1 AND id = $2 AND status = 'approved'`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("reopen disposition request: %w", err)
	}
	return nil
}

// CountEligibleApprovers counts the tenant's active members who hold every
// permission in perms: owners and admins (who pass every permission check)
// and members whose roles grant all of them.
func (r *ExposureDispositionRepository) CountEligibleApprovers(ctx context.Context, tenantID shared.ID, perms []string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT tm.user_id)
		FROM tenant_members tm
		WHERE tm.tenant_id = $1
		  AND tm.status = 'active'
		  AND (
		      tm.role IN ('owner', 'admin')
		      OR (
		          SELECT COUNT(DISTINCT rp.permission_id)
		          FROM v_user_role_grants ur
		          JOIN role_permissions rp ON rp.role_id = ur.role_id
		          WHERE ur.tenant_id = tm.tenant_id AND ur.user_id = tm.user_id
		            AND rp.permission_id = ANY($2::text[])
		      ) = cardinality($2::text[])
		  )`, tenantID.String(), pq.Array(perms)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count eligible disposition approvers: %w", err)
	}
	return n, nil
}

// IsTenantOwner reports whether the user is an active owner of the tenant.
func (r *ExposureDispositionRepository) IsTenantOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_members
			WHERE tenant_id = $1 AND user_id = $2 AND role = 'owner' AND status = 'active'
		)`, tenantID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check tenant owner: %w", err)
	}
	return ok, nil
}

// RecentMemberRemoval answers the latest time after since at which the
// tenant lost a possible second approver: a member suspended, offboarded,
// removed, expired, demoted, or a role change that can strip the approve
// permission (recentApproverChange; nil: none).
func (r *ExposureDispositionRepository) RecentMemberRemoval(ctx context.Context, tenantID shared.ID, since time.Time) (*time.Time, error) {
	return recentApproverChange(ctx, r.db, tenantID, since)
}

func scanDisposition(s interface{ Scan(dest ...any) error }) (*exposure.DispositionRequest, error) {
	var (
		req                                 exposure.DispositionRequest
		id, tenantID, exposureID, state, st string
		requestedBy, decidedBy              sql.NullString
		decidedAt                           sql.NullTime
	)
	if err := s.Scan(&id, &tenantID, &exposureID, &state, &requestedBy, &req.Reason, &st,
		&decidedBy, &decidedAt, &req.DecisionReason, &req.SelfApproved, &req.CreatedAt); err != nil {
		return nil, err
	}
	req.ID, _ = shared.IDFromString(id)
	req.TenantID, _ = shared.IDFromString(tenantID)
	req.ExposureID, _ = shared.IDFromString(exposureID)
	req.RequestedState = exposure.State(state)
	req.Status = exposure.DispositionStatus(st)
	if requestedBy.Valid {
		if v, err := shared.IDFromString(requestedBy.String); err == nil {
			req.RequestedBy = &v
		}
	}
	if decidedBy.Valid {
		if v, err := shared.IDFromString(decidedBy.String); err == nil {
			req.DecidedBy = &v
		}
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		req.DecidedAt = &t
	}
	return &req, nil
}
