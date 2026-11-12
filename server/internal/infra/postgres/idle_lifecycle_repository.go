package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IdleLifecycleRepository stores the idle lifecycle of the organizations the
// idle policy is on for (migrations 001347 and idle_policy_opt_in). Every per-organization query is scoped by tenant_id.
type IdleLifecycleRepository struct {
	db *DB
}

// NewIdleLifecycleRepository creates the repository.
func NewIdleLifecycleRepository(db *DB) *IdleLifecycleRepository {
	return &IdleLifecycleRepository{db: db}
}

var _ lifecycle.Repository = (*IdleLifecycleRepository)(nil)

// Workspaces lists the organizations the idle policy is on for, with their
// stage and the latest sign-in of an active member. An organization without
// a row, or with the policy off, is never listed.
func (r *IdleLifecycleRepository) Workspaces(ctx context.Context) ([]lifecycle.Workspace, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id, t.name, t.slug, t.created_at, l.stage, l.stage_changed_at,
		       (SELECT max(u.last_login_at) FROM tenant_members m JOIN users u ON u.id = m.user_id
		         WHERE m.tenant_id = t.id AND m.status = 'active')
		  FROM tenant_idle_lifecycle l
		  JOIN tenants t ON t.id = l.tenant_id
		 WHERE l.policy_enabled
		 ORDER BY t.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list idle-policy organizations: %w", err)
	}
	defer rows.Close()
	out := []lifecycle.Workspace{}
	for rows.Next() {
		var (
			w      lifecycle.Workspace
			id     string
			stage  string
			signIn sql.NullTime
		)
		if err := rows.Scan(&id, &w.Name, &w.Slug, &w.CreatedAt, &stage, &w.StageChangedAt, &signIn); err != nil {
			return nil, fmt.Errorf("scan idle-policy organization: %w", err)
		}
		tid, perr := shared.IDFromString(id)
		if perr != nil {
			continue
		}
		w.TenantID, w.Stage = tid, lifecycle.Stage(stage)
		if signIn.Valid {
			w.LastSignIn = signIn.Time
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// SetStage records the organization's stage.
func (r *IdleLifecycleRepository) SetStage(ctx context.Context, tenantID shared.ID, stage lifecycle.Stage, at time.Time) error {
	if !stage.IsValid() {
		return fmt.Errorf("%w: unknown idle stage", shared.ErrValidation)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_idle_lifecycle (tenant_id, stage, stage_changed_at) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET stage = EXCLUDED.stage, stage_changed_at = EXCLUDED.stage_changed_at`,
		tenantID.String(), string(stage), at)
	if err != nil {
		return fmt.Errorf("set idle stage: %w", err)
	}
	return nil
}

// Status returns the organization's lifecycle (active when there is no row).
func (r *IdleLifecycleRepository) Status(ctx context.Context, tenantID shared.ID) (*lifecycle.Status, error) {
	var (
		stage                    sql.NullString
		changed, setAt, lastSign sql.NullTime
		enabled                  sql.NullBool
		reason                   sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT l.stage, l.stage_changed_at, l.policy_enabled, l.policy_reason, l.policy_set_at,
		       (SELECT max(u.last_login_at) FROM tenant_members m JOIN users u ON u.id = m.user_id
		         WHERE m.tenant_id = t.id AND m.status = 'active')
		  FROM tenants t LEFT JOIN tenant_idle_lifecycle l ON l.tenant_id = t.id
		 WHERE t.id = $1`, tenantID.String()).Scan(&stage, &changed, &enabled, &reason, &setAt, &lastSign)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("get idle status: %w", err)
	}
	st := &lifecycle.Status{Stage: lifecycle.StageActive, PolicyEnabled: enabled.Bool, PolicyReason: reason.String}
	if stage.Valid {
		st.Stage = lifecycle.Stage(stage.String)
	}
	st.StageChangedAt, st.PolicySetAt, st.LastSignIn = nullTimeValue(changed), nullTimeValue(setAt), nullTimeValue(lastSign)
	return st, nil
}

// SetPolicy turns the idle policy on or off for the organization. Both
// directions return it to active: turning it on starts the count from the
// latest sign-in, and turning it off lifts any read-only stage at once.
func (r *IdleLifecycleRepository) SetPolicy(ctx context.Context, tenantID shared.ID, p lifecycle.Policy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_idle_lifecycle (tenant_id, stage, stage_changed_at, policy_enabled, policy_reason, policy_set_by, policy_set_at)
		VALUES ($1, 'active', $5, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET stage = 'active', stage_changed_at = EXCLUDED.stage_changed_at,
		  policy_enabled = EXCLUDED.policy_enabled, policy_reason = EXCLUDED.policy_reason,
		  policy_set_by = EXCLUDED.policy_set_by, policy_set_at = EXCLUDED.policy_set_at`,
		tenantID.String(), p.Enabled, p.Reason, nullID(p.By), p.At)
	if err != nil {
		return fmt.Errorf("set idle policy: %w", err)
	}
	return nil
}

// ReadOnly reports whether the organization is read-only now.
func (r *IdleLifecycleRepository) ReadOnly(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ro bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM tenant_idle_lifecycle l
		   WHERE l.tenant_id = $1 AND l.policy_enabled
		     AND l.stage IN ('read_only', 'final_warning', 'deletion_due')
		     AND NOT EXISTS (
		       SELECT 1 FROM tenant_members m JOIN users u ON u.id = m.user_id
		        WHERE m.tenant_id = l.tenant_id AND m.status = 'active'
		          AND u.last_login_at > l.stage_changed_at))`, tenantID.String()).Scan(&ro)
	if err != nil {
		return false, fmt.Errorf("check idle read-only: %w", err)
	}
	return ro, nil
}

// Recipients returns the emails of the organization's active owners and admins.
func (r *IdleLifecycleRepository) Recipients(ctx context.Context, tenantID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.email FROM tenant_members m JOIN users u ON u.id = m.user_id
		 JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		 WHERE m.tenant_id = $1 AND m.status = 'active' AND ver.role IN ('owner', 'admin') AND u.status = 'active'
		 ORDER BY u.email`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list idle recipients: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
