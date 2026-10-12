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

// IdleLifecycleRepository stores the idle lifecycle of Free organizations
// (migration 001347). Every per-organization query is scoped by tenant_id.
type IdleLifecycleRepository struct {
	db *DB
}

// NewIdleLifecycleRepository creates the repository.
func NewIdleLifecycleRepository(db *DB) *IdleLifecycleRepository {
	return &IdleLifecycleRepository{db: db}
}

var _ lifecycle.Repository = (*IdleLifecycleRepository)(nil)

// FreeWorkspaces lists the Free organizations with their stage, exemption
// and the latest sign-in of an active member.
func (r *IdleLifecycleRepository) FreeWorkspaces(ctx context.Context) ([]lifecycle.Workspace, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id, t.name, t.slug, t.created_at,
		       COALESCE(l.stage, 'active'), COALESCE(l.stage_changed_at, t.created_at), COALESCE(l.exempt, false),
		       (SELECT max(u.last_login_at) FROM tenant_members m JOIN users u ON u.id = m.user_id
		         WHERE m.tenant_id = t.id AND m.status = 'active')
		  FROM tenants t
		  JOIN tenant_plans p ON p.tenant_id = t.id AND p.plan = 'free'
		  LEFT JOIN tenant_idle_lifecycle l ON l.tenant_id = t.id
		 ORDER BY t.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list free workspaces: %w", err)
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
		if err := rows.Scan(&id, &w.Name, &w.Slug, &w.CreatedAt, &stage, &w.StageChangedAt, &w.Exempt, &signIn); err != nil {
			return nil, fmt.Errorf("scan free workspace: %w", err)
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
		stage                       sql.NullString
		changed, exemptAt, lastSign sql.NullTime
		exempt                      sql.NullBool
		reason                      sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT l.stage, l.stage_changed_at, l.exempt, l.exempt_reason, l.exempt_at,
		       (SELECT max(u.last_login_at) FROM tenant_members m JOIN users u ON u.id = m.user_id
		         WHERE m.tenant_id = t.id AND m.status = 'active')
		  FROM tenants t LEFT JOIN tenant_idle_lifecycle l ON l.tenant_id = t.id
		 WHERE t.id = $1`, tenantID.String()).Scan(&stage, &changed, &exempt, &reason, &exemptAt, &lastSign)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("get idle status: %w", err)
	}
	st := &lifecycle.Status{Stage: lifecycle.StageActive, Exempt: exempt.Bool, ExemptReason: reason.String}
	if stage.Valid {
		st.Stage = lifecycle.Stage(stage.String)
	}
	st.StageChangedAt, st.ExemptAt, st.LastSignIn = nullTimeValue(changed), nullTimeValue(exemptAt), nullTimeValue(lastSign)
	return st, nil
}

// SetExemption exempts the organization (or lifts the exemption). Exempting
// also returns it to active.
func (r *IdleLifecycleRepository) SetExemption(ctx context.Context, tenantID shared.ID, e lifecycle.Exemption) error {
	var err error
	if e.Exempt {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO tenant_idle_lifecycle (tenant_id, stage, stage_changed_at, exempt, exempt_reason, exempt_by, exempt_at)
			VALUES ($1, 'active', $4, true, $2, $3, $4)
			ON CONFLICT (tenant_id) DO UPDATE SET stage = 'active', stage_changed_at = EXCLUDED.stage_changed_at,
			  exempt = true, exempt_reason = EXCLUDED.exempt_reason, exempt_by = EXCLUDED.exempt_by, exempt_at = EXCLUDED.exempt_at`,
			tenantID.String(), e.Reason, nullID(e.By), e.At)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE tenant_idle_lifecycle SET exempt = false, exempt_reason = NULL, exempt_by = NULL, exempt_at = NULL
			 WHERE tenant_id = $1`, tenantID.String())
	}
	if err != nil {
		return fmt.Errorf("set idle exemption: %w", err)
	}
	return nil
}

// ReadOnly reports whether the organization is read-only now.
func (r *IdleLifecycleRepository) ReadOnly(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ro bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM tenant_idle_lifecycle l
		   WHERE l.tenant_id = $1 AND NOT l.exempt
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
		 WHERE m.tenant_id = $1 AND m.status = 'active' AND m.role IN ('owner', 'admin') AND u.status = 'active'
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
