package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/platformrole"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ platformrole.Store = (*PlatformRoleRepository)(nil)

// PlatformRoleRepository reads and writes the console's own roles
// (platform_roles, platform_role_assignments; RFC-134). It runs on the
// console's database role and never touches the tenant role tables.
type PlatformRoleRepository struct {
	db *DB
}

// NewPlatformRoleRepository creates the repository.
func NewPlatformRoleRepository(db *DB) *PlatformRoleRepository {
	return &PlatformRoleRepository{db: db}
}

// HeldRoles returns the keys of the platform roles an administrator holds.
func (r *PlatformRoleRepository) HeldRoles(ctx context.Context, adminID string) ([]platformauthz.RoleKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT r.key FROM platform_role_assignments a
		JOIN platform_roles r ON r.id = a.role_id
		WHERE a.admin_id = $1
		ORDER BY r.key`, adminID)
	if err != nil {
		return nil, fmt.Errorf("read platform roles: %w", err)
	}
	defer rows.Close()
	var out []platformauthz.RoleKey
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("read platform roles: %w", err)
		}
		out = append(out, platformauthz.RoleKey(k))
	}
	return out, rows.Err()
}

// ListAssignments returns every administrator with the platform roles held.
func (r *PlatformRoleRepository) ListAssignments(ctx context.Context) ([]platformrole.Assignment, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.email, u.name, u.is_active, u.is_break_glass,
		       COALESCE(array_agg(pr.key ORDER BY pr.key) FILTER (WHERE pr.key IS NOT NULL), '{}')
		FROM admin_users u
		LEFT JOIN platform_role_assignments a ON a.admin_id = u.id
		LEFT JOIN platform_roles pr ON pr.id = a.role_id
		WHERE u.user_id IS NOT NULL
		GROUP BY u.id, u.email, u.name, u.is_active, u.is_break_glass
		ORDER BY u.email
		LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("list platform role assignments: %w", err)
	}
	defer rows.Close()
	var out []platformrole.Assignment
	for rows.Next() {
		var a platformrole.Assignment
		var id string
		var keys pq.StringArray
		if err := rows.Scan(&id, &a.Email, &a.Name, &a.Active, &a.BreakGlass, &keys); err != nil {
			return nil, fmt.Errorf("list platform role assignments: %w", err)
		}
		parsed, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("list platform role assignments: %w", err)
		}
		a.AdminID = parsed
		for _, k := range keys {
			a.Roles = append(a.Roles, platformauthz.RoleKey(k))
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Assign gives an additional role. A base role is never given here (the
// trigger on admin_users.role owns those).
func (r *PlatformRoleRepository) Assign(ctx context.Context, adminID shared.ID, role platformauthz.RoleKey, by shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_role_assignments (admin_id, role_id, granted_by)
		SELECT $1, id, $3 FROM platform_roles WHERE key = $2 AND NOT base
		ON CONFLICT DO NOTHING`, adminID.String(), string(role), by.String())
	if err != nil {
		return fmt.Errorf("assign platform role: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var held bool
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM platform_role_assignments a JOIN platform_roles pr ON pr.id = a.role_id
			WHERE a.admin_id = $1 AND pr.key = $2)`, adminID.String(), string(role)).Scan(&held); err != nil {
			return fmt.Errorf("assign platform role: %w", err)
		}
		if !held {
			return platformrole.ErrUnknownRole
		}
	}
	return nil
}

// Revoke takes an additional role and reports whether it was held.
func (r *PlatformRoleRepository) Revoke(ctx context.Context, adminID shared.ID, role platformauthz.RoleKey) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM platform_role_assignments a USING platform_roles pr
		WHERE a.admin_id = $1 AND pr.id = a.role_id AND pr.key = $2 AND NOT pr.base`, adminID.String(), string(role))
	if err != nil {
		return false, fmt.Errorf("revoke platform role: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
