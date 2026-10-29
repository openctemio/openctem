package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

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
