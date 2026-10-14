package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A custom role may carry the CI gate's policy and break-glass permissions,
// but never scans:ci:write: trust configurations and code host connections
// issue or admit upload credentials and stay with the owner and admin roles
// (the role_permissions trigger enforces it in the database too).
func TestCICustomRolePermissions_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	roleID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO roles (id, tenant_id, slug, name, is_system)
		VALUES ($1, $2, $3, 'AppSec engineer', false)`, roleID.String(), tenant.String(), "appsec-"+roleID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	grant := func(p string) error {
		_, err := db.ExecContext(ctx, `INSERT INTO role_permissions (id, role_id, permission_id) VALUES ($1, $2, $3)`,
			shared.NewID().String(), roleID.String(), p)
		return err
	}
	for _, p := range []string{"scans:ci:read", "scans:ci:policy", "scans:ci:override"} {
		if err := grant(p); err != nil {
			t.Fatalf("custom role refused %s: %v", p, err)
		}
	}
	if err := grant("scans:ci:write"); err == nil || !strings.Contains(err.Error(), "reserved for the owner and admin roles") {
		t.Fatalf("custom role took scans:ci:write: %v", err)
	}
	// The system owner and admin roles hold the new permission.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM role_permissions WHERE permission_id = 'scans:ci:policy'
		AND role_id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("owner and admin hold scans:ci:policy: %d %v", n, err)
	}
}
