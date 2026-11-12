package integration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Changing a member's role was three statements without a transaction
// (settings audit I-M3): the membership label, a DELETE of the user's system
// roles and an INSERT of the new one. A failure after the DELETE left the user
// with no system role. The change is now one transaction: if the INSERT fails,
// the label and the old system role stay.
func TestUpdateMembership_IsAtomic(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping membership transaction test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	ctx := context.Background()

	tenantID, userID := uuid.NewString(), uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Membership tx IT', $2)`,
		tenantID, "mtx-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Membership tx IT')`, userID, "mtx-"+userID[:8]+"@it.test")
	var membershipID string
	if err := db.QueryRowContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer') RETURNING id`,
		userID, tenantID).Scan(&membershipID); err != nil {
		t.Fatal(err)
	}

	// A trigger (created by the schema owner, for this one user only) makes
	// the repository's own role INSERT fail after its DELETE has run. The
	// tenant_members sync trigger inserts the same role one trigger level
	// deeper (pg_trigger_depth 2), which is let through.
	fn := "it_fail_role_insert_" + strings.ReplaceAll(userID[:8], "-", "")
	mig := testdb.OpenMigrator(t)
	ddl := func(q string) {
		t.Helper()
		tx, err := mig.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		testdb.LockForDDL(t, ctx, tx, "user_roles")
		if _, err := tx.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	ddl(fmt.Sprintf(`CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.user_id = '%[2]s' AND NEW.role_id = '00000000-0000-0000-0000-000000000003' AND pg_trigger_depth() = 1 THEN
				RAISE EXCEPTION 'injected failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %[1]s BEFORE INSERT ON user_roles FOR EACH ROW EXECUTE FUNCTION %[1]s();`, fn, userID))
	t.Cleanup(func() {
		ddl(fmt.Sprintf(`DROP TRIGGER IF EXISTS %[1]s ON user_roles; DROP FUNCTION IF EXISTS %[1]s();`, fn))
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})
	mid, _ := shared.IDFromString(membershipID)
	tid, _ := shared.IDFromString(tenantID)
	m, err := repo.GetMembershipByID(ctx, tid, mid)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRole(tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateMembership(ctx, m); err == nil {
		t.Fatal("UpdateMembership succeeded despite the injected failure")
	}

	var label string
	var systemRoles int
	if err := db.QueryRowContext(ctx, `SELECT role FROM tenant_members WHERE id = $1`, membershipID).Scan(&label); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND r.is_system`, userID, tenantID).Scan(&systemRoles); err != nil {
		t.Fatal(err)
	}
	if label != "viewer" || systemRoles != 1 {
		t.Fatalf("after a failed role change: label=%q system roles=%d, want viewer and 1", label, systemRoles)
	}
}
