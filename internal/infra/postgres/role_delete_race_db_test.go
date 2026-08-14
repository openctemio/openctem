package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
)

// RoleRepository.Delete used to run SELECT is_system → CountUsersWithRole →
// DELETE as three separate statements. A role could gain a user (INSERT into
// user_roles) between the count check and the DELETE and still be deleted,
// leaving a dangling user_roles reference. The guard now lives inside the
// DELETE (is_system = false AND NOT EXISTS(user_roles)), so a role with any
// assignment is never removed. These tests pin that behavior and the three
// original error outcomes.

func openRoleRaceDB(t *testing.T) *DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping role-delete race tests")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &DB{DB: sqlDB}
}

func seedTenant(ctx context.Context, t *testing.T, db *DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "tx-atom-tenant-"+id.String(), "tx-atom-"+id.String())
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

func seedUser(ctx context.Context, t *testing.T, db *DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email) VALUES ($1, $2)`,
		id.String(), "tx-atom-"+id.String()+"@example.com")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func seedRole(ctx context.Context, t *testing.T, db *DB, tenantID shared.ID, isSystem bool) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO roles (id, tenant_id, slug, name, is_system) VALUES ($1, $2, $3, $4, $5)`,
		id.String(), tenantID.String(), "role-"+id.String(), "Role "+id.String(), isSystem)
	if err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM roles WHERE id = $1`, id.String()) })
	return id
}

func assignRole(ctx context.Context, t *testing.T, db *DB, tenantID, userID, roleID shared.ID) {
	t.Helper()
	_, err := db.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
		userID.String(), tenantID.String(), roleID.String())
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}
}

func roleExists(ctx context.Context, t *testing.T, db *DB, id shared.ID) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE id = $1`, id.String()).Scan(&n); err != nil {
		t.Fatalf("role exists check: %v", err)
	}
	return n > 0
}

func TestRoleRepository_Delete_Conditional(t *testing.T) {
	ctx := context.Background()
	db := openRoleRaceDB(t)
	repo := NewRoleRepository(db)
	tenantID := seedTenant(ctx, t, db)

	t.Run("deletes an unused non-system role", func(t *testing.T) {
		roleID := seedRole(ctx, t, db, tenantID, false)
		if err := repo.Delete(ctx, role.MustParseID(roleID.String())); err != nil {
			t.Fatalf("expected delete to succeed, got %v", err)
		}
		if roleExists(ctx, t, db, roleID) {
			t.Fatal("role should have been deleted")
		}
	})

	t.Run("rejects a role that has a user assigned (the race)", func(t *testing.T) {
		roleID := seedRole(ctx, t, db, tenantID, false)
		userID := seedUser(ctx, t, db)
		// Simulate a user assignment that arrives between check and delete.
		assignRole(ctx, t, db, tenantID, userID, roleID)

		err := repo.Delete(ctx, role.MustParseID(roleID.String()))
		if !errors.Is(err, role.ErrRoleInUse) {
			t.Fatalf("expected ErrRoleInUse, got %v", err)
		}
		if !roleExists(ctx, t, db, roleID) {
			t.Fatal("in-use role must NOT be deleted")
		}
	})

	t.Run("rejects a system role", func(t *testing.T) {
		roleID := seedRole(ctx, t, db, tenantID, true)
		err := repo.Delete(ctx, role.MustParseID(roleID.String()))
		if !errors.Is(err, role.ErrCannotDeleteSystemRole) {
			t.Fatalf("expected ErrCannotDeleteSystemRole, got %v", err)
		}
		if !roleExists(ctx, t, db, roleID) {
			t.Fatal("system role must NOT be deleted")
		}
	})

	t.Run("reports not found for a missing role", func(t *testing.T) {
		err := repo.Delete(ctx, role.MustParseID(shared.NewID().String()))
		if !errors.Is(err, role.ErrRoleNotFound) {
			t.Fatalf("expected ErrRoleNotFound, got %v", err)
		}
	})
}
