// Package postgres holds the least-privilege database bootstrap
// (least-privilege-roles.sql, owner decision D-6) and its test. See
// docs/deployment/database-roles.md.
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

const script = "least-privilege-roles.sql"

// TestLeastPrivilegeRoles bootstraps a scratch database with the script and
// proves the app role can do the API's work and nothing more. It needs a
// superuser DATABASE_URL (the Postgres CI tier) and psql; it skips otherwise.
func TestLeastPrivilegeRoles(t *testing.T) {
	admin := testdb.AdminURL() // creates a database and roles: needs a superuser
	if admin == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	psql, err := exec.LookPath("psql")
	if err != nil {
		t.Skip("psql not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := open(t, admin)
	var super bool
	if err := root.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("needs a superuser connection; the least-privilege CI job runs the suite as the app role")
	}

	sfx := randHex(t)
	dbName, appRole, migRole := "lp_"+sfx+"_test", "lp_app_"+sfx, "lp_mig_"+sfx
	appPass, migPass := randHex(t), randHex(t)+"'quote"
	exec1(ctx, t, root, `CREATE DATABASE `+dbName)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = root.ExecContext(c, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, dbName)
		_, _ = root.ExecContext(c, `DROP DATABASE IF EXISTS `+dbName)
		for _, r := range []string{appRole, migRole} {
			_, _ = root.ExecContext(c, `DROP ROLE IF EXISTS `+r)
		}
		_ = root.Close()
	})
	scratchAdmin := withDB(t, admin, dbName)

	run := func(vars ...string) (string, error) {
		args := []string{scratchAdmin, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", script}
		for _, v := range vars {
			args = append(args, "-v", v)
		}
		out, err := exec.CommandContext(ctx, psql, args...).CombinedOutput()
		return string(out), err
	}
	bootstrap := func() {
		t.Helper()
		out, err := run("app_user="+appRole, "migrator_user="+migRole,
			"app_password="+appPass, "migrator_password="+migPass)
		if err != nil {
			t.Fatalf("bootstrap failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "least-privilege roles: OK") {
			t.Fatalf("bootstrap did not verify:\n%s", out)
		}
	}

	// A fresh database: bootstrap, then a "migration" as the migrator.
	bootstrap()
	mig := open(t, withUser(t, scratchAdmin, migRole, migPass))
	exec1(ctx, t, mig, `CREATE TABLE tenants (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text)`)
	exec1(ctx, t, mig, `CREATE TABLE findings (id bigserial PRIMARY KEY, tenant_id uuid REFERENCES tenants(id))`)
	exec1(ctx, t, mig, `CREATE INDEX CONCURRENTLY findings_tenant ON findings(tenant_id)`)
	exec1(ctx, t, mig, `CREATE TABLE epss_scores (cve_id text PRIMARY KEY)`)
	exec1(ctx, t, mig, `INSERT INTO schema_migrations VALUES (1, false)`)
	// Idempotent, and it grants the special cases (TRUNCATE on the feeds).
	bootstrap()

	app := open(t, withUser(t, scratchAdmin, appRole, appPass))

	// Attributes and memberships.
	var su, cdb, crole, repl, bypass bool
	if err := app.QueryRowContext(ctx, `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
		FROM pg_roles WHERE rolname = current_user`).Scan(&su, &cdb, &crole, &repl, &bypass); err != nil {
		t.Fatal(err)
	}
	if su || cdb || crole || repl || bypass {
		t.Fatalf("app role has a privileged attribute: super=%v createdb=%v createrole=%v replication=%v bypassrls=%v", su, cdb, crole, repl, bypass)
	}
	var memberships int
	if err := app.QueryRowContext(ctx, `SELECT count(*) FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user)`).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Fatalf("app role is a member of %d roles, want 0", memberships)
	}

	// What the API does at run time works.
	var tenant string
	if err := app.QueryRowContext(ctx, `INSERT INTO tenants (name) VALUES ('a') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatalf("insert (default privileges on a migrator table): %v", err)
	}
	exec1(ctx, t, app, `INSERT INTO findings (tenant_id) VALUES ($1)`, tenant)
	exec1(ctx, t, app, `UPDATE findings SET tenant_id = tenant_id WHERE tenant_id = $1`, tenant)
	exec1(ctx, t, app, `DELETE FROM findings WHERE tenant_id = $1`, tenant)
	exec1(ctx, t, app, `SELECT pg_advisory_xact_lock(42)`)
	exec1(ctx, t, app, `SELECT set_config('app.current_tenant_id', $1, false)`, tenant)
	exec1(ctx, t, app, `TRUNCATE epss_scores`)
	var version int
	if err := app.QueryRowContext(ctx, `SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	tx, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE staging (x int) ON COMMIT DROP`); err != nil {
		t.Fatalf("temp table (EPSS import): %v", err)
	}
	_ = tx.Rollback()

	// And nothing more.
	for _, q := range []string{
		`CREATE TABLE evil (x int)`,
		`ALTER TABLE findings ADD COLUMN x int`,
		`DROP TABLE findings`,
		`CREATE INDEX evil_idx ON findings(id)`,
		`TRUNCATE findings`,
		`UPDATE schema_migrations SET dirty = true`,
		`DELETE FROM schema_migrations`,
		`COPY findings TO '/tmp/openctem-lp-test'`,
		`COPY findings FROM PROGRAM 'id'`,
		`SELECT pg_read_file('/etc/passwd')`,
		`CREATE ROLE evil`,
		`CREATE SCHEMA evil`,
		`ALTER ROLE ` + appRole + ` SUPERUSER`,
		`SET ROLE ` + migRole,
		`CREATE EXTENSION IF NOT EXISTS dblink`,
	} {
		if _, err := app.ExecContext(ctx, q); err == nil {
			t.Errorf("app role was allowed: %s", q)
		}
	}

	// PUBLIC can no longer connect to the database.
	var publicConnect bool
	if err := root.QueryRowContext(ctx, `SELECT has_database_privilege('public', $1, 'CONNECT')`, dbName).Scan(&publicConnect); err != nil {
		t.Fatal(err)
	}
	if publicConnect {
		t.Error("PUBLIC still has CONNECT on the database")
	}

	// The script refuses to make the superuser running it the app role.
	var self string
	if err := root.QueryRowContext(ctx, `SELECT current_user`).Scan(&self); err != nil {
		t.Fatal(err)
	}
	if out, err := run("app_user="+self, "migrator_user="+migRole); err == nil {
		t.Errorf("bootstrap accepted the superuser as app_user:\n%s", out)
	}
}

func open(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func exec1(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func withDB(t *testing.T, dsn, db string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Skip("DATABASE_URL is not a postgres:// URL")
	}
	u.Path = "/" + db
	return u.String()
}

func withUser(t *testing.T, dsn, user, pass string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}
