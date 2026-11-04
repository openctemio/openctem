package extensiontest

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	ext "github.com/openctemio/openctem/api/pkg/extension"
)

// DB returns a database for this test alone with the core migrations
// applied, then e's migrations in e.Schema (when it has any), dropped when
// the test ends. It needs no access to the core's internal packages, so an
// extension in another module uses it as is. Skipped unless DATABASE_URL
// names a test database (a name ending in _test) whose role may create
// databases; with OPENCTEM_TEST_DB_REQUIRED=1 those preconditions fail the
// test instead.
func DB(t testing.TB, e ext.Extension) *sql.DB {
	t.Helper()
	db := testdb.PrivateDatabase(t, "ext", CoreMigrationsDir(t))
	if e.Migrations == nil {
		return db
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := applyExtension(context.Background(), db, e); err != nil {
		t.Fatal(err)
	}
	return db
}

// CoreMigrationsDir is the core's migrations directory, located next to
// this package's source (in a checkout or in the module cache).
func CoreMigrationsDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("extensiontest: cannot locate the core migrations")
	}
	// file: <api>/pkg/extension/extensiontest/db.go
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "migrations")
}

// applyExtension applies e's up migrations in its schema, in version order.
func applyExtension(ctx context.Context, db *sql.DB, e ext.Extension) error {
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %q`, e.Schema)); err != nil {
		return err
	}
	ups, err := fs.Glob(e.Migrations, "*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(ups)
	for _, f := range ups {
		b, err := fs.ReadFile(e.Migrations, f)
		if err != nil {
			return err
		}
		if err := inSchema(ctx, db, e.Schema, string(b)); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	return nil
}

func inSchema(ctx context.Context, db *sql.DB, schema, stmt string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`SET LOCAL search_path TO %q, public`, schema)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return err
	}
	return tx.Commit()
}
