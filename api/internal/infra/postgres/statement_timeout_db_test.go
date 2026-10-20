package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// A role limit stops a plain statement, a statement with its own limit runs
// past it, and the role limit is back after the transaction.
func TestStatementTimeoutHelpers_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "stmt_timeout", "../../../migrations")
	db.SetMaxOpenConns(1) // one session, so the session limit below is the one every call sees
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `SET statement_timeout = '300ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_sleep(1)`); err == nil || !strings.Contains(err.Error(), "statement timeout") {
		t.Fatalf("plain statement should hit the 300ms limit, got %v", err)
	}
	if _, err := execWithTimeout(ctx, db, 10*time.Second, `SELECT pg_sleep(1)`); err != nil {
		t.Fatalf("statement with its own limit must run: %v", err)
	}
	var v string
	if err := db.QueryRowContext(ctx, `SHOW statement_timeout`).Scan(&v); err != nil || v != "300ms" {
		t.Fatalf("role limit must return after commit, got %q %v", v, err)
	}
	if _, err := execWithTimeout(ctx, db, 2*time.Second, `SELECT pg_sleep(3)`); err == nil {
		t.Fatal("a 2s limit must stop a 3s statement")
	}
	if _, err := execWithTimeout(ctx, db, 2*maxStatementTimeout, `SELECT 1`); err == nil {
		t.Fatal("a limit above the ceiling must be refused")
	}
}
