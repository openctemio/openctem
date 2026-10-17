package postgres

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The administrators' audit log (migration 002545) is append-only and
// hash-chained: every insert extends the chain whatever the writer sends,
// updates, deletes and truncation are refused, a tampered row is reported by
// VerifyChain, and retention removes only the oldest prefix older than a
// year, anchoring the chain so the rest still verifies. A private database:
// the test tampers with the table on purpose.
func TestAdminAuditChain_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "admin_audit_chain", dir)
	ctx := context.Background()
	repo := NewAuditLogRepository(&DB{DB: db})

	write := func(action string, at time.Time) *admin.AuditLog {
		t.Helper()
		l := &admin.AuditLog{ID: shared.NewID(), AdminEmail: "root@example.com", Action: action,
			Success: true, CreatedAt: at, Severity: "info", RequestBody: map[string]any{"k": "v"}}
		if err := repo.Create(ctx, l); err != nil {
			t.Fatalf("create %s: %v", action, err)
		}
		return l
	}
	verify := func() *admin.AuditChainReport {
		t.Helper()
		r, err := repo.VerifyChain(ctx)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return r
	}

	old := time.Now().AddDate(-2, 0, 0)
	write("old.one", old)
	write("old.two", old.Add(time.Minute))
	middle := write("recent.one", time.Now())
	write("recent.two", time.Now())

	r := verify()
	if !r.OK() || r.Entries != 4 || r.FirstPosition != 1 || r.LastPosition != 4 {
		t.Fatalf("fresh chain: %+v", r)
	}

	// The writer cannot choose its own chain values.
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_audit_logs (admin_email, action, chain_position, prev_hash, hash)
		VALUES ('x@example.com', 'forged.chain', 999, 'p', 'h')`); err != nil {
		t.Fatalf("insert with chain values: %v", err)
	}
	var pos int64
	var hash string
	if err := db.QueryRowContext(ctx, `SELECT chain_position, hash FROM admin_audit_logs WHERE action = 'forged.chain'`).Scan(&pos, &hash); err != nil {
		t.Fatal(err)
	}
	if pos != 5 || hash == "h" {
		t.Fatalf("insert kept the caller's chain values: position %d hash %q", pos, hash)
	}

	// Append-only, even for the owner, outside the retention prune.
	for _, q := range []string{
		`UPDATE admin_audit_logs SET action = 'changed' WHERE action = 'recent.one'`,
		`DELETE FROM admin_audit_logs WHERE action = 'recent.one'`,
		`TRUNCATE admin_audit_logs`,
	} {
		_, err := db.ExecContext(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: %v, want the append-only refusal", q, err)
		}
	}

	// Tamper with the triggers off (what an attacker with the owner's
	// rights could do): VerifyChain names the row.
	tamper := func(q string, args ...any) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		steps := []struct {
			q    string
			args []any
		}{
			{`ALTER TABLE admin_audit_logs DISABLE TRIGGER admin_audit_refuse_change`, nil},
			{q, args},
			{`ALTER TABLE admin_audit_logs ENABLE TRIGGER admin_audit_refuse_change`, nil},
		}
		for _, st := range steps {
			if _, err := tx.ExecContext(ctx, st.q, st.args...); err != nil {
				t.Fatalf("%s: %v", st.q, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	tamper(`UPDATE admin_audit_logs SET error_message = 'edited' WHERE id = $1`, middle.ID.String())
	r = verify()
	if r.OK() || len(r.Breaks) != 1 || r.Breaks[0].ID != middle.ID.String() || r.Breaks[0].Reason != admin.ChainBreakChanged {
		t.Fatalf("edited row: %+v", r.Breaks)
	}
	tamper(`DELETE FROM admin_audit_logs WHERE action = 'recent.two'`)
	r = verify()
	if len(r.Breaks) != 2 || r.Breaks[1].Position != 5 || r.Breaks[1].Reason != admin.ChainBreakGap {
		t.Fatalf("deleted row: %+v", r.Breaks)
	}

	// Retention: only the rows older than a year, as a prefix, and the chain
	// stays anchored. A cutoff in the future is held at a year ago.
	n, err := repo.DeleteOlderThan(ctx, time.Now().Add(time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("prune: %d, %v; want the 2 rows older than a year", n, err)
	}
	r = verify()
	if r.AnchorPosition != 2 || r.FirstPosition != 3 || r.Entries != 2 {
		t.Fatalf("after prune: %+v", r)
	}
	if n, err = repo.DeleteOlderThan(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("second prune: %d, %v; want 0 (nothing older than a year)", n, err)
	}
}

// The migration chains the rows already in the table, in the order they
// were written, and its down migration removes the chain again.
func TestAdminAuditChainMigrationBackfill_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "admin_audit_backfill", dir)
	ctx := context.Background()
	v := testdb.MigrationVersion(t, dir, "admin_audit_append_only")
	testdb.Migrate(t, db, dir, v, v, true)

	for i, action := range []string{"first", "second", "third"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO admin_audit_logs (admin_email, action, created_at) VALUES ($1, $2, $3)`,
			"root@example.com", action, time.Now().Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)

	got := queryStrings(t, db, `SELECT action FROM admin_audit_logs ORDER BY chain_position`)
	if strings.Join(got, ",") != "first,second,third" {
		t.Fatalf("backfilled order: %v", got)
	}
	r, err := NewAuditLogRepository(&DB{DB: db}).VerifyChain(ctx)
	if err != nil || !r.OK() || r.Entries != 3 {
		t.Fatalf("backfilled chain: %+v, %v", r, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var cols int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'admin_audit_logs' AND column_name IN ('chain_position', 'prev_hash', 'hash')`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	if cols != 0 {
		t.Fatalf("down migration left %d chain columns", cols)
	}
	if _, err := db.ExecContext(ctx, `UPDATE admin_audit_logs SET action = action`); err != nil {
		t.Fatalf("after down the table is writable again: %v", err)
	}
}

// queryStrings runs a one-column query and returns its values.
func queryStrings(t *testing.T, db *sql.DB, q string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// adminAuditHashedColumns are the admin_audit_logs columns
// admin_audit_row_payload hashes, in its order. A column added to the table
// must be added to that function (in a new migration) and here: until then
// TestAdminAuditChainCoversEveryColumn_DB fails, because a column outside the
// hash could be edited without breaking the chain.
var adminAuditHashedColumns = []string{
	"id", "admin_id", "admin_email", "action", "resource_type", "resource_id",
	"resource_name", "request_method", "request_path", "request_body",
	"response_status", "ip_address", "user_agent", "success", "error_message",
	"severity", "created_at",
}

// Every column of admin_audit_logs except the chain's own is in the hash,
// and the payload function names each of them.
func TestAdminAuditChainCoversEveryColumn_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_cols", "../../../migrations")
	cols := queryStrings(t, db, `SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'admin_audit_logs'
		  AND column_name NOT IN ('chain_position', 'prev_hash', 'hash') ORDER BY column_name`)
	want := append([]string(nil), adminAuditHashedColumns...)
	sort.Strings(want)
	if strings.Join(cols, ",") != strings.Join(want, ",") {
		t.Fatalf("admin_audit_logs columns %v, hashed %v: add the new column to admin_audit_row_payload and adminAuditHashedColumns", cols, want)
	}
	def := queryStrings(t, db, `SELECT pg_get_functiondef('admin_audit_row_payload(admin_audit_logs)'::regprocedure)`)
	for _, c := range adminAuditHashedColumns {
		if !strings.Contains(def[0], "r."+c) {
			t.Errorf("admin_audit_row_payload does not hash %s", c)
		}
	}
}

// ChainHead reports the newest row's position and hash, which the sink's
// read of the rows after a cursor carries too (the off-box sink relies on both).
func TestAdminAuditChainHeadMatchesRows_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_head", "../../../migrations")
	ctx := context.Background()
	repo := NewAuditLogRepository(&DB{DB: db})
	if pos, hash, err := repo.ChainHead(ctx); err != nil || pos != 0 || hash != "" {
		t.Fatalf("empty chain head: %d %q %v", pos, hash, err)
	}
	for _, action := range []string{"console.login", "admin.update"} {
		if err := repo.Create(ctx, &admin.AuditLog{ID: shared.NewID(), AdminEmail: "root@example.com", Action: action,
			Success: true, CreatedAt: time.Now(), Severity: "info"}); err != nil {
			t.Fatal(err)
		}
	}
	seen, err := repo.ReadForwardRows(ctx, 0, 10)
	if err != nil || len(seen) != 2 || seen[0].Position != 1 || seen[1].Position != 2 || seen[1].PrevHash != seen[0].Hash ||
		seen[0].Hash == "" || seen[1].Log.Action != "admin.update" {
		t.Fatalf("rows %+v err=%v", seen, err)
	}
	pos, hash, err := repo.ChainHead(ctx)
	if err != nil || pos != 2 || hash != seen[1].Hash {
		t.Fatalf("head: %d %q %v; want 2 %q", pos, hash, err, seen[1].Hash)
	}
}
