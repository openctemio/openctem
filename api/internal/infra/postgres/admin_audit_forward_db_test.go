package postgres

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/adminauditfwd"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The off-box forwarder's database side (migration 002775): rows are read in
// chain order after a cursor, the head is the chain tail, the cursor persists
// and never moves backwards, and a row edited behind the trigger's back is
// reported by the verification the forwarder runs. A private database: the
// test tampers with the table on purpose.
func TestAdminAuditForward_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_fwd", "../../../migrations")
	ctx := context.Background()
	repo := NewAuditLogRepository(&DB{DB: db})
	for _, a := range []string{"one", "two", "three"} {
		l := &admin.AuditLog{ID: shared.NewID(), AdminEmail: "root@example.com", Action: a, Success: true,
			CreatedAt: time.Now(), Severity: "info", RequestBody: map[string]any{}}
		if err := repo.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := repo.ReadForwardRows(ctx, 1, 10)
	if err != nil || len(rows) != 2 || rows[0].Position != 2 || rows[1].Position != 3 {
		t.Fatalf("rows after 1: %+v err=%v", rows, err)
	}
	var m map[string]any
	if err := json.Unmarshal(rows[0].JSON, &m); err != nil || m["action"] != "two" || m["hash"] != rows[0].Hash {
		t.Fatalf("row json %s err=%v", rows[0].JSON, err)
	}
	if bounded, _ := repo.ReadForwardRows(ctx, 0, 1); len(bounded) != 1 {
		t.Fatalf("limit not honored: %d", len(bounded))
	}
	head, err := repo.ChainHead(ctx)
	if err != nil || head.Position != 3 || head.Hash != rows[1].Hash {
		t.Fatalf("head %+v err=%v", head, err)
	}

	c, err := repo.LoadForwardCursor(ctx)
	if err != nil || c.Position != 0 {
		t.Fatalf("fresh cursor %+v err=%v", c, err)
	}
	if err := repo.SaveForwardCursor(ctx, adminauditfwd.Cursor{Position: 3, Hash: head.Hash}); err != nil {
		t.Fatal(err)
	}
	// A stale writer cannot rewind it.
	if err := repo.SaveForwardCursor(ctx, adminauditfwd.Cursor{Position: 1, Hash: "old"}); err != nil {
		t.Fatal(err)
	}
	c, _ = repo.LoadForwardCursor(ctx)
	if c.Position != 3 || c.Hash != head.Hash {
		t.Fatalf("cursor after stale save: %+v", c)
	}

	// Tamper with a row as the table owner (trigger off), then verify.
	if _, err := db.ExecContext(ctx, `ALTER TABLE admin_audit_logs DISABLE TRIGGER admin_audit_refuse_change`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE admin_audit_logs SET action = 'forged' WHERE chain_position = 2`); err != nil {
		t.Fatal(err)
	}
	rep, err := repo.VerifyChain(ctx)
	if err != nil || rep.OK() {
		t.Fatalf("tamper not detected: %+v err=%v", rep, err)
	}
}

// The forwarder ships an explicit column list, never the whole row: a column
// added to admin_audit_logs is not shipped until it is listed. The test fails
// when the table and the list disagree, and the shipped JSON has exactly the
// listed keys.
func TestAdminAuditForwardColumns_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_fwdcols", "../../../migrations")
	ctx := context.Background()
	cols := queryStrings(t, db, `SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'admin_audit_logs' ORDER BY column_name`)
	want := append([]string(nil), adminAuditForwardColumns...)
	sort.Strings(want)
	if strings.Join(cols, ",") != strings.Join(want, ",") {
		t.Fatalf("admin_audit_logs columns %v, forwarded %v: a new column must be reviewed and added to adminAuditForwardColumns", cols, want)
	}

	repo := NewAuditLogRepository(&DB{DB: db})
	l := &admin.AuditLog{ID: shared.NewID(), AdminEmail: "root@example.com", Action: "x", Success: true,
		CreatedAt: time.Now(), Severity: "info", RequestBody: map[string]any{}}
	if err := repo.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	rows, err := repo.ReadForwardRows(ctx, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err=%v", rows, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rows[0].JSON, &m); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("shipped keys %v, want %v", got, want)
	}

	// A column added later is NOT shipped until listed.
	if _, err := db.ExecContext(ctx, `ALTER TABLE admin_audit_logs ADD COLUMN internal_note text DEFAULT 'secret'`); err != nil {
		t.Fatal(err)
	}
	rows, err = repo.ReadForwardRows(ctx, 0, 10)
	if err != nil || len(rows) != 1 || strings.Contains(string(rows[0].JSON), "internal_note") || strings.Contains(string(rows[0].JSON), "secret") {
		t.Fatalf("an unlisted column was shipped: %s err=%v", rows[0].JSON, err)
	}
}
