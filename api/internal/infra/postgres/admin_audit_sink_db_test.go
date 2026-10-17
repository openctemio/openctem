package postgres

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/auditsink"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newSinkAuditLog(action string) *admin.AuditLog {
	id := shared.NewID()
	return &admin.AuditLog{ID: shared.NewID(), AdminID: &id, AdminEmail: "root@example.com", Action: action,
		ResourceType: "sensor", ResourceID: &id, RequestMethod: "POST", RequestPath: "/x", ResponseStatus: 201,
		IPAddress: "203.0.113.9", UserAgent: "ua-withheld", Success: true, CreatedAt: time.Now(), Severity: "info",
		RequestBody: map[string]any{"secret": "body-withheld"}}
}

// The sink's database side: rows are read in chain order after a cursor with
// only the shipped columns, the head is the chain tail, the cursor persists
// and never moves backwards, and a row edited behind the trigger's back is
// reported by the verification the forwarder runs. A private database: the
// test tampers with the table on purpose.
func TestAdminAuditSink_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_sink", "../../../migrations")
	ctx := context.Background()
	repo := NewAuditLogRepository(&DB{DB: db})
	for _, a := range []string{"one", "two", "three"} {
		if err := repo.Create(ctx, newSinkAuditLog(a)); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := repo.ReadForwardRows(ctx, 1, 10)
	if err != nil || len(rows) != 2 || rows[0].Position != 2 || rows[1].Position != 3 {
		t.Fatalf("rows after 1: %+v err=%v", rows, err)
	}
	l := rows[0].Log
	if l.Action != "two" || l.IPAddress != "203.0.113.9" || l.ResourceID == nil || l.AdminID == nil || l.ResponseStatus != 201 ||
		rows[0].Hash == "" || rows[0].PrevHash == "" || l.UserAgent != "" || l.RequestBody != nil {
		t.Fatalf("row %+v / %+v", rows[0], l)
	}
	if bounded, _ := repo.ReadForwardRows(ctx, 0, 1); len(bounded) != 1 {
		t.Fatalf("limit not honored: %d", len(bounded))
	}
	pos, hash, err := repo.ChainHead(ctx)
	if err != nil || pos != 3 || hash != rows[1].Hash {
		t.Fatalf("head %d %s err=%v", pos, hash, err)
	}

	c, err := repo.LoadForwardCursor(ctx)
	if err != nil || c.Position != 0 {
		t.Fatalf("fresh cursor %+v err=%v", c, err)
	}
	if err := repo.SaveForwardCursor(ctx, auditsink.Cursor{Position: 3, Hash: hash}); err != nil {
		t.Fatal(err)
	}
	// A stale writer cannot rewind it.
	if err := repo.SaveForwardCursor(ctx, auditsink.Cursor{Position: 1, Hash: "old"}); err != nil {
		t.Fatal(err)
	}
	c, _ = repo.LoadForwardCursor(ctx)
	if c.Position != 3 || c.Hash != hash {
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

// Every admin_audit_logs column is either shipped off the box or deliberately
// withheld. A column added to the table fails this test until someone decides
// which, so nothing leaves the box (or is silently left out of the copy) by
// accident.
func TestAdminAuditSinkColumns_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_sinkcols", "../../../migrations")
	ctx := context.Background()
	cols := queryStrings(t, db, `SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'admin_audit_logs'`)
	decided := append(append([]string(nil), AdminAuditShippedColumns...), AdminAuditWithheldColumns...)
	sort.Strings(cols)
	sort.Strings(decided)
	if strings.Join(cols, ",") != strings.Join(decided, ",") {
		t.Fatalf("admin_audit_logs columns %v, decided (shipped + withheld) %v: add the new column to AdminAuditShippedColumns "+
			"(and the sink's rowEvent) or to AdminAuditWithheldColumns", cols, decided)
	}

	// The withheld columns are never read into the shipped row.
	repo := NewAuditLogRepository(&DB{DB: db})
	if err := repo.Create(ctx, newSinkAuditLog("x")); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ReadForwardRows(ctx, 0, 10)
	if err != nil || len(got) != 1 || got[0].Log.UserAgent != "" || got[0].Log.RequestBody != nil {
		t.Fatalf("rows %+v err=%v", got, err)
	}
	// A column added later is not read (and so not shipped) until listed.
	if _, err := db.ExecContext(ctx, `ALTER TABLE admin_audit_logs ADD COLUMN internal_note text DEFAULT 'secret'`); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.ReadForwardRows(ctx, 0, 10); err != nil || len(got) != 1 {
		t.Fatalf("after ADD COLUMN: %+v err=%v", got, err)
	}
}
