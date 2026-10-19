package adminbootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
)

// recordingNotifier keeps the notices instead of emailing them.
type recordingNotifier struct{ got []adminconsole.RosterChange }

func (n *recordingNotifier) NotifyRosterChange(_ context.Context, c adminconsole.RosterChange) error {
	n.got = append(n.got, c)
	return nil
}

type auditRow struct {
	Action, ResourceName, Severity, AdminEmail string
	Meta                                       map[string]any
}

func auditRows(t *testing.T, db *sql.DB) []auditRow {
	t.Helper()
	rows, err := db.Query(`SELECT action, coalesce(resource_name, ''), severity, admin_email, coalesce(request_body, '{}')
		FROM admin_audit_logs ORDER BY chain_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var body []byte
		if err := rows.Scan(&r.Action, &r.ResourceName, &r.Severity, &r.AdminEmail, &body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &r.Meta); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func verifyChain(t *testing.T, db *sql.DB) {
	t.Helper()
	r, err := postgres.NewAuditLogRepository(&postgres.DB{DB: db}).VerifyChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() {
		t.Fatalf("admin audit chain broken: %+v", r)
	}
}

type adminRow struct {
	ID, Role, UserID   string
	Active, BreakGlass bool
}

func getAdmin(t *testing.T, db *sql.DB, email string) *adminRow {
	t.Helper()
	var a adminRow
	err := db.QueryRow(`SELECT id, role, coalesce(user_id::text, ''), is_active, is_break_glass FROM admin_users WHERE email = $1`, email).
		Scan(&a.ID, &a.Role, &a.UserID, &a.Active, &a.BreakGlass)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return &a
}

func runOpts(t *testing.T, db *sql.DB, o Options) (string, error) {
	t.Helper()
	if o.Actor == (Actor{}) {
		o.Actor = Actor{OSUser: "alice", Hostname: "ops-host-1"}
	}
	if err := o.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var out bytes.Buffer
	err := Run(context.Background(), db, o, &out)
	return out.String(), err
}

// One test database for the whole flow; each step builds on the previous one.
func TestBootstrapAccountability_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "adminbootstrap", "../../migrations")
	const primary, backup = "root@example.com", "breakglass@example.com"

	// Create: one chained admin.created entry per administrator.
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows := auditRows(t, db)
	if len(rows) != 2 || rows[0].Action != AuditActionAdminCreated || rows[1].Action != AuditActionAdminCreated ||
		rows[0].ResourceName != primary || rows[1].ResourceName != backup {
		t.Fatalf("after create: %+v", rows)
	}
	if r := rows[0]; r.AdminEmail != AuditActor || r.Severity != "high" || r.Meta["os_user"] != "alice" ||
		r.Meta["hostname"] != "ops-host-1" || r.Meta["role_after"] != "super_admin" || r.Meta["status_after"] != "active" {
		t.Fatalf("created entry: %+v", r)
	}
	verifyChain(t, db)
	backupBefore := getAdmin(t, db, backup)

	// Re-running changes nothing and writes nothing.
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup}); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if n := len(auditRows(t, db)); n != 2 {
		t.Fatalf("idempotent re-run wrote %d entries", n-2)
	}

	// -force needs confirmation: without a terminal and without -yes nothing changes.
	primaryBefore := getAdmin(t, db, primary)
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true}); err == nil ||
		!strings.Contains(err.Error(), "-yes") {
		t.Fatalf("force without confirmation: %v", err)
	}
	// A wrong typed-back email changes nothing either.
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true,
		Confirm: func(string) bool { return false }}); err == nil || !strings.Contains(err.Error(), "did not match") {
		t.Fatalf("force with wrong confirmation: %v", err)
	}
	if got := getAdmin(t, db, primary); got.ID != primaryBefore.ID || len(auditRows(t, db)) != 2 {
		t.Fatal("a refused -force changed something")
	}

	// -force replaces the primary only: the backup keeps its row and account.
	n := &recordingNotifier{}
	var confirmed []string
	out, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true, Notifier: n,
		Confirm: func(e string) bool { confirmed = append(confirmed, e); return true }})
	if err != nil {
		t.Fatalf("force: %v", err)
	}
	if len(confirmed) != 1 || confirmed[0] != primary {
		t.Fatalf("confirmation asked for %v, want only the primary", confirmed)
	}
	if got := getAdmin(t, db, backup); *got != *backupBefore {
		t.Fatalf("-force touched the backup: %+v -> %+v", backupBefore, got)
	}
	if got := getAdmin(t, db, primary); got.ID == primaryBefore.ID || got.Role != "super_admin" || !got.Active {
		t.Fatalf("primary not replaced: %+v", got)
	}
	if !strings.Contains(out, "before: role super_admin, active") || !strings.Contains(out, "-force-backup") {
		t.Fatalf("output should show before/after and the backup note:\n%s", out)
	}
	rows = auditRows(t, db)
	if len(rows) != 3 || rows[2].Action != AuditActionAdminReplaced || rows[2].ResourceName != primary ||
		rows[2].Meta["role_before"] != "super_admin" || rows[2].Meta["replaced_admin_id"] != primaryBefore.ID {
		t.Fatalf("after force: %+v", rows)
	}
	verifyChain(t, db)
	// The other active administrator (the backup) is told; the replaced one is not.
	if len(n.got) != 1 || len(n.got[0].Recipients) != 1 || n.got[0].Recipients[0] != backup ||
		!strings.Contains(n.got[0].Summary, "replaced administrator "+primary) || strings.Contains(n.got[0].Summary, "Oc") {
		t.Fatalf("notice: %+v", n.got)
	}

	// -force on a readonly administrator without -role keeps it readonly.
	if _, err := db.Exec(`UPDATE admin_users SET role = 'readonly' WHERE email = $1`, primary); err != nil {
		t.Fatal(err)
	}
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true, Yes: true}); err != nil {
		t.Fatalf("force readonly: %v", err)
	}
	if got := getAdmin(t, db, primary); got.Role != "readonly" {
		t.Fatalf("-force without -role changed the role to %s", got.Role)
	}
	rows = auditRows(t, db)
	if last := rows[len(rows)-1]; last.Meta["role_before"] != "readonly" || last.Meta["role_after"] != "readonly" {
		t.Fatalf("readonly replace entry: %+v", last)
	}

	// An inactive administrator is not brought back without an explicit -role.
	if _, err := db.Exec(`UPDATE admin_users SET is_active = FALSE WHERE email = $1`, primary); err != nil {
		t.Fatal(err)
	}
	before := len(auditRows(t, db))
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true, Yes: true}); err == nil ||
		!strings.Contains(err.Error(), "-role") {
		t.Fatalf("force on inactive admin without -role: %v", err)
	}
	if got := getAdmin(t, db, primary); got.Active || len(auditRows(t, db)) != before {
		t.Fatal("refused reactivation changed something")
	}
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, Force: true, Yes: true, Role: "ops_admin"}); err != nil {
		t.Fatalf("force with explicit -role: %v", err)
	}
	if got := getAdmin(t, db, primary); got.Role != "ops_admin" || !got.Active {
		t.Fatalf("explicit -role: %+v", got)
	}

	// -force-backup replaces the backup.
	backupBefore = getAdmin(t, db, backup)
	if _, err := runOpts(t, db, Options{Email: primary, BackupEmail: backup, ForceBackup: true, Yes: true}); err != nil {
		t.Fatalf("force-backup: %v", err)
	}
	if got := getAdmin(t, db, backup); got.ID == backupBefore.ID {
		t.Fatal("-force-backup did not replace the backup")
	}
	verifyChain(t, db)

	// The last active super admin (now the backup) cannot be replaced by a
	// lower role; re-creating it as super admin is fine.
	if _, err := db.Exec(`UPDATE admin_users SET role = 'readonly' WHERE email = $1`, primary); err != nil {
		t.Fatal(err)
	}
	before = len(auditRows(t, db))
	backupBefore = getAdmin(t, db, backup)
	if _, err := runOpts(t, db, Options{Email: backup, NoBackup: true, Force: true, Yes: true, Role: "readonly"}); !errors.Is(err, errLastSuperAdmin) {
		t.Fatalf("replacing the last super admin with readonly: %v", err)
	}
	if got := getAdmin(t, db, backup); *got != *backupBefore || len(auditRows(t, db)) != before {
		t.Fatal("refused last-super-admin replacement changed something")
	}
	if _, err := runOpts(t, db, Options{Email: backup, NoBackup: true, Force: true, Yes: true, Role: "super_admin"}); err != nil {
		t.Fatalf("re-creating the last super admin as super admin: %v", err)
	}

	// -force with -email naming the break-glass backup keeps it break-glass.
	if _, err := runOpts(t, db, Options{Email: backup, NoBackup: true, Force: true, Yes: true}); err != nil {
		t.Fatalf("force on the backup through -email: %v", err)
	}
	if !getAdmin(t, db, backup).BreakGlass {
		t.Fatal("-force through -email dropped the break-glass mark")
	}

	// -link: an administrator from before sign-in accounts gets one, audited.
	const legacy = "legacy@example.com"
	if _, err := db.Exec(`INSERT INTO admin_users (id, email, name, role, is_active, created_at, updated_at)
		VALUES (gen_random_uuid(), $1, 'legacy', 'ops_admin', FALSE, NOW(), NOW())`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := runOpts(t, db, Options{Email: legacy, LinkOnly: true}); err != nil {
		t.Fatalf("link: %v", err)
	}
	rows = auditRows(t, db)
	last := rows[len(rows)-1]
	if last.Action != AuditActionAdminRelinked || last.ResourceName != legacy || last.Meta["status_before"] != "inactive" ||
		last.Meta["status_after"] != "active" || last.Meta["role_after"] != "ops_admin" {
		t.Fatalf("relinked entry: %+v", last)
	}
	if got := getAdmin(t, db, legacy); got.UserID == "" || !got.Active || got.Role != "ops_admin" {
		t.Fatalf("link: %+v", got)
	}
	verifyChain(t, db)
}
