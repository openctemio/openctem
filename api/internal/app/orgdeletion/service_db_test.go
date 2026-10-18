package orgdeletion_test

// Organization deletion with a grace period against a migrated database:
// an owner schedules it, the organization is refused at the access gate at
// once, nothing is deleted before the grace ends, an owner cancels, and the
// purge worker deletes it once due (the real tenant delete). A member who is
// not an owner can do neither. Requires DATABASE_URL.

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/internal/app/suspension"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestOrganizationDeletionGrace_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := sqlDB.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()

	org := shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Deletion IT', $2)`, org.String(), "odel-"+org.String()[24:])
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM audit_log_chain WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
			_, _ = sqlDB.ExecContext(context.Background(), q, org.String())
		}
	})
	user := func(role string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Deletion IT')`, id.String(), "odel-"+id.String()[24:]+"@it.test")
		t.Cleanup(func() { _, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id.String(), org.String(), role)
		return id
	}
	owner, member := user("owner"), user("member")

	store := postgres.NewOrganizationStatusRepository(db)
	gate := suspension.NewGate(store, nil, log)
	tenants := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	svc := orgdeletion.NewService(store, tenants, gate, nil, auditapp.NewAuditService(postgres.NewAuditRepository(db), log), log)
	now := time.Now().UTC()
	svc.SetClock(func() time.Time { return now })
	actx := auditapp.AuditContext{ActorID: owner.String()}

	if _, err := svc.Schedule(ctx, actx, org, member); !errors.Is(err, orgdeletion.ErrNotOwner) {
		t.Fatalf("member schedules: %v", err)
	}
	due, err := svc.Schedule(ctx, actx, org, owner)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if err := gate.CheckAccess(ctx, org); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
		t.Fatalf("a pending organization must be refused at the gate: %v", err)
	}
	var status string
	var dueAt sql.NullTime
	if err := sqlDB.QueryRow(`SELECT status, deletion_due_at FROM tenants WHERE id = $1`, org.String()).Scan(&status, &dueAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending_deletion" || !dueAt.Valid || dueAt.Time.Sub(due).Abs() > time.Second {
		t.Fatalf("row: status=%s due=%v want %v", status, dueAt, due)
	}
	// The check keeps the due date and the status together.
	if _, err := sqlDB.Exec(`UPDATE tenants SET deletion_due_at = NULL WHERE id = $1`, org.String()); err == nil {
		t.Fatal("a pending organization without a due date was accepted")
	}

	if n, err := svc.PurgeDue(ctx); n != 0 || err != nil {
		t.Fatalf("purge before the grace ended: %d %v", n, err)
	}
	if err := svc.Cancel(ctx, actx, org, member); !errors.Is(err, orgdeletion.ErrNotOwner) {
		t.Fatalf("member cancels: %v", err)
	}
	if err := svc.Cancel(ctx, actx, org, owner); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := gate.CheckAccess(ctx, org); err != nil {
		t.Fatalf("a cancelled deletion must reopen the organization: %v", err)
	}

	// Schedule again and let the grace run out: the worker deletes it.
	if _, err := svc.Schedule(ctx, actx, org, owner); err != nil {
		t.Fatal(err)
	}
	now = now.Add(tenantdom.DeletionGrace + time.Minute)
	n, err := svc.PurgeDue(ctx)
	if err != nil || n < 1 {
		t.Fatalf("purge after the grace: %d %v", n, err)
	}
	var left int
	if err := sqlDB.QueryRow(`SELECT count(*) FROM tenants WHERE id = $1`, org.String()).Scan(&left); err != nil || left != 0 {
		t.Fatalf("organization still there: %d %v", left, err)
	}
	// Member accounts are kept.
	if err := sqlDB.QueryRow(`SELECT count(*) FROM users WHERE id = $1`, owner.String()).Scan(&left); err != nil || left != 1 {
		t.Fatalf("owner account: %d %v", left, err)
	}
}
