package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// Organization suspension and account block against a migrated database:
// the store, the scheduled work that skips a suspended organization, the
// sign-in membership lists, and an account block that a stale entity save
// cannot lift. Requires DATABASE_URL.
func TestOrganizationSuspension_DB(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Suspension IT', $2)`, id.String(), "susp-"+id.String()[24:])
		t.Cleanup(func() {
			for _, q := range []string{`DELETE FROM scans WHERE tenant_id = $1`, `DELETE FROM report_schedules WHERE tenant_id = $1`,
				`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
				_, _ = sqlDB.ExecContext(context.Background(), q, id.String())
			}
		})
		return id
	}
	newUser := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Suspension IT')`, id.String(), "susp-"+id.String()[24:]+"@it.test")
		t.Cleanup(func() { _, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
		return id
	}
	adminID := shared.NewID()
	exec(`INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Ops', 'ops_admin')`,
		adminID.String(), "susp-admin-"+adminID.String()[24:]+"@it.test")
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM admin_users WHERE id = $1`, adminID.String())
	})

	store := NewOrganizationStatusRepository(db)
	suspended, active := newTenant(), newTenant()

	t.Run("store: suspend once, read who and why, lift once", func(t *testing.T) {
		if s, err := store.OrganizationStatus(ctx, suspended); err != nil || s != tenantdom.OrganizationActive {
			t.Fatalf("default status = %q %v", s, err)
		}
		ok, err := store.Suspend(ctx, suspended, &adminID, "abuse report 42", time.Now())
		if err != nil || !ok {
			t.Fatalf("suspend: %v %v", ok, err)
		}
		if ok, _ := store.Suspend(ctx, suspended, &adminID, "again", time.Now()); ok {
			t.Fatal("a second suspension must change nothing")
		}
		sus, name, err := store.Suspension(ctx, suspended)
		if err != nil || sus.Status != tenantdom.OrganizationSuspended || sus.Reason != "abuse report 42" ||
			sus.By == nil || *sus.By != adminID || sus.At == nil || name != "Suspension IT" {
			t.Fatalf("suspension = %+v %q %v", sus, name, err)
		}
		if _, err := store.OrganizationStatus(ctx, shared.NewID()); err == nil {
			t.Fatal("unknown organization must be not found")
		}
	})

	t.Run("scheduled work skips the suspended organization", func(t *testing.T) {
		ids, err := NewTenantRepository(db).ListActiveTenantIDs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(ids, suspended) || !slices.Contains(ids, active) {
			t.Fatalf("ListActiveTenantIDs: suspended listed=%v active listed=%v",
				slices.Contains(ids, suspended), slices.Contains(ids, active))
		}
		past := time.Now().Add(-time.Hour)
		for _, tid := range []shared.ID{suspended, active} {
			exec(`INSERT INTO scans (tenant_id, name, scan_type, scanner_name, targets, schedule_type, schedule_cron, next_run_at, status)
			      VALUES ($1, 'due', 'single', 'nuclei', ARRAY['example.com'], 'crontab', '0 * * * *', $2, 'active')`, tid.String(), past)
			exec(`INSERT INTO report_schedules (id, tenant_id, name, report_type, cron_expression, is_active, next_run_at)
			      VALUES ($1, $2, 'due', 'executive', '0 * * * *', true, $3)`, shared.NewID().String(), tid.String(), past)
		}
		due, err := NewScanRepository(db).ListDueForExecution(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		seen := map[shared.ID]bool{}
		for _, s := range due {
			seen[s.TenantID] = true
		}
		if seen[suspended] || !seen[active] {
			t.Fatalf("due scans: suspended=%v active=%v", seen[suspended], seen[active])
		}
		reports, err := NewReportScheduleRepository(db).ListDue(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		seen = map[shared.ID]bool{}
		for _, r := range reports {
			seen[r.TenantID()] = true
		}
		if seen[suspended] || !seen[active] {
			t.Fatalf("due reports: suspended=%v active=%v", seen[suspended], seen[active])
		}
	})

	t.Run("sign-in lists the suspended organization with the suspended ones", func(t *testing.T) {
		uid := newUser()
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'owner'), ($1, $3, 'member')`,
			uid.String(), suspended.String(), active.String())
		ms, err := NewTenantRepository(db).GetUserMembershipsWithStatus(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms.Active) != 1 || ms.Active[0].TenantID != active.String() || ms.Active[0].OrganizationSuspended {
			t.Fatalf("active = %+v", ms.Active)
		}
		if len(ms.Suspended) != 1 || ms.Suspended[0].TenantID != suspended.String() || !ms.Suspended[0].OrganizationSuspended {
			t.Fatalf("suspended = %+v", ms.Suspended)
		}
	})

	t.Run("lifting restores scheduling", func(t *testing.T) {
		if ok, err := store.Unsuspend(ctx, suspended); err != nil || !ok {
			t.Fatalf("unsuspend: %v %v", ok, err)
		}
		if ok, _ := store.Unsuspend(ctx, suspended); ok {
			t.Fatal("lifting twice must change nothing")
		}
		sus, _, _ := store.Suspension(ctx, suspended)
		if sus.Status != tenantdom.OrganizationActive || sus.Reason != "" || sus.By != nil || sus.At != nil {
			t.Fatalf("after lift = %+v", sus)
		}
		ids, _ := NewTenantRepository(db).ListActiveTenantIDs(ctx)
		if !slices.Contains(ids, suspended) {
			t.Fatal("a lifted organization must be scheduled again")
		}
	})

	t.Run("account block: set once, a stale save keeps it, unblock lifts it", func(t *testing.T) {
		uid := newUser()
		users := NewUserRepository(db)
		dir := NewPlatformUserDirectory(db)
		// Loaded before the block, saved after it (a sign-in stamp).
		stale, err := users.GetByID(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := dir.SetBlocked(ctx, uid, true, &adminID, "spam campaign"); err != nil || !ok {
			t.Fatalf("block: %v %v", ok, err)
		}
		if ok, _ := dir.SetBlocked(ctx, uid, true, &adminID, "again"); ok {
			t.Fatal("blocking twice must change nothing")
		}
		if err := users.Update(ctx, stale); err != nil {
			t.Fatalf("stale update: %v", err)
		}
		u, _ := users.GetByID(ctx, uid)
		if u.Status() != userdom.StatusSuspended || u.IsActive() {
			t.Fatalf("a stale save lifted the block: status=%s", u.Status())
		}
		d, err := dir.Get(ctx, uid)
		if err != nil || d.BlockedAt == nil || d.BlockedReason != "spam campaign" || d.Status != "suspended" {
			t.Fatalf("directory = %+v %v", d, err)
		}
		if ok, err := dir.SetBlocked(ctx, uid, false, nil, "resolved"); err != nil || !ok {
			t.Fatalf("unblock: %v %v", ok, err)
		}
		u, _ = users.GetByID(ctx, uid)
		d, _ = dir.Get(ctx, uid)
		if !u.IsActive() || d.BlockedAt != nil || d.BlockedReason != "" {
			t.Fatalf("after unblock: active=%v %+v", u.IsActive(), d.PlatformUserSummary)
		}
	})
}
