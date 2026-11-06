package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Waits for scope approval are tenant-scoped: a wait is created only for the
// tenant's own scan, listed and claimed only within the tenant, claimed
// once, and an expired wait is neither listed nor counted.
func TestScanScopeWaits_TenantScoped_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewScanScopeWaitRepository(&DB{DB: db})

	newScan := func(tid shared.ID) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets) VALUES ($1, $2, $3, 'single', 'nuclei', ARRAY['app.acme.vn'])`,
			id.String(), tid.String(), "wait "+id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	now := time.Now().UTC()
	mine, theirs := newScan(tenant), newScan(other)
	wait := func(tid, sid shared.ID, expires time.Time) scan.ScopeWait {
		return scan.ScopeWait{ScanID: sid, TenantID: tid, CreatedAt: now.Add(-time.Hour), ExpiresAt: expires}
	}

	if err := repo.Create(ctx, wait(tenant, mine, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	// Another tenant's scan cannot be made to wait under this tenant.
	if err := repo.Create(ctx, wait(tenant, theirs, now.Add(time.Hour))); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant create: %v, want not found", err)
	}
	if err := repo.Create(ctx, wait(other, theirs, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	got, err := repo.ListByTenant(ctx, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ScanID != mine || got[0].TenantID != tenant {
		t.Fatalf("list = %+v, want only this tenant's wait", got)
	}
	if ok, _ := repo.Exists(ctx, other, mine); ok {
		t.Fatal("another tenant sees this wait")
	}
	if ok, _ := repo.Claim(ctx, other, mine); ok {
		t.Fatal("another tenant claimed this wait")
	}
	if ok, err := repo.Claim(ctx, tenant, mine); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if ok, _ := repo.Claim(ctx, tenant, mine); ok {
		t.Fatal("a wait was claimed twice")
	}
	if ok, _ := repo.Exists(ctx, other, theirs); !ok {
		t.Fatal("the other tenant lost its wait")
	}

	// Expired waits are not listed or counted, and are removed on list.
	late := newScan(tenant)
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_scope_waits (scan_id, tenant_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		late.String(), tenant.String(), now.Add(-2*time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.Exists(ctx, tenant, late); ok {
		t.Fatal("an expired wait counts")
	}
	if got, _ := repo.ListByTenant(ctx, tenant, 10); len(got) != 0 {
		t.Fatalf("expired wait listed: %+v", got)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM scan_scope_waits WHERE scan_id = $1`, late.String()).Scan(&n)
	if n != 0 {
		t.Fatal("expired wait not removed")
	}

	// Deleting the scan removes its wait.
	if err := repo.Create(ctx, wait(tenant, mine, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM scans WHERE id = $1`, mine.String()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.Exists(ctx, tenant, mine); ok {
		t.Fatal("wait outlived its scan")
	}
}
