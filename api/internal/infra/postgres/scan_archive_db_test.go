package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// One-off (ad-hoc) scans that never ran are archived, not deleted, and never
// listed again; migration 001154 marks the quick scans created before ad-hoc
// scans existed as ad hoc.

func seedOneOff(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, name string, adHoc bool, age time.Duration) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, description, scan_type, scanner_name, ad_hoc, created_at)
		 VALUES ($1, $2, $3, 'Quick scan of 1 targets', 'single', 'nuclei', $4, $5)`,
		id.String(), tenantID.String(), name, adHoc, time.Now().Add(-age)); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, id.String()) })
	return id
}

func archivedAt(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (bool, string) {
	t.Helper()
	var at sql.NullTime
	var status string
	if err := db.QueryRowContext(ctx, `SELECT archived_at, status FROM scans WHERE id = $1`, id.String()).Scan(&at, &status); err != nil {
		t.Fatalf("read scan: %v", err)
	}
	return at.Valid, status
}

func TestArchiveNeverRunOneOffs(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	runs := NewScanRunRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)
	old := 40 * 24 * time.Hour

	stale := seedOneOff(ctx, t, db, tenantID, "stale one-off", true, old)
	ran := seedOneOff(ctx, t, db, tenantID, "one-off that ran", true, old)
	seedCounterRun(ctx, t, runs, tenantID, ran)
	recent := seedOneOff(ctx, t, db, tenantID, "recent one-off", true, time.Hour)
	saved := seedOneOff(ctx, t, db, tenantID, "saved configuration", false, old)

	got, err := repo.ArchiveNeverRunOneOffs(ctx, 30*24*time.Hour, 1000)
	if err != nil {
		t.Fatalf("ArchiveNeverRunOneOffs: %v", err)
	}
	var mine []scan.ArchivedScan
	for _, a := range got {
		if a.TenantID == tenantID {
			mine = append(mine, a)
		}
	}
	if len(mine) != 1 || mine[0].ID != stale || mine[0].Name != "stale one-off" {
		t.Fatalf("archived %+v, want only the stale one-off", mine)
	}
	if ok, status := archivedAt(ctx, t, db, stale); !ok || status != "disabled" {
		t.Fatalf("stale: archived=%v status=%s, want archived and disabled", ok, status)
	}
	for name, id := range map[string]shared.ID{"ran": ran, "recent": recent, "saved": saved} {
		if ok, _ := archivedAt(ctx, t, db, id); ok {
			t.Errorf("%s scan was archived", name)
		}
	}

	// Kept, not deleted; never listed, not even with one-off scans shown.
	if _, err := repo.GetByTenantAndID(ctx, tenantID, stale); err != nil {
		t.Fatalf("archived scan is gone: %v", err)
	}
	list, err := repo.List(ctx, scan.Filter{TenantID: &tenantID}, pagination.New(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list.Data {
		if s.ID == stale {
			t.Fatal("an archived scan is listed")
		}
	}
	if list.Total != 3 {
		t.Errorf("listed %d scans (with one-offs), want 3", list.Total)
	}

	// A second pass archives nothing more.
	again, err := repo.ArchiveNeverRunOneOffs(ctx, 30*24*time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range again {
		if a.TenantID == tenantID {
			t.Fatalf("second pass archived %s again", a.Name)
		}
	}
}

// The migration's legacy match: scans the quick-scan generator named, and
// nothing a person named.
func TestMigration001154_MarksLegacyQuickScansAdHoc(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenantID := seedScanTriggerTenant(ctx, t, db)
	legacy := seedOneOff(ctx, t, db, tenantID, "Quick Scan - 20260720-101112", false, 80*24*time.Hour)
	suffixed := seedOneOff(ctx, t, db, tenantID, "Quick Scan - 20260720-101113-0a1b2c3d4e5f", false, 80*24*time.Hour)
	mine := seedOneOff(ctx, t, db, tenantID, "Quick Scan of the VPN", false, 80*24*time.Hour)

	raw, err := os.ReadFile("../../../migrations/001154_scans_archived_one_off.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmt := string(raw)[strings.Index(string(raw), "UPDATE scans"):]
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("migration update: %v", err)
	}
	read := func(id shared.ID) bool {
		var adHoc bool
		if err := tx.QueryRowContext(ctx, `SELECT ad_hoc FROM scans WHERE id = $1`, id.String()).Scan(&adHoc); err != nil {
			t.Fatal(err)
		}
		return adHoc
	}
	if !read(legacy) || !read(suffixed) {
		t.Error("a generated quick scan was not marked ad hoc")
	}
	if read(mine) {
		t.Error("a scan a person named was marked ad hoc")
	}
}
