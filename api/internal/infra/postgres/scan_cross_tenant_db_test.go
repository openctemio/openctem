package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// D-11 (research/14 SEC-15): the scan-area repositories delete and update a
// row only inside the caller's tenant. Each test seeds a row for a victim
// tenant and acts on it with another tenant's id: the call must report not
// found and leave the row as it was.

func requireNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("%s with another tenant's id: err = %v, want shared.ErrNotFound", what, err)
	}
}

func rowExists(ctx context.Context, t *testing.T, db *sql.DB, table string, id shared.ID) bool {
	t.Helper()
	var n int
	// table is a test constant, never input.
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE id = $1`, id.String()).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n == 1
}

func TestScanDelete_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, 'victim scan', 'single', 'nuclei')`,
		scanID.String(), victim.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, scanID.String())
	})

	requireNotFound(t, "ScanRepository.Delete", repo.Delete(ctx, attacker, scanID))
	if !rowExists(ctx, t, db, "scans", scanID) {
		t.Fatal("another tenant deleted the scan")
	}

	// The scheduler and run bookkeeping writes are tenant-bound too.
	if err := repo.RecordRunStarted(ctx, attacker, scanID, shared.NewID()); err != nil {
		t.Fatalf("RecordRunStarted: %v", err)
	}
	if err := repo.RecordTriggerFailure(ctx, attacker, scanID, "failed"); err != nil {
		t.Fatalf("RecordTriggerFailure: %v", err)
	}
	var status sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT last_run_status FROM scans WHERE id = $1`, scanID.String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status.Valid {
		t.Fatalf("another tenant wrote last_run_status = %q", status.String)
	}

	if err := repo.Delete(ctx, victim, scanID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if rowExists(ctx, t, db, "scans", scanID) {
		t.Fatal("owner delete left the scan")
	}
}

func TestScanProfileUpdateDelete_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanProfileRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_profiles (id, tenant_id, name, description) VALUES ($1, $2, 'victim profile', '')`,
		id.String(), victim.String()); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_profiles WHERE id = $1`, id.String())
	})

	p, err := repo.GetByTenantAndID(ctx, victim, id)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if _, err := repo.GetByTenantAndID(ctx, attacker, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetByTenantAndID across tenants: %v", err)
	}

	p.TenantID = attacker
	p.Name = "renamed by another tenant"
	requireNotFound(t, "ScanProfileRepository.Update", repo.Update(ctx, p))
	var name string
	if err := db.QueryRowContext(ctx, `SELECT name FROM scan_profiles WHERE id = $1`, id.String()).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "victim profile" {
		t.Fatalf("another tenant renamed the profile to %q", name)
	}

	requireNotFound(t, "ScanProfileRepository.Delete", repo.Delete(ctx, attacker, id))
	if !rowExists(ctx, t, db, "scan_profiles", id) {
		t.Fatal("another tenant deleted the profile")
	}
}

func TestScanSessionUpdateDelete_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanSessionRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_sessions (id, tenant_id, scanner_name, asset_type, asset_value, error_message)
		 VALUES ($1, $2, 'semgrep', 'repository', 'github.com/victim/app', 'original')`,
		id.String(), victim.String()); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_sessions WHERE id = $1`, id.String())
	})

	s, err := repo.GetByTenantAndID(ctx, victim, id)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	s.TenantID = attacker
	s.ErrorMessage = "overwritten by another tenant"
	if err := repo.Update(ctx, s); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("ScanSessionRepository.Update across tenants: err = %v, want not found", err)
	}
	var msg sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT error_message FROM scan_sessions WHERE id = $1`, id.String()).Scan(&msg); err != nil {
		t.Fatal(err)
	}
	if msg.String != "original" {
		t.Fatalf("another tenant overwrote the session: %q", msg.String)
	}

	if err := repo.Delete(ctx, attacker, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("ScanSessionRepository.Delete across tenants: err = %v, want not found", err)
	}
	if !rowExists(ctx, t, db, "scan_sessions", id) {
		t.Fatal("another tenant deleted the session")
	}
}

func TestCommandDelete_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewCommandRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO commands (id, tenant_id, type) VALUES ($1, $2, 'scan')`,
		id.String(), victim.String()); err != nil {
		t.Fatalf("seed command: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String()) })

	requireNotFound(t, "CommandRepository.Delete", repo.Delete(ctx, attacker, id))
	if !rowExists(ctx, t, db, "commands", id) {
		t.Fatal("another tenant deleted the command")
	}
}

func TestToolExecutionUpdate_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewToolExecutionRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	var toolID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM tools WHERE tenant_id IS NULL LIMIT 1`).Scan(&toolID); err != nil {
		t.Fatalf("pick a platform tool: %v", err)
	}
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tool_executions (id, tenant_id, tool_id, error_message) VALUES ($1, $2, $3, 'original')`,
		id.String(), victim.String(), toolID); err != nil {
		t.Fatalf("seed tool execution: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tool_executions WHERE id = $1`, id.String())
	})

	if _, err := repo.GetByIDInTenant(ctx, attacker, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetByIDInTenant across tenants: err = %v, want not found", err)
	}
	e, err := repo.GetByIDInTenant(ctx, victim, id)
	if err != nil {
		t.Fatalf("load tool execution: %v", err)
	}
	e.TenantID = attacker
	e.ErrorMessage = "overwritten by another tenant"
	requireNotFound(t, "ToolExecutionRepository.Update", repo.Update(ctx, e))
	var msg sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT error_message FROM tool_executions WHERE id = $1`, id.String()).Scan(&msg); err != nil {
		t.Fatal(err)
	}
	if msg.String != "original" {
		t.Fatalf("another tenant overwrote the tool execution: %q", msg.String)
	}
}
