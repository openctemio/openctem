package routes

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/ingest"
)

// A Nessus CIS FAILED (scanner severity High) on a normal server is a medium
// compliance finding; on a crown jewel it is high; a level 2 failure is low
// (docs/architecture/compliance-checks.md, "Priority").
func TestCompliancePriority_NessusImport_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.92"
	t1 := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	sev := func(control string) string {
		t.Helper()
		var s string
		if err := ih.db.QueryRowContext(context.Background(), `SELECT severity FROM findings
			WHERE tenant_id = $1 AND finding_type = 'compliance' AND compliance_control_id = $2`, ih.tenantID, control).Scan(&s); err != nil {
			t.Fatalf("finding %s: %v", control, err)
		}
		return s
	}
	ih.nsUpload(t, "", true, ccFile(ip, t1, ccItem{"3.1", "FAILED"}))
	if s := sev("3.1"); s != "medium" {
		t.Fatalf("level 1 failure on a normal server = %s, want medium", s)
	}
	if _, err := ih.db.ExecContext(context.Background(), `UPDATE assets SET is_crown_jewel = true WHERE tenant_id = $1 AND name = $2`, ih.tenantID, ip); err != nil {
		t.Fatal(err)
	}
	ih.nsUpload(t, "", true, ccFile(ip, t1.Add(time.Hour), ccItem{"3.2", "FAILED"}))
	if s := sev("3.2"); s != "high" {
		t.Fatalf("level 1 failure on a crown jewel = %s, want high", s)
	}
	// Another tenant's crown jewel never raises this tenant's finding: the
	// facts are read pinned to the tenant (the repository test covers it);
	// here the same address in another tenant stays medium.
	other := newImportHarness(t, ingest.SourceResolveDryRun)
	other.nsUpload(t, "", true, ccFile(ip, t1, ccItem{"3.3", "FAILED"}))
	var s string
	if err := other.db.QueryRowContext(context.Background(), `SELECT severity FROM findings WHERE tenant_id = $1 AND compliance_control_id = '3.3'`, other.tenantID).Scan(&s); err != nil || s != "medium" {
		t.Fatalf("other tenant's failure = %s, %v; want medium", s, err)
	}
}
