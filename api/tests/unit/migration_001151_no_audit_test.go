package unit

import (
	"os"
	"strings"
	"testing"
)

// Migration 001151 backfills asset types. It must not write audit_logs from
// SQL: the tamper-evident chain (audit_log_chain) is extended only by the
// app's AuditService, and an unchained tenant-scoped audit row reads as a
// chain break to the verifier.
func TestMigration001151WritesNoAuditRows(t *testing.T) {
	for _, f := range []string{
		"../../migrations/001151_retype_assets_by_name.up.sql",
		"../../migrations/001151_retype_assets_by_name.down.sql",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				code = append(code, l)
			}
		}
		if strings.Contains(strings.ToLower(strings.Join(code, "\n")), "audit_log") {
			t.Errorf("%s writes to the audit tables; use the app's AuditService instead", f)
		}
	}
}
