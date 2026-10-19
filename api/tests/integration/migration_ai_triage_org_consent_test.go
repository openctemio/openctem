package integration

// The AI triage consent migration keeps AI triage on for organizations that
// already used it (with an audit row), leaves every other organization off,
// never overrides an administrator's choice, and its down step removes only
// what the upgrade recorded. Found by name, so the merge queue may renumber it.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigrationAITriageOrgConsent(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	read := func(suffix string) string {
		t.Helper()
		files, err := filepath.Glob("../../migrations/*_ai_triage_org_consent." + suffix + ".sql")
		if err != nil || len(files) != 1 {
			t.Fatalf("migration file: %v %v", files, err)
		}
		b, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up, down := read("up"), read("down")

	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	// used: has a triage result. unused: none. off: used, but its mode is
	// disabled. chosen: used, and an administrator already turned it on.
	tenants := map[string]string{}
	for _, name := range []string{"used", "unused", "off", "chosen", "nullai"} {
		id := shared.NewID().String()
		tenants[name] = id
		settings := `{}`
		switch name {
		case "off":
			settings = `{"ai": {"mode": "disabled"}}`
		case "nullai":
			// A JSON null section must become an object, not [null, {...}].
			settings = `{"ai": null}`
		case "chosen":
			settings = `{"ai": {"mode": "platform", "enabled_at": "2026-05-01T00:00:00Z", "enabled_by": "11111111-1111-7111-8111-111111111111"}}`
		}
		exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, $2, $2, $3::jsonb)`, id, "aic-"+name+"-"+id[:8], settings)
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, id)
			_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
		})
		if name == "unused" {
			continue
		}
		asset := shared.NewID().String()
		finding := shared.NewID().String()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`, asset, id, "aic-"+id[:8]+".example.com")
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', 'm', 'high', $1::text, 'new')`, finding, id, asset)
		exec(`INSERT INTO ai_triage_results (tenant_id, finding_id, triage_type, status) VALUES ($1, $2, 'manual', 'completed')`, id, finding)
	}

	state := func(name string) (by string, audits int) {
		t.Helper()
		var v sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT settings->'ai'->>'enabled_by' FROM tenants WHERE id = $1`, tenants[name]).Scan(&v); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_settings.opt_in_migrated'`, tenants[name]).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		return v.String, audits
	}

	exec(up)
	exec(up) // idempotent
	want := map[string][2]any{
		"used":   {"upgrade", 1},
		"unused": {"", 0},
		"off":    {"", 0},
		"chosen": {"11111111-1111-7111-8111-111111111111", 0},
		"nullai": {"upgrade", 1},
	}
	for name, w := range want {
		by, audits := state(name)
		if by != w[0] || audits != w[1] {
			t.Errorf("%s after up: enabled_by=%q audits=%d, want %q %d", name, by, audits, w[0], w[1])
		}
	}
	var kind string
	if err := db.QueryRowContext(ctx, `SELECT jsonb_typeof(settings->'ai') FROM tenants WHERE id = $1`, tenants["nullai"]).Scan(&kind); err != nil || kind != "object" {
		t.Errorf("null ai section after up: %q (%v), want an object", kind, err)
	}
	var at sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT settings->'ai'->>'enabled_at' FROM tenants WHERE id = $1`, tenants["used"]).Scan(&at); err != nil || len(at.String) != len("2026-10-19T00:00:00Z") {
		t.Errorf("enabled_at = %q (%v), want an RFC 3339 UTC timestamp", at.String, err)
	}

	exec(down)
	for name, w := range map[string]string{"used": "", "chosen": "11111111-1111-7111-8111-111111111111"} {
		if by, _ := state(name); by != w {
			t.Errorf("%s after down: enabled_by=%q, want %q", name, by, w)
		}
	}
	if _, audits := state("used"); audits != 1 {
		t.Errorf("down must keep the audit row, got %d", audits)
	}
	exec(up)
	if by, _ := state("used"); by != "upgrade" {
		t.Errorf("up after down: enabled_by=%q, want upgrade", by)
	}
}
