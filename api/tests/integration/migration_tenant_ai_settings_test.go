package integration

// The tenant_ai_settings migration moves tenants.settings.ai into the table:
// platform/disabled/byok map to platform/off/own, an unusable own provider or
// an unencrypted key turns the source off (never a fall back to the platform
// key), the encrypted key keeps its ciphertext, only explicit auto-triage
// keys are kept, settings.ai is removed, and the down step restores it. Run in
// a transaction that is rolled back. Found by name, so the merge queue may
// renumber it.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigrationTenantAISettings(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	read := func(suffix string) string {
		t.Helper()
		files, err := filepath.Glob("../../migrations/*_tenant_ai_settings." + suffix + ".sql")
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

	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	// Back to the schema before the migration, with legacy JSON tenants.
	exec(down)
	cases := map[string]string{
		"none":      `{}`,
		"platform":  `{"ai": {"mode": "platform", "enabled_at": "2026-05-01T00:00:00Z", "enabled_by": "upgrade", "auto_triage_enabled": false}}`,
		"disabled":  `{"ai": {"mode": "disabled"}}`,
		"byok":      `{"ai": {"mode": "byok", "provider": "openai", "model_override": "gpt-4o", "api_key": "enc:v1:Q0lQSEVS", "auto_triage_severities": ["critical"]}}`,
		"plaintext": `{"ai": {"mode": "byok", "provider": "openai", "api_key": "sk-plain-0123456789"}}`,
		"azure":     `{"ai": {"mode": "byok", "provider": "azure_openai", "api_key": "enc:v1:Q0lQSEVS", "azure_endpoint": "https://x.openai.azure.com"}}`,
		"agent":     `{"ai": {"mode": "agent"}}`,
		"nullai":    `{"ai": null}`,
	}
	ids := map[string]string{}
	for name, settings := range cases {
		id := shared.NewID().String()
		ids[name] = id
		exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, $2, $2, $3::jsonb)`, id, "tai-"+name+"-"+id[:8], settings)
	}

	var idList []string
	for _, id := range ids {
		idList = append(idList, id)
	}
	exec(up)
	type row struct {
		source, provider, model, key, by, policy string
		hasEnabled                               bool
	}
	_ = row{}
	get := func(name string) (row, bool) {
		var r row
		var key, model sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT source, provider, model, key_enc, enabled_by, policy::text, enabled_at IS NOT NULL
			FROM tenant_ai_settings WHERE tenant_id = $1`, ids[name]).Scan(&r.source, &r.provider, &model, &key, &r.by, &r.policy, &r.hasEnabled)
		if err == sql.ErrNoRows {
			return r, false
		}
		if err != nil {
			t.Fatal(err)
		}
		r.key, r.model = key.String, model.String
		return r, true
	}
	if _, ok := get("none"); ok {
		t.Error("an organization without settings.ai must not get a row")
	}
	if _, ok := get("nullai"); ok {
		t.Error("a null settings.ai must not get a row")
	}
	if r, _ := get("platform"); r.source != "platform" || !r.hasEnabled || r.by != "upgrade" || r.policy != `{"auto_triage_enabled": false}` {
		t.Errorf("platform: %+v", r)
	}
	if r, _ := get("disabled"); r.source != "off" {
		t.Errorf("disabled: %+v", r)
	}
	if r, _ := get("byok"); r.source != "own" || r.provider != "openai" || r.model != "gpt-4o" || r.key != "Q0lQSEVS" ||
		r.policy != `{"auto_triage_severities": ["critical"]}` {
		t.Errorf("byok: %+v", r)
	}
	if r, _ := get("plaintext"); r.source != "off" || r.key != "" {
		t.Errorf("an unencrypted key must be dropped and the source turned off: %+v", r)
	}
	if r, _ := get("azure"); r.source != "off" || r.provider != "" || r.key != "" {
		t.Errorf("azure_openai must be turned off without a key: %+v", r)
	}
	if r, _ := get("agent"); r.source != "off" {
		t.Errorf("agent must be turned off: %+v", r)
	}
	var left int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM tenants WHERE settings ? 'ai' AND id = ANY($1)`, pq.Array(idList)).Scan(&left); err != nil || left != 0 {
		t.Errorf("settings.ai must be gone: %d %v", left, err)
	}

	// Down puts the JSON back; up again moves it again.
	exec(down)
	var mode, key sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT settings->'ai'->>'mode', settings->'ai'->>'api_key' FROM tenants WHERE id = $1`, ids["byok"]).Scan(&mode, &key); err != nil ||
		mode.String != "byok" || key.String != "enc:v1:Q0lQSEVS" {
		t.Errorf("down: mode=%q key=%q %v", mode.String, key.String, err)
	}
	exec(up)
	if r, ok := get("byok"); !ok || r.source != "own" {
		t.Errorf("up after down: %+v %v", r, ok)
	}
}
