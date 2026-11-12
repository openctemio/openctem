package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An organization that had switched AI triage off on Settings > Modules still
// has triage off after the upgrade (the choice moves to its AI settings), an
// organization that had not is untouched, and the down migration gives the
// switch back to exactly the organizations that were carried over.
func TestRetireNoopModulesKeepsAITriageOff_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "retire_noop_modules", dir)
	ctx := context.Background()
	v := testdb.MigrationVersion(t, dir, "retire_noop_modules")
	testdb.Migrate(t, db, dir, v, v, true)

	offNoRow, offWithRow, on := shared.NewID(), shared.NewID(), shared.NewID()
	for i, id := range []shared.ID{offNoRow, offWithRow, on} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug, created_by) VALUES ($1, $2, $3, NULL)`,
			id.String(), "t", "retire-noop-"+strings.Repeat("x", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []shared.ID{offNoRow, offWithRow} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_modules (tenant_id, module_id, is_enabled) VALUES ($1, 'ai_triage', false)`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	// This organization already tuned triage: its other values must survive.
	if _, err := db.ExecContext(ctx, `INSERT INTO tenant_ai_settings (tenant_id, use_cases) VALUES ($1,
		'{"triage": {"mode": "auto_apply", "ceiling": "restricted", "min_confidence": 0.93}}')`, offWithRow.String()); err != nil {
		t.Fatal(err)
	}

	testdb.Migrate(t, db, dir, v, v, false)
	repo := NewTenantAISettingsRepository(&DB{DB: db})

	for name, id := range map[string]shared.ID{"no settings row": offNoRow, "existing settings": offWithRow} {
		p, err := repo.GetUseCases(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.For(aidom.UseCaseTriage).Mode; got != aidom.UseCaseOff {
			t.Fatalf("%s: triage is %q after the upgrade, want off (the organization had switched it off)", name, got)
		}
	}
	p, _ := repo.GetUseCases(ctx, offWithRow)
	if s := p.For(aidom.UseCaseTriage); s.Ceiling != aidom.DataClassRestricted || s.MinConfidence != 0.93 {
		t.Fatalf("the organization's other triage settings were lost: %+v", s)
	}
	if p, _ := repo.GetUseCases(ctx, on); p.For(aidom.UseCaseTriage).Mode == aidom.UseCaseOff {
		t.Fatal("an organization that never switched triage off must not get it switched off")
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_modules WHERE module_id = 'ai_triage'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("the module switch should be gone: %d %v", left, err)
	}

	// Down: the switch comes back for the two carried-over organizations, and
	// the marker is removed from their settings.
	testdb.Migrate(t, db, dir, v, v, true)
	var back, marked int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_modules WHERE module_id = 'ai_triage' AND NOT is_enabled`).Scan(&back)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_ai_settings WHERE use_cases -> 'triage' ? 'from_module_switch'`).Scan(&marked)
	if back != 2 || marked != 0 {
		t.Fatalf("down: %d switches restored (want 2), %d markers left (want 0)", back, marked)
	}
}

// An organization that had switched Suppressions off must not see its rules
// start muting findings again after suppressions became always on: the up
// migration deactivates them, the down migration brings back exactly those, and
// an organization that had the module on is untouched.
func TestRetireNoopModulesKeepsSuppressionsOff_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "retire_noop_suppr", dir)
	ctx := context.Background()
	v := testdb.MigrationVersion(t, dir, "retire_noop_modules")
	testdb.Migrate(t, db, dir, v, v, true)

	off, on := shared.NewID(), shared.NewID()
	for i, id := range []shared.ID{off, on} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug, created_by) VALUES ($1, 't', $2, NULL)`,
			id.String(), "retire-suppr-"+strings.Repeat("x", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tenant_modules (tenant_id, module_id, is_enabled) VALUES ($1, 'suppressions', false)`, off.String()); err != nil {
		t.Fatal(err)
	}
	rule := func(tenant shared.ID, name, status string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO suppression_rules (tenant_id, name, rule_id, suppression_type, status, expires_at)
			VALUES ($1, $2, 'sql-injection', 'false_positive', $3, NOW() + interval '30 days')`, tenant.String(), name, status); err != nil {
			t.Fatal(err)
		}
	}
	rule(off, "off-approved", "approved")
	rule(off, "off-pending", "pending")
	rule(on, "on-approved", "approved")

	repo := NewSuppressionRepository(&DB{DB: db})
	active := func(tenant shared.ID) int {
		t.Helper()
		rules, err := repo.FindActiveByTenant(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return len(rules)
	}
	if active(off) != 1 {
		t.Fatalf("before the upgrade the rule mutes (the module row is off but nothing read it here): %d", active(off))
	}

	testdb.Migrate(t, db, dir, v, v, false)
	if got := active(off); got != 0 {
		t.Fatalf("after the upgrade %d rule(s) of the organization that switched suppressions off mute findings; want 0", got)
	}
	if got := active(on); got != 1 {
		t.Fatalf("an organization that never switched suppressions off lost its rule: %d active", got)
	}
	var pending string
	if err := db.QueryRowContext(ctx, `SELECT status FROM suppression_rules WHERE name = 'off-pending'`).Scan(&pending); err != nil || pending != "pending" {
		t.Fatalf("a pending rule must not change: %q %v", pending, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if got := active(off); got != 1 {
		t.Fatalf("down: the rule must be active again as before: %d", got)
	}
	var sw int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_modules WHERE module_id = 'suppressions' AND NOT is_enabled AND tenant_id = $1`, off.String()).Scan(&sw); err != nil || sw != 1 {
		t.Fatalf("down: the switch must be restored: %d %v", sw, err)
	}
	var col int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'suppression_rules' AND column_name = 'deactivated_by_migration'`).Scan(&col)
	if col != 0 {
		t.Fatal("down must drop the marker column")
	}
}
