package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration 000682 (research 18 F7): resolved/suppressed findings take the
// disposition of the rule recorded for them, only when that rule is certain,
// without being counted as regressions. Replayed in a rolled-back transaction.
func TestSuppressedDispositionMigration(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	up, err := os.ReadFile("../../../migrations/000682_suppressed_findings_disposition.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		asset.String(), tenant.String(), "h-"+asset.String()); err != nil {
		t.Fatal(err)
	}

	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "tenants", "assets", "findings", "suppression_rules", "finding_suppressions")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	rule := func(tid shared.ID, typ string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO suppression_rules (id, tenant_id, rule_id, name, suppression_type, status, requested_by, requested_at)
			VALUES ($1, $2, 'r', 'n', $3, 'approved', NULL, NOW())`, id.String(), tid.String(), typ)
		return id
	}
	finding := func(status, resolution string, rules ...shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolution, resolved_at)
			VALUES ($1::uuid, $2, $3, 'sast', 'semgrep', 'm', 'high', $1::text, $4, NULLIF($5, ''), NOW())`,
			id.String(), tenant.String(), asset.String(), status, resolution)
		for _, r := range rules {
			exec(`INSERT INTO finding_suppressions (finding_id, suppression_rule_id) VALUES ($1, $2)`, id.String(), r.String())
		}
		return id
	}
	fpRule, arRule, wfRule := rule(tenant, "false_positive"), rule(tenant, "accepted_risk"), rule(tenant, "wont_fix")
	foreign := rule(other, "false_positive")

	cases := []struct {
		name string
		id   shared.ID
		want string
	}{
		{"false-positive rule", finding("resolved", "suppressed", fpRule), "false_positive"},
		{"accepted-risk rule", finding("resolved", "suppressed", arRule), "accepted"},
		{"won't-fix rule", finding("resolved", "suppressed", wfRule), "accepted"},
		{"no recorded rule", finding("resolved", "suppressed"), "resolved"},
		{"rules disagree", finding("resolved", "suppressed", fpRule, arRule), "resolved"},
		{"another tenant's rule", finding("resolved", "suppressed", foreign), "resolved"},
		{"a real fix", finding("resolved", "auto_fixed", fpRule), "resolved"},
		{"open finding", finding("confirmed", "suppressed", fpRule), "confirmed"},
	}
	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("re-apply migration: %v", err)
	}
	for _, tc := range cases {
		var status string
		var regression bool
		if err := tx.QueryRowContext(ctx, `SELECT status, COALESCE(is_regression, false) FROM findings WHERE id = $1`, tc.id.String()).
			Scan(&status, &regression); err != nil {
			t.Fatal(err)
		}
		if status != tc.want || regression {
			t.Errorf("%s: status %s regression %v, want %s and no regression", tc.name, status, regression, tc.want)
		}
	}
}
