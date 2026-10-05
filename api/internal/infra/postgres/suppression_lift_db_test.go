package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A suppression is an exception, not a fix: when the rule stops applying
// (deleted or expired) the findings it hid must come back. They used to stay
// suppressed forever.

func seedSuppressionRule(ctx context.Context, t *testing.T, db *sql.DB, tenant, requester shared.ID, ruleID string, expires *time.Time) shared.ID {
	t.Helper()
	id := shared.NewID()
	var exp any
	if expires != nil {
		exp = *expires
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO suppression_rules (id, tenant_id, rule_id, name, suppression_type, status, requested_by, approved_by, approved_at, expires_at)
		VALUES ($1, $2, $3, $4, 'false_positive', 'approved', $5, $5, NOW(), $6)`,
		id.String(), tenant.String(), ruleID, "rule "+ruleID, requester.String(), exp); err != nil {
		t.Fatalf("seed suppression rule: %v", err)
	}
	return id
}

func seedSuppressedFinding(ctx context.Context, t *testing.T, db *sql.DB, tenant, asset, rule shared.ID, toolRule string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status, resolution, resolved_at)
		VALUES ($1, $2, $3, 'sast', 'semgrep', $4, 'msg', 'high', $5, 'false_positive', 'suppressed', NOW())`,
		id.String(), tenant.String(), asset.String(), toolRule, "fp-"+id.String()); err != nil {
		t.Fatalf("seed suppressed finding: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO finding_suppressions (finding_id, suppression_rule_id) VALUES ($1, $2)`,
		id.String(), rule.String()); err != nil {
		t.Fatalf("link suppression: %v", err)
	}
	return id
}

func findingState(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (status, resolution string) {
	t.Helper()
	var res sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT status, resolution FROM findings WHERE id = $1`, id.String()).Scan(&status, &res); err != nil {
		t.Fatal(err)
	}
	return status, res.String
}

func TestSuppressionDelete_LiftsItsFindings_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	user := seedGroupsUser(ctx, t, db, "supp.test")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule := seedSuppressionRule(ctx, t, db, tenant, user, "semgrep.sqli", nil)
	lifted := seedSuppressedFinding(ctx, t, db, tenant, asset, rule, "semgrep.sqli")
	// A finding someone triaged since (no longer the suppression's disposition)
	// is left alone.
	touched := seedSuppressedFinding(ctx, t, db, tenant, asset, rule, "semgrep.sqli")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET status = 'confirmed', resolution = NULL WHERE id = $1`, touched.String()); err != nil {
		t.Fatal(err)
	}
	// Another active rule covers this one: it stays suppressed, re-linked.
	cover := seedSuppressionRule(ctx, t, db, tenant, user, "semgrep.xss", nil)
	covered := seedSuppressedFinding(ctx, t, db, tenant, asset, rule, "semgrep.xss")

	// Another tenant's suppressed finding with a same-named rule is untouched.
	other := seedTestTenant(ctx, t, db)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	otherRule := seedSuppressionRule(ctx, t, db, other, user, "semgrep.sqli", nil)
	otherFinding := seedSuppressedFinding(ctx, t, db, other, otherAsset, otherRule, "semgrep.sqli")

	if err := repo.Delete(ctx, tenant, rule); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if st, res := findingState(ctx, t, db, lifted); st != "new" || res != "" {
		t.Fatalf("lifted finding = %s/%q, want new with no resolution", st, res)
	}
	var activities int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'reopened'`,
		lifted.String()).Scan(&activities); err != nil {
		t.Fatal(err)
	}
	if activities != 1 {
		t.Fatalf("reopened activities = %d, want 1", activities)
	}
	if st, _ := findingState(ctx, t, db, touched); st != "confirmed" {
		t.Fatalf("triaged finding = %s, want confirmed (left alone)", st)
	}
	if st, res := findingState(ctx, t, db, covered); st != "false_positive" || res != "suppressed" {
		t.Fatalf("covered finding = %s/%q, want still suppressed", st, res)
	}
	var linked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_suppressions WHERE finding_id = $1 AND suppression_rule_id = $2`,
		covered.String(), cover.String()).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 1 {
		t.Fatal("covered finding not re-linked to the rule that still applies")
	}
	if st, _ := findingState(ctx, t, db, otherFinding); st != "false_positive" {
		t.Fatalf("other tenant's finding = %s, want untouched", st)
	}
}

func TestSuppressionExpire_LiftsItsFindings_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	user := seedGroupsUser(ctx, t, db, "supp.exp")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	past := time.Now().Add(-time.Hour)
	rule := seedSuppressionRule(ctx, t, db, tenant, user, "semgrep.expiring", &past)
	f := seedSuppressedFinding(ctx, t, db, tenant, asset, rule, "semgrep.expiring")

	if _, err := repo.ExpireRules(ctx); err != nil {
		t.Fatalf("expire: %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM suppression_rules WHERE id = $1`, rule.String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Fatalf("rule status = %s, want expired", status)
	}
	if st, res := findingState(ctx, t, db, f); st != "new" || res != "" {
		t.Fatalf("finding of expired rule = %s/%q, want reopened", st, res)
	}
}

func TestSuppressionApprovers_CountAndOwner_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	owner := seedGroupsUser(ctx, t, db, "own.test")
	member := seedGroupsUser(ctx, t, db, "mem.test")
	for _, m := range []struct {
		user shared.ID
		role string
	}{{owner, "owner"}, {member, "member"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			m.user.String(), tenant.String(), m.role); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}

	n, err := repo.CountEligibleApprovers(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("eligible approvers = %d, want 1 (the owner; a plain member cannot approve)", n)
	}
	if ok, err := repo.IsTenantOwner(ctx, tenant, owner); err != nil || !ok {
		t.Fatalf("IsTenantOwner(owner) = %v, %v", ok, err)
	}
	if ok, err := repo.IsTenantOwner(ctx, tenant, member); err != nil || ok {
		t.Fatalf("IsTenantOwner(member) = %v, %v", ok, err)
	}
	other := seedTestTenant(ctx, t, db)
	if ok, err := repo.IsTenantOwner(ctx, other, owner); err != nil || ok {
		t.Fatalf("owner of tenant A is not owner of tenant B: %v, %v", ok, err)
	}

	// An admin is a second eligible approver.
	admin := seedGroupsUser(ctx, t, db, "adm.test")
	if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`,
		admin.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.CountEligibleApprovers(ctx, tenant); n != 2 {
		t.Fatalf("eligible approvers with an admin = %d, want 2", n)
	}
}

// Migration 000942 switches off stored priority rules that cannot be valid and
// records them; valid rules stay on. Replayed as the schema owner in a
// rolled-back transaction.
func TestPriorityRuleSafetyMigration_DisablesInvalidRules_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	up, err := os.ReadFile("../../../migrations/000942_priority_rules_disable_invalid.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000942_priority_rules_disable_invalid.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	// 000942 creates and drops priority_rule_safety_report, whose FK takes a lock
	// on tenants: lock tenants first, as LockForDDL asks, or a parallel test that
	// writes tenants closes a deadlock with this one.
	testdb.LockForDDL(t, ctx, tx, "tenants", "priority_override_rules", "priority_rule_safety_report")
	exec(string(down))

	ids := map[string]string{}
	add := func(key, conditions string) {
		id := shared.NewID().String()
		ids[key] = id
		exec(`INSERT INTO priority_override_rules (id, tenant_id, name, priority_class, conditions, is_active)
			VALUES ($1, $2, $3, 'P3', $4::jsonb, TRUE)`, id, tenant.String(), key, conditions)
	}
	add("empty", `[]`)
	add("unknown-field", `[{"field":"nope","operator":"eq","value":true}]`)
	add("null-value", `[{"field":"is_in_kev","operator":"eq","value":null}]`)
	add("valid", `[{"field":"is_in_kev","operator":"eq","value":true}]`)

	exec(string(up))

	active := func(key string) bool {
		var a bool
		if err := tx.QueryRowContext(ctx, `SELECT is_active FROM priority_override_rules WHERE id = $1`, ids[key]).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	for _, k := range []string{"empty", "unknown-field", "null-value"} {
		if active(k) {
			t.Errorf("rule %q still active; want switched off", k)
		}
		var reason string
		if err := tx.QueryRowContext(ctx, `SELECT reason FROM priority_rule_safety_report WHERE rule_id = $1`, ids[k]).Scan(&reason); err != nil {
			t.Errorf("rule %q not in the report: %v", k, err)
		}
	}
	if !active("valid") {
		t.Error("a valid rule was switched off")
	}

	// Down puts the switched-off rules back.
	exec(string(down))
	if !active("empty") {
		t.Error("down did not re-enable the rule the migration switched off")
	}
}
