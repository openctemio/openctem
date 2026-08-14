package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
)

// SuppressionRepository.SaveWithAudit persists the rule state change and its
// audit row in one transaction. Previously Save and RecordAudit were separate
// autocommitted Execs (audit best-effort), so the audit trail could diverge
// from rule state. These tests prove both rows commit together, and that a
// failure recording the audit rolls the rule save back too (no orphan state).

func openSuppressionDB(t *testing.T) *DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping suppression atomicity tests")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &DB{DB: sqlDB}
}

func newSuppressionRule(t *testing.T, tenantID, requestedBy shared.ID) *suppression.Rule {
	t.Helper()
	rule, err := suppression.NewRule(tenantID, "atomic-test-"+shared.NewID().String(),
		suppression.SuppressionTypeFalsePositive, requestedBy)
	if err != nil {
		t.Fatalf("new rule: %v", err)
	}
	// The table requires at least one of rule_id / path_pattern / asset_id.
	rule.SetRuleIDPattern("CVE-2021-0000")
	return rule
}

func countAudits(ctx context.Context, t *testing.T, db *DB, ruleID shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM suppression_rule_audit WHERE suppression_rule_id = $1`,
		ruleID.String()).Scan(&n); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	return n
}

func countRules(ctx context.Context, t *testing.T, db *DB, ruleID shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM suppression_rules WHERE id = $1`, ruleID.String()).Scan(&n); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	return n
}

func TestSuppressionRepository_SaveWithAudit_Atomic(t *testing.T) {
	ctx := context.Background()
	db := openSuppressionDB(t)
	repo := NewSuppressionRepository(db)
	tenantID := seedTenant(ctx, t, db)
	actorID := seedUser(ctx, t, db)

	t.Run("commits rule and audit together", func(t *testing.T) {
		rule := newSuppressionRule(t, tenantID, actorID)
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM suppression_rules WHERE id = $1`, rule.ID().String())
		})

		if err := repo.SaveWithAudit(ctx, rule, "created", &actorID, map[string]any{"k": "v"}); err != nil {
			t.Fatalf("SaveWithAudit: %v", err)
		}
		if countRules(ctx, t, db, rule.ID()) != 1 {
			t.Fatal("rule should be persisted")
		}
		if countAudits(ctx, t, db, rule.ID()) != 1 {
			t.Fatal("audit row should be persisted")
		}
	})

	t.Run("rolls the rule back when the audit write fails", func(t *testing.T) {
		rule := newSuppressionRule(t, tenantID, actorID)
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM suppression_rules WHERE id = $1`, rule.ID().String())
		})

		// A non-existent actor violates suppression_rule_audit.actor_id → users FK,
		// which must abort the whole transaction — including the rule save.
		ghostActor := shared.NewID()
		err := repo.SaveWithAudit(ctx, rule, "created", &ghostActor, nil)
		if err == nil {
			t.Fatal("expected SaveWithAudit to fail on the audit FK violation")
		}
		if countRules(ctx, t, db, rule.ID()) != 0 {
			t.Fatal("rule save must be rolled back when the audit write fails")
		}
		if countAudits(ctx, t, db, rule.ID()) != 0 {
			t.Fatal("no audit row should survive a rolled-back transaction")
		}
	})
}
