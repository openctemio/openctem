package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TestPriorityAuditRepository_LogChangesBatch checks that the batched write
// stores each entry exactly as LogChange would (own tenant, nullable previous
// class, rule and actor), in one statement.
func TestPriorityAuditRepository_LogChangesBatch(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantA, tenantB := shared.NewID(), shared.NewID()
	p2 := vulnerability.PriorityClass("P2")
	rule, actor := shared.NewID(), shared.NewID()
	entries := []finding.PriorityAuditEntry{
		{TenantID: tenantA, FindingID: shared.NewID(), NewClass: "P1", Reason: "first", Source: "auto"},
		{TenantID: tenantA, FindingID: shared.NewID(), PreviousClass: &p2, NewClass: "P0", Reason: "rule hit", Source: "rule", RuleID: &rule},
		{TenantID: tenantB, FindingID: shared.NewID(), NewClass: "P3", Reason: "manual", Source: "manual", ActorID: &actor},
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM priority_class_audit_log WHERE tenant_id = ANY($1::uuid[])`,
			"{"+tenantA.String()+","+tenantB.String()+"}")
	})

	repo := NewPriorityAuditRepository(&DB{DB: db})
	if err := repo.LogChanges(ctx, entries); err != nil {
		t.Fatalf("LogChanges: %v", err)
	}
	if err := repo.LogChanges(ctx, nil); err != nil {
		t.Fatalf("LogChanges(nil): %v", err)
	}

	for _, e := range entries {
		var tenant, next, reason, source string
		var prev, ruleID, actorID sql.NullString
		err := db.QueryRowContext(ctx, `
			SELECT tenant_id, previous_class, new_class, reason, source, rule_id, actor_id
			FROM priority_class_audit_log WHERE finding_id = $1`, e.FindingID.String()).
			Scan(&tenant, &prev, &next, &reason, &source, &ruleID, &actorID)
		if err != nil {
			t.Fatalf("read back %s: %v", e.FindingID, err)
		}
		if tenant != e.TenantID.String() {
			t.Errorf("tenant = %s, want %s (each row keeps its own tenant)", tenant, e.TenantID)
		}
		if next != string(e.NewClass) || reason != e.Reason || source != e.Source {
			t.Errorf("row = %s/%s/%s, want %s/%s/%s", next, reason, source, e.NewClass, e.Reason, e.Source)
		}
		if (e.PreviousClass != nil) != prev.Valid || (prev.Valid && prev.String != string(*e.PreviousClass)) {
			t.Errorf("previous_class = %+v, want %v", prev, e.PreviousClass)
		}
		if (e.RuleID != nil) != ruleID.Valid || (e.ActorID != nil) != actorID.Valid {
			t.Errorf("rule/actor = %+v/%+v, want %v/%v", ruleID, actorID, e.RuleID, e.ActorID)
		}
	}
}
