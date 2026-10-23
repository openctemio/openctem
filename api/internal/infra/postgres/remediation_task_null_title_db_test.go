package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// findings.title is nullable. The task-from-query preview, the primary-holder
// and claim-conflict reads and the member list must not fail on such a finding,
// and must show a title that never quotes the finding's message (a secret
// finding's message can hold the secret). Skipped unless DATABASE_URL is set.
func TestRemediationTask_NullFindingTitle_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	tenantID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'rt-nt', $2)`,
		tenantID.String(), "rtnt-"+tenantID.String()[28:]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	asset := seedAsset(ctx, t, db, tenantID)
	const secret = "AKIA-SECRET-IN-MESSAGE"
	fNull := seedFinding(ctx, t, db, tenantID, asset, "external", "high", "new")
	fEmpty := seedFinding(ctx, t, db, tenantID, asset, "external", "high", "new")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET title = NULL, message = $2, rule_name = NULL, rule_id = 'rule.x' WHERE id = $1`,
		fNull.String(), secret); err != nil {
		t.Fatalf("null title: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET title = '', message = $2, rule_name = 'Rule X name' WHERE id = $1`,
		fEmpty.String(), secret); err != nil {
		t.Fatalf("empty title: %v", err)
	}

	repo := NewRemediationTaskRepository(&DB{DB: db})
	taskID := shared.NewID()
	if err := repo.CreateTask(ctx, &remediation.NewTaskRecord{
		Task: remediation.Task{ID: taskID, TenantID: tenantID, Title: "t"},
		Action: remediation.Action{TenantID: tenantID, Key: remediation.ManualActionKey(taskID), Kind: remediation.ActionKindManual,
			Title: "t", Origin: remediation.ActionOriginManual},
		Members: []shared.ID{fNull, fEmpty}, Source: remediation.JoinSourceManual,
	}); err != nil {
		t.Fatalf("create task: %v", err)
	}

	ids := []shared.ID{fNull, fEmpty}
	stats, err := repo.QueryPreviewStats(ctx, tenantID, ids, 10)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	want := map[shared.ID]string{fNull: "rule.x", fEmpty: "Rule X name"}
	if len(stats.Sample) != 2 {
		t.Fatalf("sample rows = %d, want 2", len(stats.Sample))
	}
	for _, s := range stats.Sample {
		if s.Title != want[s.FindingID] {
			t.Errorf("sample title = %q, want %q", s.Title, want[s.FindingID])
		}
		if strings.Contains(s.Title, secret) {
			t.Errorf("sample title quotes the message")
		}
	}

	holders, err := repo.PrimaryHolders(ctx, tenantID, ids)
	if err != nil || len(holders) != 2 {
		t.Fatalf("primary holders: %v (%d)", err, len(holders))
	}
	taken, err := activePrimaryRowsInTx(ctx, db, tenantID, ids, nil)
	if err != nil || len(taken) != 2 {
		t.Fatalf("active primary rows: %v (%d)", err, len(taken))
	}
	members, err := repo.ListMembers(ctx, tenantID, taskID, remediation.MemberFilter{}, pagination.New(1, 50))
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	for _, m := range members.Data {
		if m.Title != want[m.FindingID] || strings.Contains(m.Title, secret) {
			t.Errorf("member title = %q, want %q", m.Title, want[m.FindingID])
		}
	}
}
