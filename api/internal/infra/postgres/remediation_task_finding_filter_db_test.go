package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The task list's finding_id filter under a data scope: a caller who knows
// the id of a finding on an asset outside their scope must not learn which of
// their visible tasks hold it. Skipped unless DATABASE_URL is set.
func TestRemediationTaskList_FindingIDFilterAppliesScope_DB(t *testing.T) {
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

	tenantID, otherTenant := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenantID, otherTenant} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'rt-ff', $2)`,
			id.String(), "rtff-"+id.String()[28:]); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		id := id
		defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) }()
	}
	userID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'rtff')`,
		userID.String(), userID.String()+"@rtff.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID.String()) }()

	assetIn, assetOut := seedAsset(ctx, t, db, tenantID), seedAsset(ctx, t, db, tenantID)
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
		VALUES ($1, $2, $3, 'secondary')`, userID.String(), tenantID.String(), assetIn.String()); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	fIn := seedFinding(ctx, t, db, tenantID, assetIn, "external", "high", "new")
	fOut := seedFinding(ctx, t, db, tenantID, assetOut, "external", "high", "new")
	fIn2 := seedFinding(ctx, t, db, tenantID, assetIn, "external", "high", "new")

	repo := NewRemediationTaskRepository(&DB{DB: db})
	mk := func(title string, members ...shared.ID) shared.ID {
		t.Helper()
		id := shared.NewID()
		rec := &remediation.NewTaskRecord{
			Task: remediation.Task{ID: id, TenantID: tenantID, Title: title},
			Action: remediation.Action{TenantID: tenantID, Key: remediation.ManualActionKey(id), Kind: remediation.ActionKindManual,
				Title: title, Origin: remediation.ActionOriginManual},
			Members: members, Source: remediation.JoinSourceManual,
		}
		if err := repo.CreateTask(ctx, rec); err != nil {
			t.Fatalf("create task: %v", err)
		}
		return id
	}
	// "mixed" is visible to the caller (fIn2 is in scope) and also holds the
	// finding they cannot see.
	visible := mk("visible", fIn)
	mixed := mk("mixed", fIn2, fOut)

	list := func(scope *shared.DataScope, finding shared.ID) []shared.ID {
		t.Helper()
		res, err := repo.ListTasks(ctx, tenantID, remediation.TaskFilter{FindingID: &finding, Scope: scope},
			pagination.New(1, 50))
		if err != nil {
			t.Fatalf("list tasks: %v", err)
		}
		out := make([]shared.ID, 0, len(res.Data))
		for _, tk := range res.Data {
			out = append(out, tk.ID)
		}
		return out
	}
	scope := &shared.DataScope{TenantID: tenantID, UserID: userID}

	if got := list(nil, fOut); len(got) != 1 || got[0] != mixed {
		t.Fatalf("unscoped reader: want [%s], got %v", mixed, got)
	}
	if got := list(scope, fIn); len(got) != 1 || got[0] != visible {
		t.Fatalf("scoped reader, in-scope finding: want [%s], got %v", visible, got)
	}
	if got := list(scope, fOut); len(got) != 0 {
		t.Fatalf("scoped reader, out-of-scope finding: want no task, got %v (oracle on a finding they cannot see)", got)
	}
}
