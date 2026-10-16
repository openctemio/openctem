package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A branch-only secret becomes an organization finding, and its rotation task
// is a system action found again by key (one task per secret identity).
func TestCISecretExposure_PromoteAndRotationTask_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	ci := NewCIRunRepository(&DB{DB: db})
	tasks := NewRemediationTaskRepository(&DB{DB: db})

	seed := func(tn, as shared.ID) shared.ID {
		id := seedOpenFinding(ctx, t, db, tn, openFindingSeed{asset: as, source: "secret", tool: "betterleaks", rule: "aws-access-token"})
		if _, err := db.ExecContext(ctx, `UPDATE findings SET finding_type = 'secret', branch_only = TRUE WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mine, foreign := seed(tenant, asset), seed(other, otherAsset)
	branchOnly := func(id shared.ID) bool {
		var v bool
		if err := db.QueryRowContext(ctx, `SELECT branch_only FROM findings WHERE id = $1`, id.String()).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Another tenant's id passed with this tenant's scope changes nothing.
	got, err := ci.PromoteSecretFindings(ctx, tenant, asset, []shared.ID{foreign})
	if err != nil || len(got) != 0 || !branchOnly(foreign) {
		t.Fatalf("cross-tenant promote: %v %v branch_only=%v", got, err, branchOnly(foreign))
	}
	got, err = ci.PromoteSecretFindings(ctx, tenant, asset, []shared.ID{mine})
	if err != nil || len(got) != 1 || branchOnly(mine) {
		t.Fatalf("promote: %v %v branch_only=%v", got, err, branchOnly(mine))
	}

	// The system rotation task is stored and found by its action key.
	key := "rotate:secret:0123456789abcdef0123456789abcdef"
	if tk, err := tasks.ActiveTaskByActionKey(ctx, tenant, key); err != nil || tk != nil {
		t.Fatalf("before: %v %v", tk, err)
	}
	taskID := shared.NewID()
	rec := &remediation.NewTaskRecord{
		Task:    remediation.Task{ID: taskID, TenantID: tenant, Title: "Rotate aws_access_key"},
		Action:  remediation.Action{TenantID: tenant, Key: key, Kind: remediation.KindRotate, Title: "Rotate aws_access_key", FixSpec: remediation.FixSpecForKey(key), Origin: remediation.ActionOriginSystem},
		Members: []shared.ID{mine}, Source: remediation.JoinSourceAutoJoin,
	}
	if err := tasks.CreateTask(ctx, rec); err != nil {
		t.Fatalf("create system task: %v", err)
	}
	tk, err := tasks.ActiveTaskByActionKey(ctx, tenant, key)
	if err != nil || tk == nil || tk.ID != taskID || tk.Title != "Rotate aws_access_key" {
		t.Fatalf("find by key: %+v %v", tk, err)
	}
	if tk, _ := tasks.ActiveTaskByActionKey(ctx, other, key); tk != nil {
		t.Fatal("another tenant found the task")
	}
}
