package postgres

import (
	"context"
	"testing"
	"time"
)

// Refused exchanges come from the tenant's own audit log only, newest
// first, with their rule codes; other actions and tenants never appear.
func TestCIRecentTokenRefusals(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC()
	insert := func(tid, action, repoName, meta string, at time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO audit_logs (tenant_id, action, resource_type, resource_name, result, message, metadata, logged_at)
			VALUES ($1, $2, 'ci_run', $3, 'denied', 'refused', $4::jsonb, $5)`, tid, action, repoName, meta, at); err != nil {
			t.Fatal(err)
		}
	}
	insert(tenant.String(), "ci_run.token_refused", "github.com/acme/old", `{"reasons":["owner_not_allowed"],"provider":"github"}`, now.Add(-time.Hour))
	insert(tenant.String(), "ci_run.token_refused", "github.com/acme/api", `{"reasons":["fork_refused","ref_not_allowed"],"provider":"github","ref":"refs/pull/7/merge","event":"pull_request"}`, now)
	insert(tenant.String(), "ci_run.token_issued", "github.com/acme/api", `{}`, now)
	insert(other.String(), "ci_run.token_refused", "github.com/evil/x", `{"reasons":["replay"]}`, now)

	got, err := repo.RecentTokenRefusals(ctx, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Repository != "github.com/acme/api" || got[1].Repository != "github.com/acme/old" {
		t.Fatalf("refusals: %+v", got)
	}
	if len(got[0].Reasons) != 2 || got[0].Reasons[0] != "fork_refused" || got[0].Event != "pull_request" || got[0].Ref != "refs/pull/7/merge" {
		t.Fatalf("newest: %+v", got[0])
	}
	if got, _ := repo.RecentTokenRefusals(ctx, tenant, 1); len(got) != 1 {
		t.Fatalf("limit: %d", len(got))
	}
	if got, _ := repo.RecentTokenRefusals(ctx, other, 10); len(got) != 1 || got[0].Repository != "github.com/evil/x" {
		t.Fatalf("other tenant: %+v", got)
	}
}
