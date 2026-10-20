package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A status change of a finding linked to a ticket must leave a durable record
// of the outbound status push, whatever happens to Redis. Before, the push
// was only an asynq task: Redis down at that moment (or restarted before the
// worker ran) and the ticket never learned the new status.
func TestTicketStatusSync_StatusChangeLeavesADurableJob(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "ticket-sync")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'ts-host', 'host')`, asset.String(), tenant.String())
	newFinding := func(linked bool) shared.ID {
		id := shared.NewID()
		uris := "{}"
		if linked {
			uris = "{https://acme.atlassian.net/browse/SEC-1}"
		}
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, work_item_uris)
			VALUES ($1, $2, $3, 'sast', 'ts-tool', 'm', 'medium', $4, 'new', $5)`, id.String(), tenant.String(), asset.String(), "ts-"+id.String(), uris)
		return id
	}
	jobs := func(id shared.ID) int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM durable_jobs WHERE tenant_id = $1 AND subject_id = $2 AND status = 'pending'
			AND kind IN ('jira_status_sync', 'github_status_sync')`, tenant.String(), id.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(&postgres.DB{DB: db}), logger.NewNop())
	svc.EnableTicketStatusSync()

	linked, unlinked := newFinding(true), newFinding(false)
	for _, id := range []shared.ID{linked, unlinked} {
		if _, err := svc.UpdateFindingStatus(ctx, id.String(), tenant.String(), finding.UpdateFindingStatusInput{Status: "confirmed"}); err != nil {
			t.Fatalf("status change: %v", err)
		}
	}
	if n := jobs(linked); n != 2 {
		t.Fatalf("durable status-sync jobs for the linked finding = %d, want 2 (jira, github)", n)
	}
	if n := jobs(unlinked); n != 0 {
		t.Fatalf("durable status-sync jobs for an unlinked finding = %d, want 0", n)
	}

	// The bulk route queues the same way.
	bulk := newFinding(true)
	if _, err := svc.BulkUpdateFindingsStatus(ctx, tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{bulk.String()}, Status: "confirmed", HasStatusPermission: true}); err != nil {
		t.Fatal(err)
	}
	if n := jobs(bulk); n != 2 {
		t.Fatalf("bulk: durable status-sync jobs = %d, want 2", n)
	}
}
