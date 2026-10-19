package integration

// Migration remediation_campaigns_drop_finding_filter: the contract step runs
// the conversion once more (a campaign created after the first conversion
// gets its task, a converted one is not reported again), retires the paused
// and validating statuses (audited), drops the conversion functions and the
// columns that held findings, and refuses a retired status from then on.

import (
	"math"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationRemediationCampaignsDropFindingFilter(t *testing.T) {
	const dir = "../../migrations"
	conv := testdb.MigrationVersion(t, dir, "remediation_campaigns_hold_tasks")
	v := testdb.MigrationVersion(t, dir, "remediation_campaigns_drop_finding_filter")
	db := testdb.PrivateDatabase(t, "migcampdrop", dir)
	testdb.Migrate(t, db, dir, conv, math.MaxInt, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111112"
		asset  = "f1111111-1111-4111-8111-111111111112"
		early  = "c0000000-0000-4000-8000-0000000000e1"
		late   = "c0000000-0000-4000-8000-0000000000e2"
		cEarly = "a0000000-0000-4000-8000-0000000000e1" // converted by the first migration, paused
		cLate  = "a0000000-0000-4000-8000-0000000000e2" // created after it, validating
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 't', 'mig-camp-drop')`, tenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'a', 'host')`, asset, tenant)
	for _, f := range []string{early, late} {
		exec(`INSERT INTO findings (id, tenant_id, asset_id, tool_name, message, severity, fingerprint, source, status)
			VALUES ($1::uuid, $2, $3, 'trivy', 'm', 'high', 'fp-'||$1::text, 'sca', 'new')`, f, tenant, asset)
	}
	exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter) VALUES ($1, $2, 'Early', 'paused', $3::jsonb)`,
		cEarly, tenant, `{"finding_ids":["`+early+`"]}`)

	testdb.Migrate(t, db, dir, conv, conv, false)
	exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter) VALUES ($1, $2, 'Late', 'validating', $3::jsonb)`,
		cLate, tenant, `{"finding_ids":["`+late+`"]}`)
	audits := count(`SELECT count(*) FROM audit_logs WHERE action = 'remediation_campaign.migrated' AND resource_id = $1`, cEarly)

	up := func() { testdb.Migrate(t, db, dir, v, v, false) }
	down := func() { testdb.Migrate(t, db, dir, v, v, true) }

	up()
	if n := count(`SELECT count(*) FROM remediation_task_members m JOIN remediation_tasks t ON t.id = m.task_id
		WHERE t.campaign_id = $1 AND m.finding_id = $2 AND m.left_at IS NULL`, cLate, late); n != 1 {
		t.Errorf("the late campaign's finding is in %d of its tasks, want 1", n)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'remediation_campaign.migrated' AND resource_id = $1`, cEarly); n != audits {
		t.Errorf("the converted campaign was reported again (%d audit rows, had %d)", n, audits)
	}
	if n := count(`SELECT count(*) FROM remediation_campaigns WHERE status <> 'active' AND id IN ($1, $2)`, cEarly, cLate); n != 0 {
		t.Errorf("%d campaigns kept a retired status", n)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'remediation_campaign.status_changed' AND metadata->>'trigger' = 'status_retired'`); n != 2 {
		t.Errorf("status retirement audit rows = %d, want 2", n)
	}
	if n := count(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'remediation_campaigns'
		AND column_name IN ('finding_filter', 'finding_count', 'resolved_count', 'progress', 'risk_score_before', 'risk_score_after', 'risk_reduction')`); n != 0 {
		t.Errorf("%d legacy columns left", n)
	}
	if n := count(`SELECT count(*) FROM pg_proc WHERE proname IN ('remediation_campaigns_to_tasks', 'remediation_campaign_filter_parse')`); n != 0 {
		t.Errorf("%d conversion functions left", n)
	}
	if _, err := db.Exec(`UPDATE remediation_campaigns SET status = 'paused' WHERE id = $1`, cEarly); err == nil {
		t.Error("a retired status was accepted")
	}

	down()
	if n := count(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'remediation_campaigns' AND column_name = 'finding_filter'`); n != 1 {
		t.Error("down did not bring finding_filter back")
	}
	if n := count(`SELECT count(*) FROM remediation_tasks WHERE campaign_id = $1`, cLate); n != 1 {
		t.Errorf("down removed the late campaign's task (%d)", n)
	}
	up()
}
