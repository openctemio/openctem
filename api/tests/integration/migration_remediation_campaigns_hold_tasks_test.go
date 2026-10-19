package integration

// Migration remediation_campaigns_hold_tasks: what each running legacy
// campaign tracks through its finding_filter becomes tasks of the campaign.
// A finding claimed by two campaigns goes to the one furthest along (then the
// oldest), a finding already in a task never moves (a task without a campaign
// joins it, a task of another campaign keeps it and the claim is recorded),
// every campaign gets an audit row, owners and admins one notice, and the
// unique primary-membership index holds throughout. The function is
// idempotent, and the down migration removes what the up migration created.
//
// Runs on a private database: everything up to the migration before, seed,
// up, re-run, down, up.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationRemediationCampaignsHoldTasks(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "remediation_campaigns_hold_tasks")
	db := testdb.PrivateDatabase(t, "migcamp", dir)
	testdb.Migrate(t, db, dir, v, v, true)

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
	str := func(q string, args ...any) string {
		t.Helper()
		var s *string
		if err := db.QueryRow(q, args...).Scan(&s); errors.Is(err, sql.ErrNoRows) {
			return ""
		} else if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if s == nil {
			return ""
		}
		return *s
	}

	const (
		tenantA = "a1111111-1111-4111-8111-111111111111"
		tenantB = "b2222222-2222-4222-8222-222222222222"
		owner   = "d1111111-1111-4111-8111-111111111111" // owner of A
		dev     = "d2222222-2222-4222-8222-222222222222" // active member of A
		gone    = "d3333333-3333-4333-8333-333333333333" // offboarded from A
		ownerB  = "d4444444-4444-4444-8444-444444444444"
		group   = "e1111111-1111-4111-8111-111111111111"
		assetA  = "f1111111-1111-4111-8111-111111111111"
		assetB  = "f2222222-2222-4222-8222-222222222222"

		f1 = "c0000000-0000-4000-8000-000000000001" // CVE-1 new: C1 and C2 claim it, C2 (active) wins
		f2 = "c0000000-0000-4000-8000-000000000002" // CVE-1 closed: never moves
		f3 = "c0000000-0000-4000-8000-000000000003" // CVE-2 in progress: C1
		f4 = "c0000000-0000-4000-8000-000000000004" // C2 by id
		f5 = "c0000000-0000-4000-8000-000000000005" // fix key, fix applied: C7 (C6 is completed)
		f6 = "c0000000-0000-4000-8000-000000000006" // in task T0 (no campaign): T0 joins C2
		f7 = "c0000000-0000-4000-8000-000000000007" // in task T1 of campaign C4: stays, C5 conflict
		f8 = "c0000000-0000-4000-8000-000000000008" // CVE-1 pentest draft: never moves
		f9 = "c0000000-0000-4000-8000-000000000009" // CVE-1, appears after the first run

		c1 = "a0000000-0000-4000-8000-000000000001" // draft, oldest, CVEs, assignee offboarded
		c2 = "a0000000-0000-4000-8000-000000000002" // active, finding ids, owner and team
		c3 = "a0000000-0000-4000-8000-000000000003" // active, severity only: tracks nothing
		c4 = "a0000000-0000-4000-8000-000000000004" // completed, owns T1
		c5 = "a0000000-0000-4000-8000-000000000005" // draft, names f7
		c6 = "a0000000-0000-4000-8000-000000000006" // completed, names f5: not converted
		c7 = "a0000000-0000-4000-8000-000000000007" // active, fix key
		c8 = "a0000000-0000-4000-8000-000000000008" // active, filter that does not parse
		cB = "a0000000-0000-4000-8000-0000000000b1" // tenant B, names A's f4

		t0 = "90000000-0000-4000-8000-000000000000"
		t1 = "90000000-0000-4000-8000-000000000001"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-camp-a'), ($2, 'b', 'mig-camp-b')`, tenantA, tenantB)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'owner@migcamp.test', 'Owner'), ($2, 'dev@migcamp.test', 'Dev'),
		($3, 'gone@migcamp.test', 'Gone'), ($4, 'ownerb@migcamp.test', 'Owner B')`, owner, dev, gone, ownerB)
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $5, 'owner', 'active'),
		($2, $5, 'member', 'active'), ($3, $5, 'member', 'offboarded'), ($4, $6, 'owner', 'active')`, owner, dev, gone, ownerB, tenantA, tenantB)
	exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'Platform team', 'mig-camp-team')`, group, tenantA)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'a', 'host'), ($3, $4, 'b', 'host')`, assetA, tenantA, assetB, tenantB)
	finding := func(id, status, source, cve string) {
		t.Helper()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, tool_name, message, title, severity, fingerprint, source, status, cve_id)
			VALUES ($1::uuid, $2, $3, 'trivy', 'm', 'Finding '||$1::text, 'high', 'fp-'||$1::text, $4, $5, NULLIF($6, ''))`,
			id, tenantA, assetA, source, status, cve)
	}
	finding(f1, "new", "sca", "CVE-2024-0001")
	finding(f2, "resolved", "sca", "CVE-2024-0001")
	finding(f3, "in_progress", "sca", "CVE-2024-0002")
	finding(f4, "new", "sast", "")
	finding(f5, "fix_applied", "sca", "")
	finding(f6, "new", "sast", "")
	finding(f7, "confirmed", "sast", "")
	finding(f8, "draft", "pentest", "CVE-2024-0001")
	exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key) VALUES ($1, $2, 'upgrade:npm:lodash:4.17.21')`, f5, tenantA)

	campaign := func(id, tenant, name, status, filter, created string, assignee, team any) {
		t.Helper()
		exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter, created_at, assigned_to, assigned_team, created_by, due_date)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6::timestamptz, $7, $8, $9, DATE '2030-01-31')`,
			id, tenant, name, status, filter, created, assignee, team, owner)
	}
	campaign(c1, tenantA, "Patch CVE wave", "draft", `{"cve_ids":["CVE-2024-0001","CVE-2024-0002"]}`, "2026-01-01", gone, nil)
	campaign(c2, tenantA, "Fix picked findings", "active", `{"finding_ids":["`+f1+`","`+f4+`","`+f6+`"]}`, "2026-02-01", dev, group)
	campaign(c3, tenantA, "Patch critical", "active", `{"severities":["critical"]}`, "2026-03-01", nil, nil)
	campaign(c4, tenantA, "Old program", "completed", `{}`, "2025-01-01", nil, nil)
	campaign(c5, tenantA, "Late claim", "draft", `{"finding_id":"`+f7+`"}`, "2026-04-01", nil, nil)
	campaign(c6, tenantA, "Done long ago", "completed", `{"finding_ids":["`+f5+`"]}`, "2025-02-01", nil, nil)
	campaign(c7, tenantA, "Upgrade lodash", "active", `{"remediation_key":"upgrade:npm:lodash:4.17.21"}`, "2026-05-01", nil, nil)
	campaign(c8, tenantA, "Broken filter", "active", `{"bogus":1}`, "2026-06-01", nil, nil)
	campaign(cB, tenantB, "Other organization", "active", `{"finding_ids":["`+f4+`"]}`, "2026-01-01", nil, nil)

	// Two existing tasks: T0 without a campaign holds f6, T1 of C4 holds f7.
	for _, row := range [][3]string{{t0, f6, ""}, {t1, f7, c4}} {
		exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin)
			VALUES ($1::uuid, $2, 'manual:'||$1::text, 'manual', 'existing', 'manual')`, row[0], tenantA)
		exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, member_count, open_count)
			VALUES ($1, $2, $1, NULLIF($3, '')::uuid, 'existing', 1, 1)`, row[0], tenantA, row[2])
		exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
			VALUES ($1, $2, $3, 'primary', 'manual')`, tenantA, row[0], row[1])
	}

	up := func() { testdb.Migrate(t, db, dir, v, v, false) }
	down := func() { testdb.Migrate(t, db, dir, v, v, true) }

	taskOf := func(campaignID string) string {
		t.Helper()
		return str(`SELECT t.id::text FROM remediation_tasks t
			WHERE t.campaign_id = $1 AND EXISTS (SELECT 1 FROM remediation_task_events e
			      WHERE e.task_id = t.id AND e.kind = 'created' AND e.data->>'origin' = 'campaign_migration')`, campaignID)
	}
	members := func(taskID string) string {
		t.Helper()
		return str(`SELECT string_agg(finding_id::text, ',' ORDER BY finding_id) FROM remediation_task_members
			WHERE task_id = $1 AND left_at IS NULL AND role = 'primary'`, taskID)
	}
	audit := func(campaignID string) map[string]any {
		t.Helper()
		raw := str(`SELECT metadata::text FROM audit_logs WHERE action = 'remediation_campaign.migrated' AND resource_id = $1
			ORDER BY logged_at DESC LIMIT 1`, campaignID)
		if raw == "" {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	check := func(round int) {
		t.Helper()
		// C2 (active) won f1 from C1 (draft, older) and took f4; T0 joined it.
		tc2 := taskOf(c2)
		if got := members(tc2); got != f1+","+f4 {
			t.Errorf("round %d: C2 task members = %s", round, got)
		}
		var title, state, src string
		var user, grp *string
		var n int
		if err := db.QueryRow(`SELECT title, state, assignee_user_id::text, assignee_group_id::text, member_count, COALESCE(deadline_source, '')
			FROM remediation_tasks WHERE id = $1`, tc2).Scan(&title, &state, &user, &grp, &n, &src); err != nil {
			t.Fatal(err)
		}
		if title != "Fix picked findings" || state != "open" || user == nil || *user != dev || grp == nil || *grp != group || n != 2 || src != "campaign" {
			t.Errorf("round %d: C2 task = %q %s user=%v group=%v members=%d source=%s", round, title, state, user, grp, n, src)
		}
		if got := str(`SELECT campaign_id::text FROM remediation_tasks WHERE id = $1`, t0); got != c2 {
			t.Errorf("round %d: T0 campaign = %q, want C2", round, got)
		}
		// C1 kept f3 only (f1 went to C2, f2 is closed, f8 is a pentest draft); its assignee left.
		tc1 := taskOf(c1)
		if got := members(tc1); got != f3 {
			t.Errorf("round %d: C1 task members = %s", round, got)
		}
		if got := str(`SELECT state FROM remediation_tasks WHERE id = $1`, tc1); got != "in_progress" {
			t.Errorf("round %d: C1 task state = %s", round, got)
		}
		if got := str(`SELECT assignee_user_id::text FROM remediation_tasks WHERE id = $1`, tc1); got != "" {
			t.Errorf("round %d: C1 task assignee = %s, want none (offboarded)", round, got)
		}
		// The fix key campaign took f5; the completed campaign that names it took nothing.
		if got := members(taskOf(c7)); got != f5 {
			t.Errorf("round %d: C7 task members = %s", round, got)
		}
		if got := str(`SELECT state FROM remediation_tasks WHERE id = $1`, taskOf(c7)); got != "verifying" {
			t.Errorf("round %d: C7 task state = %s", round, got)
		}
		// T1 stays in C4.
		if got := str(`SELECT campaign_id::text FROM remediation_tasks WHERE id = $1`, t1); got != c4 {
			t.Errorf("round %d: T1 campaign = %q, want C4", round, got)
		}
		for _, c := range []string{c3, c4, c5, c6, c8, cB} {
			if taskOf(c) != "" {
				t.Errorf("round %d: campaign %s got a task", round, c)
			}
		}
		// Isolation: tenant B's campaign never reaches tenant A's finding.
		if n := count(`SELECT count(*) FROM remediation_tasks WHERE tenant_id = $1`, tenantB); n != 0 {
			t.Errorf("round %d: tasks in tenant B = %d", round, n)
		}
		// The invariant: at most one active primary membership per finding.
		if n := count(`SELECT count(*) FROM (SELECT finding_id FROM remediation_task_members
			WHERE left_at IS NULL AND role = 'primary' GROUP BY finding_id HAVING count(*) > 1) d`); n != 0 {
			t.Errorf("round %d: %d findings in two tasks", round, n)
		}
		if n := count(`SELECT count(*) FROM finding_activities WHERE activity_type = 'remediation_task_changed'
			AND changes->>'origin' = 'campaign_migration'`); n != 4 {
			t.Errorf("round %d: finding timeline entries = %d, want 4", round, n)
		}
		// Timeline: T0 joined, T1 kept a claim.
		if n := count(`SELECT count(*) FROM remediation_task_events WHERE task_id = $1 AND kind = 'updated' AND data->>'campaign_id' = $2`, t0, c2); n != 1 {
			t.Errorf("round %d: T0 join events = %d", round, n)
		}
		if n := count(`SELECT count(*) FROM remediation_task_events WHERE task_id = $1 AND kind = 'campaign_conflict' AND data->>'campaign_id' = $2`, t1, c5); n != 1 {
			t.Errorf("round %d: T1 conflict events = %d", round, n)
		}
	}

	up()
	check(1)

	// Audit rows.
	if m := audit(c1); m == nil || m["outcome"] != "tasks" || m["conflict_count"] != float64(1) || m["assignee_dropped"] != true ||
		!strings.Contains(migCampJSON(t, m["conflicts"]), `"campaign_id":"`+c2+`"`) {
		t.Errorf("C1 audit = %v", m)
	}
	if m := audit(c2); m == nil || m["outcome"] != "tasks" || m["findings_moved"] != float64(2) || !strings.Contains(migCampJSON(t, m["tasks_attached"]), t0) {
		t.Errorf("C2 audit = %v", m)
	}
	for c, want := range map[string]string{c3: "no_scope", c5: "all_elsewhere", c8: "invalid_filter", cB: "no_open_findings"} {
		if m := audit(c); m == nil || m["outcome"] != want {
			t.Errorf("campaign %s audit = %v, want outcome %s", c, m, want)
		}
	}
	for _, c := range []string{c4, c6} {
		if audit(c) != nil {
			t.Errorf("completed campaign %s was audited", c)
		}
	}
	// Notices: A's owner (not the member), B's owner.
	if n := count(`SELECT count(*) FROM notifications WHERE notification_type = 'system_alert' AND tenant_id = $1 AND audience_id = $2`, tenantA, owner); n != 1 {
		t.Errorf("owner notices in A = %d", n)
	}
	if n := count(`SELECT count(*) FROM notifications WHERE notification_type = 'system_alert' AND audience_id = $1`, dev); n != 0 {
		t.Errorf("member notices = %d", n)
	}
	if n := count(`SELECT count(*) FROM notifications WHERE notification_type = 'system_alert' AND tenant_id = $1`, tenantB); n != 1 {
		t.Errorf("owner notices in B = %d", n)
	}

	// Idempotent: a second run changes and reports nothing.
	audits := count(`SELECT count(*) FROM audit_logs WHERE action = 'remediation_campaign.migrated'`)
	if n := count(`SELECT remediation_campaigns_to_tasks(false)`); n != 0 {
		t.Errorf("second run reported %d campaigns", n)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'remediation_campaign.migrated'`); n != audits {
		t.Errorf("second run wrote %d audit rows", n-audits)
	}
	check(2)

	// A finding that appears before the contract step joins the earlier task.
	finding(f9, "new", "sca", "CVE-2024-0001")
	if n := count(`SELECT remediation_campaigns_to_tasks(false)`); n != 1 {
		t.Errorf("third run reported %d campaigns, want 1", n)
	}
	if got := members(taskOf(c1)); got != f3+","+f9 {
		t.Errorf("C1 task after the late finding = %s", got)
	}
	if n := count(`SELECT count(*) FROM remediation_tasks WHERE campaign_id = $1`, c1); n != 1 {
		t.Errorf("C1 tasks = %d, want 1", n)
	}
	exec(`DELETE FROM findings WHERE id = $1`, f9)

	down()
	if n := count(`SELECT count(*) FROM remediation_tasks`); n != 2 {
		t.Errorf("after down: tasks = %d, want the 2 that existed", n)
	}
	if got := str(`SELECT campaign_id::text FROM remediation_tasks WHERE id = $1`, t0); got != "" {
		t.Errorf("after down: T0 campaign = %q", got)
	}
	if got := str(`SELECT campaign_id::text FROM remediation_tasks WHERE id = $1`, t1); got != c4 {
		t.Errorf("after down: T1 campaign = %q", got)
	}
	if n := count(`SELECT count(*) FROM finding_activities WHERE changes->>'origin' = 'campaign_migration'`); n != 0 {
		t.Errorf("after down: %d finding timeline entries left", n)
	}
	if n := count(`SELECT count(*) FROM remediation_actions WHERE action_key LIKE 'manual:%' AND id NOT IN ($1, $2)`, t0, t1); n != 0 {
		t.Errorf("after down: %d actions left", n)
	}
	if n := count(`SELECT count(*) FROM pg_proc WHERE proname IN ('remediation_campaigns_to_tasks', 'remediation_campaign_filter_parse')`); n != 0 {
		t.Errorf("after down: %d conversion functions left", n)
	}

	up()
	check(3)
}

func migCampJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
