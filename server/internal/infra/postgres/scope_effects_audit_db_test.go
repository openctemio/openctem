package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Scope effects are accountable finding by finding (research/438): every
// close and reopen writes a finding.status_changed audit row in the same
// transaction, naming the exclusion and its kind; closing a critical-tier
// finding (critical, P0 or KEV) is high. A close leaves the SLA
// (not_applicable, never met or missed); the reopen keeps the deadline, so
// excluding and re-including never resets a clock. Nothing is written for
// another tenant. Requires DATABASE_URL.
func TestScopeEffectsAuditAndSLA(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScopeEffectsRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	asset := func(tid shared.ID, name string) string {
		t.Helper()
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'subdomain', 'active')`,
			id, tid.String(), name)
		return id
	}
	deadline := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	finding := func(tid shared.ID, assetID, severity string, kev bool) string {
		t.Helper()
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status,
				fingerprint, is_in_kev, sla_deadline)
			VALUES ($1, $2, $3, 'dast', 'tool', 'msg', $4, 'confirmed', $5, $6, $7)`,
			id, tid.String(), assetID, severity, "fp-scope-audit-"+id, kev, deadline)
		return id
	}
	var exID string
	if err := db.QueryRowContext(ctx, `INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status,
			approved_by, approved_at, created_by, kind)
		VALUES ($1, 'domain', 'gone.example.com', 'sold', 'active', 'a', now(), 'r', 'not_ours') RETURNING id::text`,
		tenant.String()).Scan(&exID); err != nil {
		t.Fatal(err)
	}
	a := asset(tenant, "gone.example.com")
	fKEV := finding(tenant, a, "medium", true)
	fLow := finding(tenant, a, "low", false)
	theirs := finding(other, asset(other, "gone.example.com"), "critical", true)
	mustExec(t, db, `UPDATE findings SET work_item_uris = ARRAY['https://example.atlassian.net/browse/SEC-1'] WHERE id = $1`, fKEV)

	closed, err := repo.CloseOutOfScope(ctx, tenant, 100)
	if err != nil || len(closed) != 2 {
		t.Fatalf("closed %d (err %v), want 2", len(closed), err)
	}

	type row struct {
		severity string
		meta     map[string]any
	}
	auditOf := func(tid shared.ID, findingID, newStatus string) []row {
		t.Helper()
		rows, err := db.QueryContext(ctx, `SELECT severity, metadata FROM audit_logs
			WHERE tenant_id = $1 AND resource_type = 'finding' AND resource_id = $2
			  AND action = 'finding.status_changed' AND metadata->>'new_status' = $3`, tid.String(), findingID, newStatus)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			var raw []byte
			if err := rows.Scan(&r.severity, &raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &r.meta); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	sla := func(id string) (string, time.Time) {
		t.Helper()
		var st string
		var dl time.Time
		if err := db.QueryRowContext(ctx, `SELECT sla_status, sla_deadline FROM findings WHERE id = $1`, id).Scan(&st, &dl); err != nil {
			t.Fatal(err)
		}
		return st, dl
	}

	jobs := func(findingID string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM durable_jobs WHERE tenant_id = $1 AND subject_id = $2
			AND kind IN ('jira_status_sync', 'github_status_sync') AND status = 'pending'`, tenant.String(), findingID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := jobs(fKEV); n != 2 {
		t.Fatalf("ticket pushes queued for the linked finding: %d, want 2 (Jira, GitHub)", n)
	}
	if n := jobs(fLow); n != 0 {
		t.Fatalf("ticket pushes queued for an unlinked finding: %d, want 0", n)
	}

	kevAudit := auditOf(tenant, fKEV, "resolved")
	if len(kevAudit) != 1 || kevAudit[0].severity != "high" {
		t.Fatalf("KEV close audit rows %+v, want one high", kevAudit)
	}
	m := kevAudit[0].meta
	if m["old_status"] != "confirmed" || m["closure_reason"] != "out_of_scope" || m["source"] != "scope_effects" ||
		m["actor_kind"] != "system" {
		t.Fatalf("KEV close audit metadata %v", m)
	}
	excl, _ := m["exclusions"].([]any)
	if len(excl) != 1 {
		t.Fatalf("audit names %d exclusions, want 1: %v", len(excl), m["exclusions"])
	}
	if e, _ := excl[0].(map[string]any); e["id"] != exID || e["kind"] != "not_ours" {
		t.Fatalf("audit exclusion %v, want %s/not_ours", excl[0], exID)
	}
	if lowAudit := auditOf(tenant, fLow, "resolved"); len(lowAudit) != 1 || lowAudit[0].severity != "medium" {
		t.Fatalf("low close audit rows %+v, want one medium", lowAudit)
	}
	if st, _ := sla(fKEV); st != "not_applicable" {
		t.Fatalf("closed out of scope past the deadline: sla_status %s, want not_applicable", st)
	}
	if got := auditOf(other, theirs, "resolved"); len(got) != 0 {
		t.Fatalf("the other tenant got %d audit rows", len(got))
	}
	var theirStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1`, theirs).Scan(&theirStatus); err != nil {
		t.Fatal(err)
	}
	if theirStatus != "confirmed" {
		t.Fatalf("the other tenant's finding is %s, want confirmed", theirStatus)
	}

	// Re-include: the finding reopens with the deadline it had, now overdue.
	mustExec(t, db, `DELETE FROM scope_exclusions WHERE id = $1`, exID)
	reopened, err := repo.ReopenBackInScope(ctx, tenant, 100)
	if err != nil || len(reopened) != 2 {
		t.Fatalf("reopened %d (err %v), want 2", len(reopened), err)
	}
	if st, dl := sla(fKEV); st != "overdue" || !dl.Equal(deadline) {
		t.Fatalf("after re-include: sla_status %s deadline %v, want overdue at %v", st, dl, deadline)
	}
	back := auditOf(tenant, fKEV, "confirmed")
	if len(back) != 1 || back[0].severity != "medium" || back[0].meta["trigger"] != "back_in_scope" ||
		back[0].meta["old_status"] != "resolved" {
		t.Fatalf("reopen audit rows %+v, want one medium back_in_scope from resolved", back)
	}
}
