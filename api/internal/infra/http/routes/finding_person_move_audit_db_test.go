package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Every person's status move and assignment change writes an audit row with
// the old and new value and the actor (finding_activities is deleted with the
// finding; audit_logs are not). A bulk move writes one row per finding plus a
// summary. Audit rows carry the finding's tenant and survive the finding's
// deletion.
func TestFindingPersonMovesAreAudited_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.vuln.SetAssigneeChecker(postgres.NewAccessControlRepository(&postgres.DB{DB: h.db}))
	fa, fb := h.findingA.String(), h.findingB.String()
	h.exec(`UPDATE findings SET status = 'new', severity = 'medium' WHERE id = ANY($1::uuid[])`, "{"+fa+","+fb+"}")
	count := func(action, id string) int {
		return h.countRows(`SELECT count(*) FROM audit_logs WHERE action = $1 AND resource_id = $2 AND tenant_id = (SELECT tenant_id FROM findings WHERE id = $2::uuid)`, action, id)
	}

	if code, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodPatch, "/api/v1/findings/"+fa+"/status",
		map[string]any{"status": "confirmed"}); code != http.StatusOK {
		t.Fatalf("status: %d %.300s", code, body)
	}
	if n := count("finding.status_changed", fa); n != 1 {
		t.Fatalf("status audit rows = %d, want 1", n)
	}
	var oldS, newS, actor string
	if err := h.db.QueryRow(`SELECT metadata->>'old_status', metadata->>'new_status', COALESCE(actor_id::text, '')
		FROM audit_logs WHERE action = 'finding.status_changed' AND resource_id = $1`, fa).Scan(&oldS, &newS, &actor); err != nil {
		t.Fatal(err)
	}
	if oldS != "new" || newS != "confirmed" || actor != h.memberA.String() {
		t.Errorf("audit = %s -> %s by %s, want new -> confirmed by memberA", oldS, newS, actor)
	}

	// Assignment (bulk path) and unassignment.
	assignPerms := []string{permission.FindingsRead.String(), permission.FindingsAssign.String(), permission.FindingsBulkUpdate.String()}
	if code, body := h.doPerms(h.memberA, assignPerms, http.MethodPost, "/api/v1/findings/bulk/assign",
		map[string]any{"finding_ids": []string{fa}, "user_id": h.memberA.String()}); code != http.StatusOK {
		t.Fatalf("assign: %d %.300s", code, body)
	}
	if n := count("finding.assigned", fa); n != 1 {
		t.Errorf("assign audit rows = %d, want 1", n)
	}
	if code, body := h.doPerms(h.memberA, assignPerms, http.MethodPost, "/api/v1/findings/"+fa+"/unassign", nil); code != http.StatusOK {
		t.Fatalf("unassign: %d %.300s", code, body)
	}
	if n := count("finding.unassigned", fa); n != 1 {
		t.Errorf("unassign audit rows = %d, want 1", n)
	}

	// A bulk move by the owner: one row per finding plus one summary.
	summaries := func() int {
		return h.countRows(`SELECT count(*) FROM audit_logs WHERE action = 'finding.bulk_updated' AND tenant_id = (SELECT tenant_id FROM findings WHERE id = $1::uuid)`, fa)
	}
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, fb)
	beforeMoves := count("finding.status_changed", fa) + count("finding.status_changed", fb)
	beforeSummaries := summaries()
	if code, body := h.doPerms(h.owner, rgMemberPerms, http.MethodPost, "/api/v1/findings/bulk/status",
		map[string]any{"finding_ids": []string{fa, fb}, "status": "in_progress"}); code != http.StatusOK {
		t.Fatalf("bulk status: %d %.300s", code, body)
	}
	if n := count("finding.status_changed", fa) + count("finding.status_changed", fb) - beforeMoves; n != 2 {
		t.Errorf("bulk per-finding audit rows = %d, want 2", n)
	}
	if n := summaries() - beforeSummaries; n != 1 {
		t.Errorf("bulk summary rows = %d, want 1", n)
	}

	// The audit outlives the finding.
	h.exec(`DELETE FROM findings WHERE id = $1`, fa)
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE resource_id = $1 AND action = 'finding.status_changed'`, fa); n < 2 {
		t.Errorf("audit rows after deletion = %d, want the 2 moves", n)
	}
}
