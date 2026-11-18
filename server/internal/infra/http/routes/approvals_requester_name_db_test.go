package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// The approvals inbox names each requester, from the caller's organization
// only: a current member is named, a user of another organization (or a
// former member) is not, an actor request has no name, and another
// organization lists none of these approvals.
func TestApprovalsList_RequesterName_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), log)
		svc.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
		vh := handler.NewVulnerabilityHandler(svc, validator.New(), log)
		vh.SetApprovalMemberNamer(postgres.NewScopeActorRepository(db))
		hs.Vulnerability = vh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	owner, member := h.member(org, "owner"), h.member(org, "member")
	outsider := h.member(other, "owner")
	h.exec(`UPDATE users SET name = 'Lan Requester' WHERE id = $1`, member.id)
	h.exec(`UPDATE users SET name = 'Other Org Person' WHERE id = $1`, outsider.id)
	t.Cleanup(func() {
		for _, tn := range []string{org, other} {
			h.exec(`DELETE FROM finding_status_approvals WHERE tenant_id = $1`, tn)
			h.exec(`DELETE FROM findings WHERE tenant_id = $1`, tn)
		}
	})

	newFinding := func(tid string) string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, 'sast', 'name-test', 'm', 'medium', $1::text, 'confirmed')`, id, tid)
		return id
	}
	approval := func(tid, findingID, requestedBy, actor string) string {
		id := shared.NewID().String()
		var by any
		if requestedBy != "" {
			by = requestedBy
		}
		var act any
		if actor != "" {
			act = actor
		}
		h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by,
			requested_by_actor, justification, status) VALUES ($1, $2, $3, 'false_positive', $4, $5, 'why', 'pending')`,
			id, tid, findingID, by, act)
		return id
	}
	byMember := approval(org, newFinding(org), member.id, "")
	byOutsider := approval(org, newFinding(org), outsider.id, "")
	byAI := approval(org, newFinding(org), "", "ai_triage")
	otherOrgs := approval(other, newFinding(other), outsider.id, "")

	type row struct {
		ID              string `json:"id"`
		RequestedBy     string `json:"requested_by"`
		RequestedByName string `json:"requested_by_name"`
	}
	list := func(u policyUser) map[string]row {
		var out struct {
			Data []row `json:"data"`
		}
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/approvals?status=pending", "", http.StatusOK)), &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]row{}
		for _, r := range out.Data {
			m[r.ID] = r
		}
		return m
	}

	got := list(owner)
	if got[byMember].RequestedByName != "Lan Requester" {
		t.Fatalf("member requester not named: %+v", got[byMember])
	}
	if r, ok := got[byOutsider]; !ok || r.RequestedByName != "" || r.RequestedBy != outsider.id {
		t.Fatalf("a user of another organization was named (or the row is missing): %+v", r)
	}
	if r := got[byAI]; r.RequestedByName != "" || r.RequestedBy != "" {
		t.Fatalf("actor request has a person: %+v", r)
	}
	if _, leaked := got[otherOrgs]; leaked {
		t.Fatal("another organization's approval is listed")
	}

	// The other organization sees only its own approval, named from its own
	// members.
	theirs := list(outsider)
	if len(theirs) != 1 || theirs[otherOrgs].RequestedByName != "Other Org Person" {
		t.Fatalf("other organization list: %+v", theirs)
	}

	// A member who leaves is no longer named.
	h.exec(`UPDATE tenant_members SET status = 'offboarded' WHERE user_id = $1 AND tenant_id = $2`, member.id, org)
	if r := list(owner)[byMember]; r.RequestedByName != "" {
		t.Fatalf("an offboarded member is still named: %+v", r)
	}
}

// The finding page's approval band names the requester the same way as the
// inbox: GET /findings/{id}/approvals names a current member, not a user of
// another organization or a member who left, and an actor request carries
// the actor and no person.
func TestFindingApprovals_RequesterName_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), log)
		svc.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
		vh := handler.NewVulnerabilityHandler(svc, validator.New(), log)
		vh.SetApprovalMemberNamer(postgres.NewScopeActorRepository(db))
		hs.Vulnerability = vh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	owner, member, leaver := h.member(org, "owner"), h.member(org, "member"), h.member(org, "member")
	outsider := h.member(other, "owner")
	h.exec(`UPDATE users SET name = 'Lan Requester' WHERE id = $1`, member.id)
	h.exec(`UPDATE users SET name = 'Gone Person' WHERE id = $1`, leaver.id)
	h.exec(`UPDATE users SET name = 'Other Org Person' WHERE id = $1`, outsider.id)
	t.Cleanup(func() {
		for _, tn := range []string{org, other} {
			h.exec(`DELETE FROM finding_status_approvals WHERE tenant_id = $1`, tn)
			h.exec(`DELETE FROM findings WHERE tenant_id = $1`, tn)
		}
	})

	findingID := shared.NewID().String()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'name-test', 'm', 'medium', $1::text, 'confirmed')`, findingID, org)
	approval := func(requestedBy, actor, status string) string {
		id := shared.NewID().String()
		var by any
		if requestedBy != "" {
			by = requestedBy
		}
		var act any
		if actor != "" {
			act = actor
		}
		h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by,
			requested_by_actor, justification, status) VALUES ($1, $2, $3, 'false_positive', $4, $5, 'why', $6)`,
			id, org, findingID, by, act, status)
		return id
	}
	byMember := approval(member.id, "", "pending")
	byLeaver := approval(leaver.id, "", "canceled")
	byOutsider := approval(outsider.id, "", "canceled")
	byAI := approval("", "ai_triage", "canceled")
	h.exec(`UPDATE tenant_members SET status = 'offboarded' WHERE user_id = $1 AND tenant_id = $2`, leaver.id, org)

	type row struct {
		ID               string `json:"id"`
		RequestedBy      string `json:"requested_by"`
		RequestedByName  string `json:"requested_by_name"`
		RequestedByActor string `json:"requested_by_actor"`
	}
	var rows []row
	if err := json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/findings/"+findingID+"/approvals", "", http.StatusOK)), &rows); err != nil {
		t.Fatal(err)
	}
	got := map[string]row{}
	for _, r := range rows {
		got[r.ID] = r
	}
	if len(got) != 4 {
		t.Fatalf("want the finding's 4 approvals, got %+v", rows)
	}
	if got[byMember].RequestedByName != "Lan Requester" {
		t.Fatalf("a current member is not named: %+v", got[byMember])
	}
	if r := got[byLeaver]; r.RequestedByName != "" || r.RequestedBy != leaver.id {
		t.Fatalf("a former member is named: %+v", r)
	}
	if r := got[byOutsider]; r.RequestedByName != "" {
		t.Fatalf("a user of another organization is named: %+v", r)
	}
	if r := got[byAI]; r.RequestedByName != "" || r.RequestedBy != "" || r.RequestedByActor != "ai_triage" {
		t.Fatalf("an actor request names a person: %+v", r)
	}

	// Another organization cannot read this finding's approvals at all.
	_, body := h.do(outsider, http.MethodGet, "/api/v1/findings/"+findingID+"/approvals", "")
	if strings.Contains(body, "Lan Requester") || strings.Contains(body, byMember) {
		t.Fatalf("another organization reads this finding's approvals: %s", body)
	}
}
