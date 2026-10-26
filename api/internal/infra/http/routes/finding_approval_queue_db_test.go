package routes

// GET /api/v1/approvals?queue= (My Work): each queue is a view on the
// caller's own rows. Review holds only requests the caller may still decide
// (never their own, never one they signed, never one on an asset they own,
// nothing without findings:approve); requested holds the caller's own
// requests; no caller sees another organization's requests; the counts are
// the totals of the lists they open.

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
)

type approvalQueuePage struct {
	Data []struct {
		ID      string `json:"id"`
		Finding *struct {
			Severity  string `json:"severity"`
			KEV       bool   `json:"kev"`
			AssetName string `json:"asset_name"`
		} `json:"finding"`
		ChangedSinceRequest []string `json:"changed_since_request"`
	} `json:"data"`
	Total       int64            `json:"total"`
	QueueCounts map[string]int64 `json:"queue_counts"`
}

func (h *findingApprovalHarness) approvalQueue(u policyUser, query string) approvalQueuePage {
	h.t.Helper()
	var out approvalQueuePage
	if err := json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/approvals/?"+query, "", http.StatusOK)), &out); err != nil {
		h.t.Fatalf("decode %s: %v", query, err)
	}
	return out
}

func (p approvalQueuePage) ids() []string {
	out := make([]string, 0, len(p.Data))
	for _, d := range p.Data {
		out = append(out, d.ID)
	}
	slices.Sort(out)
	return out
}

func sortedIDs(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestApprovalQueues_CallerOwnRows_DB(t *testing.T) {
	h := newFindingApprovalHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner := h.member(org, "owner")
	requester, peer, assetOwner := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	reader := h.member(org, "member") // findings:read, no findings:approve
	otherOwner := h.member(other, "owner")

	plain := h.requestStatus(requester, h.newFinding(org, "medium"), "false_positive")

	// owner has signed this one already (a request needing more sign-offs).
	signed := h.requestStatus(requester, h.newFinding(org, "medium"), "false_positive")
	h.exec(`INSERT INTO approval_signoffs (tenant_id, subject_type, subject_id, user_id) VALUES ($1, 'finding_approval', $2, $3)`,
		org, signed, owner.id)

	// assetOwner owns this finding's asset: the policy never lets them decide.
	assetID := uuid.NewString()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'queue-owned.example', 'domain')`, assetID, org)
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`, assetID, assetOwner.id)
	ownedFinding := h.newFinding(org, "medium")
	h.exec(`UPDATE findings SET asset_id = $2 WHERE id = $1`, ownedFinding, assetID)
	owned := h.requestStatus(requester, ownedFinding, "false_positive")

	// Past its decide-by time: it can no longer be decided.
	late := h.requestStatus(requester, h.newFinding(org, "medium"), "false_positive")
	h.exec(`UPDATE finding_status_approvals SET decide_by = NOW() - INTERVAL '1 minute' WHERE id = $1`, late)

	// peer's own request, and a decided one of requester.
	peerOwn := h.requestStatus(peer, h.newFinding(org, "medium"), "false_positive")
	decided := h.requestStatus(requester, h.newFinding(org, "medium"), "false_positive")
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+decided+"/reject", `{"reason":"no"}`, http.StatusOK)

	// Another organization's pending request.
	otherOrgReq := h.requestStatus(otherOwner, h.newFinding(other, "medium"), "false_positive")
	_ = otherOrgReq

	cases := []struct {
		name          string
		u             policyUser
		review        []string
		requestedOpen []string
	}{
		{"owner", owner, sortedIDs(plain, owned, peerOwn), nil},
		{"peer", peer, sortedIDs(plain, signed, owned), sortedIDs(peerOwn)},
		{"assetOwner", assetOwner, sortedIDs(plain, signed, peerOwn), nil},
		{"requester", requester, sortedIDs(peerOwn), sortedIDs(plain, signed, owned, late)},
		{"reader", reader, nil, nil},
		{"otherOwner", otherOwner, nil, sortedIDs(otherOrgReq)},
	}
	for _, c := range cases {
		review := h.approvalQueue(c.u, "queue=review&per_page=50")
		if got := review.ids(); !slices.Equal(got, c.review) {
			t.Errorf("%s review = %v, want %v", c.name, got, c.review)
		}
		requested := h.approvalQueue(c.u, "queue=requested&status=pending&per_page=50")
		if got := requested.ids(); !slices.Equal(got, c.requestedOpen) {
			t.Errorf("%s requested = %v, want %v", c.name, got, c.requestedOpen)
		}
		// The counts are the totals of the lists they open.
		for _, p := range []approvalQueuePage{review, requested} {
			if p.QueueCounts["review"] != review.Total || p.QueueCounts["requested"] != requested.Total {
				t.Errorf("%s queue_counts = %v, review total %d, requested total %d", c.name, p.QueueCounts, review.Total, requested.Total)
			}
		}
	}

	// requested lists every status of one's own requests when asked.
	if all := h.approvalQueue(requester, "queue=requested&per_page=50").ids(); !slices.Contains(all, decided) {
		t.Errorf("requester requested (all statuses) misses the rejected request: %v", all)
	}
	// Without queue the response is unchanged (no queue_counts, no facts).
	if p := h.approvalQueue(owner, "status=pending"); p.QueueCounts != nil || (len(p.Data) > 0 && p.Data[0].Finding != nil) {
		t.Errorf("plain list grew queue fields: %+v", p)
	}
	h.expect(owner, http.MethodGet, "/api/v1/approvals/?queue=everyone", "", http.StatusBadRequest)
}

// A queue row says what changed since the request: a finding that became
// known exploited after the request shows kev, and its facts now.
func TestApprovalQueues_ChangedSinceRequest_DB(t *testing.T) {
	h := newFindingApprovalHarness(t)
	org := h.tenantWithFindings()
	owner, requester := h.member(org, "owner"), h.member(org, "admin")
	fid := h.newFinding(org, "medium")
	req := h.requestStatus(requester, fid, "accepted")
	quiet := h.requestStatus(requester, h.newFinding(org, "medium"), "false_positive")

	h.exec(`UPDATE findings SET is_in_kev = TRUE WHERE id = $1`, fid)

	page := h.approvalQueue(owner, "queue=review&per_page=50")
	seen := 0
	for _, d := range page.Data {
		switch d.ID {
		case req:
			seen++
			if !slices.Equal(d.ChangedSinceRequest, []string{"kev"}) {
				t.Errorf("changed_since_request = %v, want [kev]", d.ChangedSinceRequest)
			}
			if d.Finding == nil || !d.Finding.KEV || d.Finding.Severity != "medium" {
				t.Errorf("finding facts = %+v", d.Finding)
			}
		case quiet:
			seen++
			if len(d.ChangedSinceRequest) != 0 {
				t.Errorf("unchanged request shows %v", d.ChangedSinceRequest)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("review rows = %+v", page.Data)
	}
}

// The finding page's own list (GET /findings/{id}/approvals) says what
// changed since a pending request with the same rule as the review queue, so
// an approver deciding there sees it too; another organization gets nothing.
func TestFindingApprovals_ChangedSinceRequestOnTheFinding_DB(t *testing.T) {
	h := newFindingApprovalHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner, requester := h.member(org, "owner"), h.member(org, "admin")
	outsider := h.member(other, "owner")
	fid := h.newFinding(org, "medium")
	req := h.requestStatus(requester, fid, "accepted")
	h.exec(`UPDATE findings SET is_in_kev = TRUE WHERE id = $1`, fid)

	var rows []struct {
		ID                  string   `json:"id"`
		Status              string   `json:"status"`
		ChangedSinceRequest []string `json:"changed_since_request"`
	}
	if err := json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/findings/"+fid+"/approvals/", "", http.StatusOK)), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != req || !slices.Equal(rows[0].ChangedSinceRequest, []string{"kev"}) {
		t.Fatalf("finding approvals = %+v, want the request with [kev]", rows)
	}
	// Another organization's owner reads nothing of this finding.
	if code, body := h.do(outsider, http.MethodGet, "/api/v1/findings/"+fid+"/approvals/", ""); code == http.StatusOK && containsID(body, req) {
		t.Errorf("another organization read the request: %.200s", body)
	}
}

func containsID(body, id string) bool {
	var rows []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(body), &rows) != nil {
		return false
	}
	for _, r := range rows {
		if r.ID == id {
			return true
		}
	}
	return false
}
