package routes

// GET /findings/quick-views (research 234 D1): every count equals the total
// of the list its params open, for the same caller, so a scoped member never
// counts a finding outside their scope and no caller counts another tenant's.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type qvResponse struct {
	Views []struct {
		Key    string `json:"key"`
		Count  int64  `json:"count"`
		Params string `json:"params"`
	} `json:"views"`
}

func (h *gsHarness) quickViews(t *testing.T, c flCaller) (qvResponse, http.Header) {
	t.Helper()
	status, hdr, body := h.listFindingsPath(t, c, "/api/v1/findings/quick-views")
	if status != http.StatusOK {
		t.Fatalf("%s GET /findings/quick-views = %d: %.300s", c.name, status, body)
	}
	var out qvResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out, hdr
}

// seedQuickViewFindings adds one finding per view on A1 (memberA's scope)
// and on B1 (out of it), one B1 finding assigned to memberA, and another
// tenant's findings in every state.
func (h *gsHarness) seedQuickViewFindings(t *testing.T) (pendingOn shared.ID) {
	t.Helper()
	tid := h.tenant.String()
	ins := func(tenant, asset string, status, extra string) shared.ID {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'qv-tool', 'qv finding', 'medium', $1::text, $4)`, id.String(), tenant, asset, status)
		if extra != "" {
			h.exec(`UPDATE findings SET `+extra+` WHERE id = $1`, id.String())
		}
		return id
	}
	for _, asset := range []string{h.assetA.String(), h.assetB.String()} {
		ins(tid, asset, "new", "")
		ins(tid, asset, "confirmed", "sla_status = 'overdue', sla_deadline = NOW() - INTERVAL '3 days'")
		ins(tid, asset, "accepted", "acceptance_expires_at = NOW() + INTERVAL '10 days'")
		ins(tid, asset, "accepted", "acceptance_expires_at = NOW() + INTERVAL '90 days'")
		ins(tid, asset, "resolved", "")
		ins(tid, asset, "false_positive", "")
	}
	ins(tid, h.assetB.String(), "in_progress", "assigned_to = '"+h.memberA.String()+"'")
	pendingOn = h.findingA
	h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, justification, status)
		VALUES ($1, $2, $3, 'false_positive', 'qv', 'pending')`, shared.NewID().String(), tid, pendingOn.String())
	pendingB := ins(tid, h.assetB.String(), "confirmed", "")
	h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, justification, status)
		VALUES ($1, $2, $3, 'false_positive', 'qv', 'pending')`, shared.NewID().String(), tid, pendingB.String())

	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "qv-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'qv-other.example', 'domain')`, otherAsset.String(), other.String())
	for _, st := range []string{"new", "confirmed", "accepted", "resolved"} {
		ins(other.String(), otherAsset.String(), st, "")
	}
	return pendingOn
}

func TestFindingQuickViews_CountsEqualTheirListsInScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.seedQuickViewFindings(t)

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	wantKeys := []string{"active", "needs_triage", "my_queue", "sla_breached", "pending_approval", "accepted_expiring", "closed"}
	got := map[string]map[string]int64{}
	for _, c := range []flCaller{admin, memberA} {
		qv, hdr := h.quickViews(t, c)
		if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "private") {
			t.Errorf("%s Cache-Control = %q, want private", c.name, cc)
		}
		if len(qv.Views) != len(wantKeys) {
			t.Fatalf("%s views = %+v", c.name, qv.Views)
		}
		got[c.name] = map[string]int64{}
		for i, v := range qv.Views {
			if v.Key != wantKeys[i] {
				t.Errorf("%s view %d = %s, want %s", c.name, i, v.Key, wantKeys[i])
			}
			_, total, _ := h.listIDs(t, c, v.Params)
			if v.Count != total {
				t.Errorf("%s %s count = %d, GET /findings?%s total = %d", c.name, v.Key, v.Count, v.Params, total)
			}
			got[c.name][v.Key] = v.Count
		}
	}

	// The owner counts both assets of this tenant, never the other tenant's.
	// Active: fa fb fb2 fp + per asset new, confirmed + memberA's in_progress + pendingB.
	// My queue is "related to me": memberA owns A1 (its open findings, fa,
	// new, confirmed) and is the assignee of one B1 finding; the owner has none.
	want := map[string]map[string]int64{
		"owner":   {"active": 10, "needs_triage": 2, "my_queue": 0, "sla_breached": 2, "pending_approval": 2, "accepted_expiring": 2, "closed": 8},
		"memberA": {"active": 4, "needs_triage": 1, "my_queue": 4, "sla_breached": 1, "pending_approval": 1, "accepted_expiring": 1, "closed": 4},
	}
	for who, m := range want {
		for k, n := range m {
			if got[who][k] != n {
				t.Errorf("%s %s = %d, want %d (all: %v)", who, k, got[who][k], n, got[who])
			}
		}
	}
}

// The filters behind the new views work on the list itself.
func TestFindingsList_QuickViewFilters(t *testing.T) {
	h := newGroupScopeHarness(t)
	pending := h.seedQuickViewFindings(t)
	admin := flCaller{"owner", h.owner, true}

	ids, _, _ := h.listIDs(t, admin, "pending_approval=true&asset_id="+h.assetA.String())
	if len(ids) != 1 || ids[0] != pending.String() {
		t.Errorf("pending_approval=true on A1 = %v, want [%s]", ids, pending)
	}
	_, withoutPending, _ := h.listIDs(t, admin, "pending_approval=false&state=all")
	_, all, _ := h.listIDs(t, admin, "state=all")
	if withoutPending != all-2 {
		t.Errorf("pending_approval=false = %d, want %d", withoutPending, all-2)
	}
	if _, n, _ := h.listIDs(t, admin, "status=accepted&acceptance_expires_at_lte=P30D"); n != 2 {
		t.Errorf("accepted expiring within 30 days = %d, want 2", n)
	}
	if _, n, _ := h.listIDs(t, admin, "acceptance_expires_at_gt=%2BP30D"); n != 2 {
		t.Errorf("acceptance expiring after 30 days = %d, want 2", n)
	}
	_, closed, _ := h.listIDs(t, admin, "state=closed")
	_, fixed, _ := h.listIDs(t, admin, "state=fixed")
	_, disp, _ := h.listIDs(t, admin, "state=dispositioned")
	if closed != fixed+disp || closed == 0 {
		t.Errorf("state=closed = %d, want fixed %d + dispositioned %d", closed, fixed, disp)
	}
}
