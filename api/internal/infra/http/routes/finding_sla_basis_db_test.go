package routes

// GET /findings/{id} sla_basis: why the deadline is the date it is. It rides
// on the single-finding read, so the same scope check applies (a member
// cannot read the block of a finding outside their scope), and it is computed
// with the deadline writers' rule.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type slaBasisBody struct {
	SLABasis *struct {
		PolicyScope        string     `json:"policy_scope"`
		Basis              string     `json:"basis"`
		Days               int        `json:"days"`
		KEVCapDays         int        `json:"kev_cap_days"`
		ClockStartedAt     time.Time  `json:"clock_started_at"`
		ClockReason        string     `json:"clock_reason"`
		Restarts           int        `json:"restarts"`
		LastRestartTrigger string     `json:"last_restart_trigger"`
		ExpectedDeadline   *time.Time `json:"expected_deadline"`
	} `json:"sla_basis"`
}

func (h *gsHarness) slaBasis(t *testing.T, c flCaller, id string) (int, slaBasisBody) {
	t.Helper()
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings/"+id)
	var out slaBasisBody
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return status, out
}

func TestFindingSLABasis_PriorityWindowAndReopenedClock(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA.String()
	h.exec(`UPDATE findings SET priority_class = 'P1', first_detected_at = NOW() - INTERVAL '10 days' WHERE id = $1`, fa)

	owner := flCaller{"owner", h.owner, true}
	status, got := h.slaBasis(t, owner, fa)
	if status != http.StatusOK || got.SLABasis == nil {
		t.Fatalf("owner GET = %d, sla_basis %v", status, got.SLABasis)
	}
	b := got.SLABasis
	// No policy configured: the platform defaults, the P1 window.
	if b.PolicyScope != "platform" || b.Basis != "priority" || b.Days <= 0 || b.ClockReason != "first_detected" || b.Restarts != 0 {
		t.Errorf("first look = %+v", b)
	}

	// A regression restarted the clock.
	h.exec(`UPDATE findings SET last_reopened_at = NOW(), sla_started_at = NOW() WHERE id = $1`, fa)
	h.exec(`INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
		VALUES (gen_random_uuid(), $1, $2, 'sla_restarted', 'system', 'system: scan', '{"trigger":"scan"}', 'auto', NOW())`,
		h.tenant.String(), fa)
	_, got = h.slaBasis(t, owner, fa)
	if b := got.SLABasis; b == nil || b.ClockReason != "reopened" || b.Restarts != 1 || b.LastRestartTrigger != "scan" ||
		time.Since(b.ClockStartedAt) > time.Hour || b.ExpectedDeadline == nil {
		t.Errorf("after restart = %+v", b)
	}

	// An organization policy with its own P1 window governs from then on.
	h.exec(`INSERT INTO sla_policies (id, tenant_id, name, is_default, is_active, critical_days, high_days, medium_days, low_days, info_days, p0_days, p1_days, p2_days, p3_days, kev_cap_days)
		VALUES (gen_random_uuid(), $1, 'Prod', true, true, 2, 7, 30, 90, 0, 1, 5, 20, 60, 3)`, h.tenant.String())
	_, got = h.slaBasis(t, owner, fa)
	if b := got.SLABasis; b == nil || b.PolicyScope != "organization" || b.Days != 5 || b.KEVCapDays != 3 {
		t.Errorf("with a policy = %+v", b)
	}
}

func TestFindingSLABasis_OutOfScopeFindingIsNotRead(t *testing.T) {
	h := newGroupScopeHarness(t)
	memberA := flCaller{"memberA", h.memberA, false}
	if status, got := h.slaBasis(t, memberA, h.findingB.String()); status == http.StatusOK || got.SLABasis != nil {
		t.Errorf("memberA GET FB = %d with sla_basis %v, want refused", status, got.SLABasis)
	}
	if status, got := h.slaBasis(t, memberA, h.findingA.String()); status != http.StatusOK || got.SLABasis == nil {
		t.Errorf("memberA GET FA = %d, sla_basis %v", status, got.SLABasis)
	}
}
