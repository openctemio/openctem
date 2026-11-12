package routes

// The practice and compliance_result filters of GET /findings
// (docs/architecture/finding-practices.md) narrow within the caller's tenant
// and data scope: a scoped member filtering on compliance never sees a
// compliance finding outside their scope, and nobody sees another tenant's.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFindingsList_PracticeFilterWithinScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	tid := h.tenant.String()
	ins := func(tenant, asset, practice, result string) string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, practice, practice_reason)
			VALUES ($1::uuid, $2, $3, 'va', 'nessus', 'practice probe', 'high', $1::text, 'new', $4, 'test')`, id, tenant, asset, practice)
		if result != "" {
			h.exec(`UPDATE findings SET finding_type = 'compliance', compliance_result = $2 WHERE id = $1`, id, result)
		}
		return id
	}
	cisA := ins(tid, h.assetA.String(), "compliance", "fail")
	passA := ins(tid, h.assetA.String(), "compliance", "pass")
	cisB := ins(tid, h.assetB.String(), "compliance", "fail")
	infraA := ins(tid, h.assetA.String(), "infra", "")

	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "pr-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'pr-other.example.com', 'host')`, otherAsset.String(), other.String())
	ins(other.String(), otherAsset.String(), "compliance", "fail")

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}

	has := func(ids []string, id string) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}

	ids, total, _ := h.listIDs(t, admin, "practice=compliance")
	if total != 3 || !has(ids, cisA) || !has(ids, passA) || !has(ids, cisB) {
		t.Fatalf("owner practice=compliance = %v (%d), want this tenant's 3", ids, total)
	}
	ids, total, _ = h.listIDs(t, memberA, "practice=compliance")
	if total != 2 || has(ids, cisB) {
		t.Fatalf("memberA practice=compliance = %v (%d), want only asset A's 2", ids, total)
	}
	ids, _, _ = h.listIDs(t, memberA, "practice_not=compliance")
	if has(ids, cisA) || has(ids, passA) || !has(ids, infraA) {
		t.Fatalf("memberA practice_not=compliance = %v", ids)
	}
	ids, total, _ = h.listIDs(t, admin, "practice=compliance&compliance_result=fail")
	if total != 2 || has(ids, passA) {
		t.Fatalf("owner compliance_result=fail = %v (%d)", ids, total)
	}
	ids, _, _ = h.listIDs(t, admin, "compliance_result_not=pass")
	if has(ids, passA) || !has(ids, infraA) {
		t.Fatalf("compliance_result_not=pass must keep findings without a result: %v", ids)
	}
	if status, _, _ := h.listFindings(t, admin, "practice=vulnerabilities"); status != 400 {
		t.Fatalf("unknown practice = %d, want 400", status)
	}
}
