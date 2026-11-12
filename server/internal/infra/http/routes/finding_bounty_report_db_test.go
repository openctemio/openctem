package routes

// Bug-bounty report fields over the real routes, handler, service,
// repository and a migrated database: the findings:write gate, the
// findings:triage requirement for reward and disclosure, tenant and
// data-scope isolation, one finding per report, and the audit row.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// bountyWriterPerms: may edit findings but not triage them.
var bountyWriterPerms = []string{ //nolint:gochecknoglobals // test fixture
	permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.AssetsRead.String(),
}

func bountyTriagerPerms() []string {
	return append(append([]string{}, bountyWriterPerms...), permission.FindingsTriage.String())
}

func (h *dsHarness) bountyReportOf(id shared.ID) map[string]any {
	h.t.Helper()
	var raw []byte
	if err := h.db.QueryRow(`SELECT COALESCE(metadata->'bounty_report', 'null'::jsonb) FROM findings WHERE id = $1`, id.String()).Scan(&raw); err != nil {
		h.t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestBountyReport_UpdateGatesScopeAndAudit_DB(t *testing.T) {
	h := newDSHarness(t)
	inScope := h.dupFinding(h.assetA, "bug_bounty", "new")
	outOfScope := h.dupFinding(h.assetB, "bug_bounty", "new")
	path := func(id shared.ID) string { return "/api/v1/findings/" + id.String() + "/bounty-report" }
	plain := map[string]any{"intake": "main-program", "ref": "R-1", "researcher": "night_owl", "state": "triaged",
		"url": "https://reports.example.com/r/1"}

	// A writer sets the plain fields; the response carries the typed object.
	status, body := h.doWithPerms(h.memberA, bountyWriterPerms, http.MethodPut, path(inScope), plain)
	if status != http.StatusOK || !strings.Contains(body, `"bounty_report":{`) || !strings.Contains(body, `"researcher":"night_owl"`) {
		t.Fatalf("writer PUT = %d %.400s", status, body)
	}
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.bounty_report_changed'
		AND resource_id = $2 AND metadata->'changes'->'state'->>'new' = 'triaged'`, h.tenant.String(), inScope.String()); n != 1 {
		t.Fatalf("audit rows for the plain change = %d, want 1", n)
	}

	// A reward or disclosure from a writer without findings:triage: 403
	// naming the permission, nothing written.
	withReward := map[string]any{"intake": "main-program", "ref": "R-1", "state": "triaged",
		"reward": map[string]any{"amount": "500", "currency": "USD", "status": "pending"}}
	status, body = h.doWithPerms(h.memberA, bountyWriterPerms, http.MethodPut, path(inScope), withReward)
	if status != http.StatusForbidden || !strings.Contains(body, "TRIAGE_PERMISSION_REQUIRED") {
		t.Fatalf("writer setting a reward = %d %.300s, want 403 TRIAGE_PERMISSION_REQUIRED", status, body)
	}
	withDisclosure := map[string]any{"intake": "main-program", "ref": "R-1",
		"disclosure": map[string]any{"state": "coordinated", "agreed_date": "2026-12-01"}}
	if status, _ = h.doWithPerms(h.memberA, bountyWriterPerms, http.MethodPut, path(inScope), withDisclosure); status != http.StatusForbidden {
		t.Fatalf("writer setting a disclosure = %d, want 403", status)
	}
	if r := h.bountyReportOf(inScope); r["reward"] != nil || r["disclosure"] != nil {
		t.Fatalf("refused change was written: %v", r)
	}

	// A triager sets the reward: audited with old (none) and new.
	if status, body = h.doWithPerms(h.memberA, bountyTriagerPerms(), http.MethodPut, path(inScope), withReward); status != http.StatusOK {
		t.Fatalf("triager setting a reward = %d %.300s", status, body)
	}
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.bounty_report_changed'
		AND resource_id = $2 AND metadata->'changes'->'reward'->'new'->>'amount' = '500'
		AND metadata->'changes'->'reward'->'old' = 'null'::jsonb`, h.tenant.String(), inScope.String()); n != 1 {
		t.Fatalf("audit rows for the reward = %d, want 1 with old and new", n)
	}

	// Identity is fixed; an http link is refused.
	moved := map[string]any{"intake": "main-program", "ref": "R-2"}
	if status, _ = h.doWithPerms(h.memberA, bountyTriagerPerms(), http.MethodPut, path(inScope), moved); status != http.StatusBadRequest {
		t.Fatalf("changing the ref = %d, want 400", status)
	}
	badURL := map[string]any{"intake": "main-program", "ref": "R-1", "url": "http://169.254.169.254/latest/meta-data/"}
	if status, _ = h.doWithPerms(h.memberA, bountyTriagerPerms(), http.MethodPut, path(inScope), badURL); status != http.StatusBadRequest {
		t.Fatalf("http url = %d, want 400", status)
	}

	// Out of the caller's data scope, or another tenant's finding: 404.
	if status, _ = h.doWithPerms(h.memberA, bountyTriagerPerms(), http.MethodPut, path(outOfScope), plain); status != http.StatusNotFound {
		t.Fatalf("out-of-scope finding = %d, want 404", status)
	}
	if status, _ = h.doWithPerms(h.memberFree, bountyTriagerPerms(), http.MethodPut, path(inScope), plain); status != http.StatusNotFound {
		t.Fatalf("member with no scope = %d, want 404", status)
	}
	other := shared.NewID()
	otherAsset := shared.NewID()
	otherFinding := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "ds-other-"+other.String())
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'other-host', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'bug_bounty', 't', 'm', 'high', $1::text, 'new')`, otherFinding.String(), other.String(), otherAsset.String())
	if status, _ = h.do(h.owner, true, http.MethodPut, path(otherFinding), plain); status != http.StatusNotFound {
		t.Fatalf("another tenant's finding (as owner) = %d, want 404", status)
	}
	if r := h.bountyReportOf(otherFinding); r != nil {
		t.Fatalf("another tenant's finding was written: %v", r)
	}

	// Without findings:write the route gate refuses.
	if status, _ = h.doWithPerms(h.memberA, []string{permission.FindingsRead.String(), permission.FindingsTriage.String()},
		http.MethodPut, path(inScope), plain); status != http.StatusForbidden {
		t.Fatalf("no findings:write = %d, want 403", status)
	}

	// Only bug_bounty findings carry a report.
	if status, _ = h.doWithPerms(h.memberA, bountyTriagerPerms(), http.MethodPut, path(h.findingA), plain); status != http.StatusBadRequest {
		t.Fatalf("report on a scanner finding = %d, want 400", status)
	}
}

func TestBountyReport_CreateGatesAndUniqueness_DB(t *testing.T) {
	h := newDSHarness(t)
	create := func(perms []string, source string, report map[string]any) (int, string) {
		return h.doWithPerms(h.memberA, perms, http.MethodPost, "/api/v1/findings/", map[string]any{
			"asset_id": h.assetA.String(), "source": source, "tool_name": "bounty-intake",
			"message": "IDOR on invoices " + shared.NewID().String(), "severity": "high", "bounty_report": report,
		})
	}
	paid := map[string]any{"intake": "vdp", "ref": "R-77", "reward": map[string]any{"amount": "250", "currency": "EUR", "status": "paid"}}

	if status, body := create(bountyWriterPerms, "bug_bounty", paid); status != http.StatusForbidden || !strings.Contains(body, "TRIAGE_PERMISSION_REQUIRED") {
		t.Fatalf("writer creating with a reward = %d %.300s, want 403", status, body)
	}
	if n := h.countRows(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND metadata->'bounty_report'->>'ref' = 'R-77'`, h.tenant.String()); n != 0 {
		t.Fatalf("refused create wrote %d findings", n)
	}
	status, body := create(bountyTriagerPerms(), "bug_bounty", paid)
	if status != http.StatusCreated || !strings.Contains(body, `"ref":"R-77"`) {
		t.Fatalf("triager create = %d %.300s", status, body)
	}
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.bounty_report_changed'
		AND metadata->>'ref' = 'R-77' AND metadata->'changes'->'reward'->'new'->>'status' = 'paid'`, h.tenant.String()); n != 1 {
		t.Fatalf("audit rows for the created report = %d, want 1", n)
	}
	// The same report again: 409, one finding per report.
	if status, body = create(bountyTriagerPerms(), "bug_bounty", map[string]any{"intake": "vdp", "ref": "R-77"}); status != http.StatusConflict {
		t.Fatalf("same report twice = %d %.300s, want 409", status, body)
	}
	// A writer may file a report without reward or disclosure.
	if status, body = create(bountyWriterPerms, "bug_bounty", map[string]any{"intake": "vdp", "ref": "R-78", "state": "new"}); status != http.StatusCreated {
		t.Fatalf("writer create without reward = %d %.300s", status, body)
	}
	// A report on another source is refused.
	if status, _ = create(bountyTriagerPerms(), "manual", map[string]any{"intake": "vdp", "ref": "R-79"}); status != http.StatusBadRequest {
		t.Fatalf("report on a manual finding = %d, want 400", status)
	}
}
