package routes

// The verification queue's Approve / Reject over the real routes, services and
// a migrated database: a finding the transition engine refuses is reported
// with a registered refusal code (never the error text), and the report never
// tells a caller anything about a finding outside its data scope or tenant.
// Approving a CVE group whose only finding was critical used to answer
// {"updated":0} with 200, which the web showed as "0 findings verified".

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type fixDecisionBody struct {
	Updated int            `json:"updated"`
	Refused int            `json:"refused"`
	Reasons map[string]int `json:"reasons"`
	Rows    []struct {
		FindingID string `json:"finding_id"`
		Code      string `json:"code"`
	} `json:"rows"`
}

func decodeFixDecision(t *testing.T, code int, body string) fixDecisionBody {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d: %.300s", code, body)
	}
	var out fixDecisionBody
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %.300s: %v", body, err)
	}
	return out
}

// criticalFixApplied puts a finding in the queue as a critical fix with no
// evidence (no checklist, no retest, not seen since).
func (h *gsHarness) criticalFixApplied(id shared.ID) {
	h.exec(`UPDATE findings SET status = 'fix_applied', severity = 'critical', priority_class = NULL, is_in_kev = false,
		last_seen_at = NOW() - interval '1 day', last_reopened_at = NULL WHERE id = $1`, id.String())
	h.exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, id.String())
}

func TestFixDecision_ApproveGroupReportsRefusal_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA
	h.criticalFixApplied(fa)
	verify := map[string]any{"filter": map[string]any{"cve_ids": []string{h.cveA}}, "note": "patched"}

	// Approve the group: nothing verified, and the reason is the code.
	code, body := h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify", verify)
	res := decodeFixDecision(t, code, body)
	if res.Updated != 0 || res.Refused != 1 || res.Reasons[finding.RefusalEvidenceRequired] != 1 ||
		len(res.Rows) != 1 || res.Rows[0].FindingID != fa.String() || res.Rows[0].Code != finding.RefusalEvidenceRequired {
		t.Fatalf("approve of a critical fix without evidence = %+v, want 0 updated and one %s", res, finding.RefusalEvidenceRequired)
	}
	if strings.Contains(body, "critical, P0") || strings.Contains(body, "error") {
		t.Fatalf("the response carries error text: %s", body)
	}
	if st := h.statusOf(fa); st != "fix_applied" {
		t.Fatalf("refused finding moved to %s", st)
	}

	// The same through the by-id form (one finding without a CVE).
	code, body = h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"finding_ids": []string{fa.String()}, "note": "patched"})
	if res := decodeFixDecision(t, code, body); res.Updated != 0 || res.Reasons[finding.RefusalEvidenceRequired] != 1 {
		t.Fatalf("by-id verify = %+v, want one %s", res, finding.RefusalEvidenceRequired)
	}

	// With the evidence the rule asks for (the checklist completed by another
	// person), the same Approve verifies the finding.
	h.completeChecklistViaAPI(h.memberA, fa)
	code, body = h.doPerms(h.memberFull, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify", verify)
	if res := decodeFixDecision(t, code, body); res.Updated != 1 || res.Refused != 0 {
		t.Fatalf("approve with the evidence = %+v, want 1 updated", res)
	}
	if st := h.statusOf(fa); st != "resolved" {
		t.Fatalf("approved finding is %s, want resolved", st)
	}
}

// Out of data scope and in another tenant: the report says nothing a caller
// may not see. By filter the finding is simply not selected; by id it reads
// exactly as a finding that does not exist.
func TestFixDecision_RefusalsScopedAndTenantIsolated_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.criticalFixApplied(h.findingB) // on B1, outside memberA's scope

	// Another tenant with a fix_applied finding of the SAME CVE as group A.
	otherTenant, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant.String(), "fdr-"+otherTenant.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, otherTenant.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'fdr.example.com', 'domain', 'public', 'high')`,
		otherAsset.String(), otherTenant.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id)
		VALUES ($1::uuid, $2, $3, 'sca', 'fdr-tool', 'fdr finding', 'medium', $1::text, 'fix_applied', $4)`,
		otherFinding.String(), otherTenant.String(), otherAsset.String(), h.cveA)

	// memberA holds findings:verify; the owner is an administrator.
	call := func(user shared.ID, path string, body any) fixDecisionBody {
		var code int
		var raw string
		if user == h.owner {
			code, raw = h.do(user, true, http.MethodPost, path, body)
		} else {
			code, raw = h.doPerms(user, rgVerifierPerms(), http.MethodPost, path, body)
		}
		return decodeFixDecision(t, code, raw)
	}
	verifyByFilter := func(user shared.ID, cve string) fixDecisionBody {
		return call(user, "/api/v1/findings/actions/verify",
			map[string]any{"filter": map[string]any{"cve_ids": []string{cve}}, "note": "patched"})
	}
	byID := func(user shared.ID, path string, id string) fixDecisionBody {
		return call(user, path, map[string]any{"finding_ids": []string{id}, "note": "patched", "reason": "not fixed"})
	}

	// Out of scope by filter: no row, no count.
	if res := verifyByFilter(h.memberA, h.cveB); res.Updated != 0 || res.Refused != 0 || len(res.Rows) != 0 {
		t.Fatalf("memberA approve of out-of-scope group = %+v, want an empty report", res)
	}
	// Out of scope by id reads exactly as a missing finding, on both actions.
	for _, path := range []string{"/api/v1/findings/actions/verify", "/api/v1/findings/actions/reject-fix"} {
		oos := byID(h.memberA, path, h.findingB.String())
		missing := byID(h.memberA, path, shared.NewID().String())
		if oos.Refused != 1 || oos.Rows[0].Code != finding.RefusalNotFound || missing.Rows[0].Code != finding.RefusalNotFound {
			t.Fatalf("%s out of scope = %+v, missing = %+v, want both %s", path, oos, missing, finding.RefusalNotFound)
		}
	}
	if st := h.statusOf(h.findingB); st != "fix_applied" {
		t.Fatalf("out-of-scope finding moved to %s", st)
	}

	// Another tenant: the same CVE selects only this tenant's findings, and
	// the other tenant's id is not found, even for the organization owner.
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, h.findingA.String())
	if res := verifyByFilter(h.owner, h.cveA); res.Updated != 0 || res.Refused != 0 {
		t.Fatalf("owner approve of group A = %+v, touched another tenant's finding", res)
	}
	for _, path := range []string{"/api/v1/findings/actions/verify", "/api/v1/findings/actions/reject-fix"} {
		if res := byID(h.owner, path, otherFinding.String()); res.Updated != 0 || res.Rows[0].Code != finding.RefusalNotFound {
			t.Fatalf("%s of another tenant's finding = %+v, want %s", path, res, finding.RefusalNotFound)
		}
	}
	if st := h.statusOf(otherFinding); st != "fix_applied" {
		t.Fatalf("another tenant's finding moved to %s", st)
	}
}
