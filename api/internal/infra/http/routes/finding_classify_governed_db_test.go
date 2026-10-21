package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	activityapp "github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PATCH /findings/{id}/classify over the real routes and a migrated database:
// a CVE only goes on a finding type that carries CVEs, a change that lowers
// the risk tier (clearing or swapping the CVE of a KEV finding) needs
// findings:approve, and every change leaves a timeline entry and an audit row.

func (h *gsHarness) classifyFixture() {
	db := &postgres.DB{DB: h.db}
	h.vuln.SetActivityService(activityapp.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), logger.NewNop()))
	h.vuln.SetKEVChecker(postgres.NewThreatIntelRepository(db).KEV())
}

func classifyPerms(approve bool) []string {
	p := []string{permission.FindingsRead.String(), permission.FindingsSeverity.String()}
	if approve {
		p = append(p, permission.FindingsApprove.String())
	}
	return p
}

func (h *gsHarness) classify(user, finding shared.ID, approve bool, body map[string]any) (int, string) {
	h.t.Helper()
	return h.doPerms(user, classifyPerms(approve), http.MethodPatch, "/api/v1/findings/"+finding.String()+"/classify", body)
}

func (h *gsHarness) cveOf(id shared.ID) string {
	h.t.Helper()
	var cve string
	if err := h.db.QueryRow(`SELECT COALESCE(cve_id, '') FROM findings WHERE id = $1`, id.String()).Scan(&cve); err != nil {
		h.t.Fatal(err)
	}
	return cve
}

func (h *gsHarness) classifyActivities(id shared.ID) int {
	return h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'metadata_updated' AND changes->>'field' = 'classification'`, id.String())
}

func TestClassify_CVEOnlyOnTypesThatCarryOne_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.classifyFixture()
	fa := h.findingA
	for i, typ := range []string{"secret", "misconfiguration", "compliance", "web3", "license"} {
		h.exec(`UPDATE findings SET finding_type = $2, cve_id = NULL, is_in_kev = false, priority_class = NULL, severity = 'medium' WHERE id = $1`, fa.String(), typ)
		code, body := h.classify(h.memberA, fa, true, map[string]any{"cve_id": "CVE-2024-21762"})
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "CLASSIFY_CVE_NOT_APPLICABLE") {
			t.Fatalf("%s: CVE accepted: %d %s", typ, code, body)
		}
		if cve := h.cveOf(fa); cve != "" {
			t.Fatalf("%s: the refused CVE was stored: %q", typ, cve)
		}
		// CWE and CVSS edits stay possible on such a finding.
		if code, body := h.classify(h.memberA, fa, true, map[string]any{"cwe_ids": []string{"CWE-" + strings.Repeat("7", i+1)}}); code != http.StatusOK {
			t.Fatalf("%s: CWE edit: %d %s", typ, code, body)
		}
	}
	if n := h.auditCount("finding.classified", fa.String()); n != 5 {
		t.Fatalf("audit rows for the five accepted CWE edits = %d, want 5 (none for the refusals)", n)
	}
	h.exec(`UPDATE findings SET finding_type = 'vulnerability' WHERE id = $1`, fa.String())
	if code, body := h.classify(h.memberA, fa, false, map[string]any{"cve_id": "cve-2024-0001"}); code != http.StatusOK || h.cveOf(fa) != "CVE-2024-0001" {
		t.Fatalf("CVE on a vulnerability: %d %s (stored %q)", code, body, h.cveOf(fa))
	}
}

func TestClassify_LoweringRiskNeedsApprove_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.classifyFixture()
	fa := h.findingA
	const kevCVE, otherKEV, plainCVE = "CVE-2098-1001", "CVE-2098-1002", "CVE-2098-1003"
	for _, c := range []string{kevCVE, otherKEV} {
		h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added) VALUES ($1, 'classify-test', NOW()) ON CONFLICT (cve_id) DO NOTHING`, c)
	}
	t.Cleanup(func() { h.exec(`DELETE FROM kev_catalog WHERE cve_id IN ($1, $2)`, kevCVE, otherKEV) })
	reset := func() {
		h.exec(`UPDATE findings SET finding_type = 'vulnerability', cve_id = $2, is_in_kev = true, priority_class = 'P0', severity = 'medium', cvss_score = NULL WHERE id = $1`, fa.String(), kevCVE)
		h.exec(`DELETE FROM finding_activities WHERE finding_id = $1 AND activity_type = 'metadata_updated'`, fa.String())
	}

	// Clearing the CVE of a KEV finding, and swapping it for a harmless one,
	// is refused without findings:approve (findings:severity is not enough).
	for name, body := range map[string]map[string]any{"clear": {"cve_id": ""}, "swap": {"cve_id": plainCVE}} {
		reset()
		code, raw := h.classify(h.memberA, fa, false, body)
		if code != http.StatusForbidden || !strings.Contains(raw, "CLASSIFY_LOWERS_RISK") {
			t.Fatalf("%s without approve: %d %s, want 403 CLASSIFY_LOWERS_RISK", name, code, raw)
		}
		if h.cveOf(fa) != kevCVE || h.classifyActivities(fa) != 0 {
			t.Fatalf("%s without approve changed the finding (cve %q)", name, h.cveOf(fa))
		}
	}

	// With findings:approve it applies, with a timeline entry and an audit row.
	reset()
	before := h.auditCount("finding.classified", fa.String())
	if code, raw := h.classify(h.memberA, fa, true, map[string]any{"cve_id": ""}); code != http.StatusOK || h.cveOf(fa) != "" {
		t.Fatalf("clear with approve: %d %s (cve %q)", code, raw, h.cveOf(fa))
	}
	if n := h.classifyActivities(fa); n != 1 {
		t.Fatalf("classification timeline entries = %d, want 1", n)
	}
	if n := h.auditCount("finding.classified", fa.String()); n != before+1 {
		t.Fatalf("audit rows = %d, want %d", n, before+1)
	}
	var changes string
	if err := h.db.QueryRow(`SELECT changes::text FROM finding_activities WHERE finding_id = $1 AND changes->>'field' = 'classification'`, fa.String()).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(changes), &m)
	if m["old_cve_id"] != kevCVE || m["new_cve_id"] != "" {
		t.Fatalf("timeline entry does not carry old and new CVE: %s", changes)
	}

	// Not lowering: a swap to another KEV CVE, a CVSS-only edit and a no-op need no approval.
	reset()
	if code, raw := h.classify(h.memberA, fa, false, map[string]any{"cve_id": otherKEV}); code != http.StatusOK {
		t.Fatalf("swap to another KEV CVE: %d %s", code, raw)
	}
	reset()
	if code, raw := h.classify(h.memberA, fa, false, map[string]any{"cve_id": kevCVE, "cvss_score": 9.8}); code != http.StatusOK {
		t.Fatalf("CVSS-only edit: %d %s", code, raw)
	}
	reset()
	n := h.classifyActivities(fa)
	if code, _ := h.classify(h.memberA, fa, false, map[string]any{"cve_id": kevCVE}); code != http.StatusOK || h.classifyActivities(fa) != n {
		var ch string
		_ = h.db.QueryRow(`SELECT changes::text FROM finding_activities WHERE finding_id = $1 AND changes->>'field' = 'classification'`, fa.String()).Scan(&ch)
		t.Fatalf("no-op classify: %d, entries %d -> %d: %s", code, n, h.classifyActivities(fa), ch)
	}

	// A finding already critical by severity cannot drop a tier: no approval needed.
	reset()
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, fa.String())
	if code, raw := h.classify(h.memberA, fa, false, map[string]any{"cve_id": plainCVE}); code != http.StatusOK {
		t.Fatalf("swap on a critical-severity finding: %d %s", code, raw)
	}
}

func TestClassify_ScopeAndPermission_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.classifyFixture()
	// memberA's scope is asset A1: finding B is out of scope and reads as missing.
	if code, raw := h.classify(h.memberA, h.findingB, true, map[string]any{"cwe_ids": []string{"CWE-79"}}); code != http.StatusNotFound {
		t.Fatalf("out-of-scope classify: %d %s, want 404", code, raw)
	}
	// findings:approve does not replace findings:severity.
	if code, raw := h.doPerms(h.memberA, []string{permission.FindingsRead.String(), permission.FindingsApprove.String()}, http.MethodPatch,
		"/api/v1/findings/"+h.findingA.String()+"/classify", map[string]any{"cwe_ids": []string{"CWE-79"}}); code != http.StatusForbidden {
		t.Fatalf("classify without findings:severity: %d %s, want 403", code, raw)
	}
}
