package routes

// The verification queue: the "Awaiting verification" count on the Findings
// page equals the findings its view lists. The view is the by-CVE groups plus
// the findings that have no CVE (a rule-only SAST, secret, misconfiguration
// or DAST finding), which grouping by cve_id leaves out; the count leaves out
// pentest findings, which their own module verifies.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *gsHarness) awaitingVerification(t *testing.T, c flCaller) int64 {
	t.Helper()
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings/stats?state=all")
	if status != http.StatusOK {
		t.Fatalf("%s stats = %d: %.300s", c.name, status, body)
	}
	var out struct {
		Awaiting int64 `json:"awaiting_verification"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Awaiting
}

func TestAwaitingVerification_CountEqualsTheQueueView(t *testing.T) {
	h := newGroupScopeHarness(t)
	insert := func(asset shared.ID, source, cve string) {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, finding_type, rule_id, cve_id)
			VALUES ($1::uuid, $2, $3, $4, 'vq-tool', 'queue finding', 'medium', $1::text, 'fix_applied', 'vulnerability', 'vq-rule', NULLIF($5, ''))`,
			id.String(), h.tenant.String(), asset.String(), source, cve)
	}
	insert(h.assetA, "sca", "CVE-2099-0001")
	insert(h.assetA, "sast", "") // a rule-only finding: no CVE
	insert(h.assetA, "secret", "")
	insert(h.assetB, "dast", "")
	insert(h.assetB, "sca", "CVE-2099-0002")
	// Pentest findings are verified in their module: not in the queue.
	insert(h.assetA, "pentest", "")

	for _, c := range []flCaller{
		{"owner", h.owner, true},
		{"memberA", h.memberA, false},
		{"full-data role", h.memberFull, false},
	} {
		count := h.awaitingVerification(t, c)
		byCVE := h.groupsSum(t, c, "cve_id", "status=fix_applied")
		_, noCVE, _ := h.listIDs(t, c, "status=fix_applied&cve_id_null=true&source_not=pentest")
		if count != byCVE+noCVE {
			t.Errorf("%s: awaiting_verification = %d, the queue shows %d by CVE + %d without a CVE", c.name, count, byCVE, noCVE)
		}
		if c.admin && noCVE != 3 {
			t.Errorf("%s: findings without a CVE in the queue = %d, want 3", c.name, noCVE)
		}
	}
}
