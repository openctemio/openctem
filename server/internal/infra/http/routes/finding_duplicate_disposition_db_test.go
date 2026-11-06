package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A merge never turns an open critical finding into an accepted risk or a
// false positive: those decisions go through the approval policy (tier,
// approvers, no self-approval), and a merge writes no approval. One person
// holding findings:triage and findings:approve folding a low finding that
// someone accepted (or dismissed) into an open critical KEV finding on the
// same asset is refused, in either direction, and nothing changes.
func TestFindingDuplicate_MergeCannotCarryDispositionOntoCriticalFinding(t *testing.T) {
	h := newDSHarness(t)
	perms := append(append([]string{}, dsMemberPerms...), permission.FindingsApprove.String())

	for _, disp := range []string{"accepted", "false_positive"} {
		t.Run(disp, func(t *testing.T) {
			low := shared.NewID()
			h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
				VALUES ($1::uuid, $2, $3, 'sast', 'dup-tool', 'low thing', 'low', $1::text, $4)`,
				low.String(), h.tenant.String(), h.assetA.String(), disp)
			crit := shared.NewID()
			h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, is_in_kev)
				VALUES ($1::uuid, $2, $3, 'sast', 'dup-tool', 'critical KEV', 'critical', $1::text, 'new', TRUE)`,
				crit.String(), h.tenant.String(), h.assetA.String())

			// low folded into critical: the critical finding must stay open.
			if status, body := h.markDup(h.memberA, false, perms, low, crit); status != http.StatusConflict {
				t.Fatalf("mark duplicate = %d %.300s, want 409", status, body)
			}
			// critical folded into the dismissed low finding: closing it under
			// somebody else's decision is the same one-person closure.
			if status, body := h.markDup(h.memberA, false, perms, crit, low); status != http.StatusConflict {
				t.Fatalf("reverse mark duplicate = %d %.300s, want 409", status, body)
			}
			if got, _ := h.dupState(crit); got != "new" {
				t.Fatalf("critical finding status = %s, want new", got)
			}
			if got, _ := h.dupState(low); got != disp {
				t.Fatalf("low finding status = %s, want %s", got, disp)
			}
			if n := h.countRows(`SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1`, crit.String()); n != 0 {
				t.Fatalf("approval rows on the critical finding = %d, want 0", n)
			}
		})
	}
}
