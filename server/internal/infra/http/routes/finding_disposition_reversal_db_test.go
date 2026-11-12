package routes

// Leaving an approved false positive or an accepted risk needs
// findings:approve, over the real routes, middleware, services and a migrated
// database: findings:status alone (single or bulk) is refused and the finding
// keeps its decision; a holder of findings:approve reopens it.

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestDispositionReversal_NeedsApprove(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA.String()

	statusOnly := []string{
		permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.FindingsStatus.String(),
		permission.FindingsBulkUpdate.String(),
	}
	withApprove := append(append([]string{}, statusOnly...), permission.FindingsApprove.String())

	attempts := []struct {
		name, method, path string
		body               any
	}{
		{"single", http.MethodPatch, "/api/v1/findings/" + fa + "/status", map[string]any{"status": "confirmed"}},
		{"bulk", http.MethodPost, "/api/v1/findings/bulk/status", map[string]any{"finding_ids": []string{fa}, "status": "confirmed"}},
	}
	for _, decided := range []string{"false_positive", "accepted"} {
		for _, a := range attempts {
			h.exec(`UPDATE findings SET status = $2, resolved_at = now() WHERE id = $1`, fa, decided)
			status, body := h.doPerms(h.memberA, statusOnly, a.method, a.path, a.body)
			if a.name == "single" && status != http.StatusForbidden {
				t.Errorf("%s: %s -> confirmed with findings:status only = %d %.300s, want 403", a.name, decided, status, body)
			}
			if st, _, _ := h.closure(h.findingA); st != decided {
				t.Fatalf("%s: a caller without findings:approve moved the %s finding to %s", a.name, decided, st)
			}
			status, body = h.doPerms(h.memberA, withApprove, a.method, a.path, a.body)
			if status != http.StatusOK {
				t.Fatalf("%s: %s -> confirmed with findings:approve = %d %.300s, want 200", a.name, decided, status, body)
			}
			if st, _, _ := h.closure(h.findingA); st != "confirmed" {
				t.Errorf("%s: %s -> confirmed with findings:approve left status %s", a.name, decided, st)
			}
		}
	}
}
