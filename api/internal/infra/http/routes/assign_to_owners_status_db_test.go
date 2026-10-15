package routes

// POST /findings/actions/assign-to-owners over the real route, handler,
// service and a migrated database: closed findings are never assigned, a
// confirmed finding starts work (confirmed → in_progress, a lifecycle edge),
// and a new finding is assigned but stays new (assignment is not triage; the
// old code tried new → in_progress, which is not an edge).

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssignToOwners_LegalStatusAndSkipsClosed(t *testing.T) {
	h := newGroupScopeHarness(t)
	cves := map[string]string{}
	ids := map[string]shared.ID{}
	for i, st := range []string{"new", "confirmed", "resolved", "false_positive", "accepted"} {
		id := shared.NewID()
		ids[st] = id
		cves[st] = fmt.Sprintf("%s%d", h.cveA[:len(h.cveA)-1], 5+i)
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id)
			VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'assign owners', 'high', $1::text, $4, $5)`,
			id.String(), h.tenant.String(), h.assetA.String(), st, cves[st])
	}
	all := make([]string, 0, len(cves))
	for _, c := range cves {
		all = append(all, c)
	}

	status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/findings/actions/assign-to-owners",
		map[string]any{"filter": map[string]any{"cve_ids": all}})
	if status != http.StatusOK || !strings.Contains(body, `"assigned":2`) || !strings.Contains(body, `"started":1`) {
		t.Fatalf("assign-to-owners = %d %.300s, want 2 assigned, 1 started", status, body)
	}

	for st, want := range map[string][2]string{
		"new":            {"new", h.memberA.String()},
		"confirmed":      {"in_progress", h.memberA.String()},
		"resolved":       {"resolved", ""},
		"false_positive": {"false_positive", ""},
		"accepted":       {"accepted", ""},
	} {
		gotStatus, _, assignee := h.findingState(ids[st])
		if gotStatus != want[0] || assignee != want[1] {
			t.Errorf("%s finding: status=%s assignee=%q, want %s / %q", st, gotStatus, assignee, want[0], want[1])
		}
	}
}
